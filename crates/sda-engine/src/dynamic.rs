//! The native dynamic engine: run the target, watch what it does, and turn that
//! into evidence.
//!
//! Three sources of runtime truth, in increasing order of usefulness:
//!
//! 1. **Process outcome** — exit code, signal, timeout. Coarse, but free.
//! 2. **Diagnostic output** — sanitizer reports, Rust panics, our own probe
//!    assertions. Parsed into located [`RuntimeEvent`]s.
//! 3. **The SDA probe stream** — a JSON-lines protocol defined here and emitted
//!    by instrumentation we control, carrying coverage and value observations
//!    that nothing else can supply.
//!
//! The third is what makes correlation possible: without knowing whether a line
//! *executed*, a clean run cannot be distinguished from an unexercised one, and
//! the whole statodynamic claim collapses.

use sda_core::{
    Analyzer, AnalyzerKind, Availability, Capability, Confidence, Evidence, Finding, Language,
    Location, ProviderInfo, RunOptions, RuntimeEvent, RuntimeEventKind, Severity, Target,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How to launch the target once.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunSpec {
    pub program: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    /// Wall-clock limit. A target that runs forever is a finding, not a hang.
    #[serde(default = "default_timeout")]
    pub timeout: Duration,
    /// Bytes fed to stdin — the usual way a fuzzed input reaches the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<Vec<u8>>,
    /// Label used to identify this run in evidence.
    #[serde(default)]
    pub run_id: String,
}

fn default_timeout() -> Duration {
    Duration::from_secs(10)
}

impl RunSpec {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        RunSpec {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            timeout: default_timeout(),
            stdin: None,
            run_id: "run-0".into(),
        }
    }
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }
    pub fn with_stdin(mut self, bytes: Vec<u8>) -> Self {
        self.stdin = Some(bytes);
        self
    }
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.run_id = id.into();
        self
    }
}

/// What happened when the target ran.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunOutcome {
    pub run_id: String,
    /// `None` when the process was killed or died on a signal.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub timed_out: bool,
}

impl RunOutcome {
    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }
    /// Whether the process died in a way that indicates a defect rather than a
    /// deliberate non-zero exit.
    pub fn crashed(&self) -> bool {
        if self.timed_out {
            return false;
        }
        match self.exit_code {
            // Unix reports a signal death as 128+n through most shells; a raw
            // `None` means the platform gave us no code at all.
            None => true,
            Some(c) => c < 0 || (128..=192).contains(&c),
        }
    }
}

// --- the SDA probe protocol ------------------------------------------------

/// One line of the SDA probe stream.
///
/// Instrumentation writes these as JSON Lines to the path named by the
/// `SDA_PROBE_OUT` environment variable. The schema is deliberately tiny so a C
/// shim can emit it with `fprintf` and a Rust one with `serde_json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "kebab-case")]
pub enum ProbeRecord {
    /// A source location executed.
    Cov {
        #[serde(rename = "f")]
        file: String,
        #[serde(rename = "l")]
        line: u32,
        #[serde(default = "one_u64", rename = "n")]
        count: u64,
    },
    /// A value observed at a probe point.
    Val {
        #[serde(rename = "f")]
        file: String,
        #[serde(rename = "l")]
        line: u32,
        #[serde(rename = "k")]
        key: String,
        #[serde(rename = "v")]
        value: f64,
    },
    /// An instrumentation-detected fault: a bounds violation, an overflow, a
    /// contract breach. This is our own sanitizer's output channel.
    Fault {
        #[serde(rename = "f")]
        file: String,
        #[serde(rename = "l")]
        line: u32,
        #[serde(rename = "k")]
        kind: String,
        #[serde(rename = "m")]
        message: String,
    },
    /// A resource high-water mark.
    Mark {
        #[serde(rename = "k")]
        key: String,
        #[serde(rename = "v")]
        value: f64,
    },
    /// The operands of a comparison the program performed.
    ///
    /// Consumed by the fuzzer as a dictionary: a value the program compares
    /// against is a value worth writing into the input. This is what lets a
    /// low-throughput, out-of-process fuzzer get past magic numbers that brute
    /// force could not reach.
    Cmp {
        #[serde(rename = "f")]
        file: String,
        #[serde(rename = "l")]
        line: u32,
        #[serde(rename = "a")]
        lhs: u64,
        #[serde(rename = "b")]
        rhs: u64,
    },
}

fn one_u64() -> u64 {
    1
}

/// Everything a run observed, after parsing.
#[derive(Clone, Debug, Default)]
pub struct Observation {
    pub events: Vec<RuntimeEvent>,
    /// `(file, line) -> execution count`, the input the correlation engine needs
    /// to tell "did not happen" from "never ran".
    pub coverage: BTreeMap<(String, u32), u64>,
    pub marks: BTreeMap<String, f64>,
    /// Values the program was seen comparing against, for the fuzzer to use as
    /// a dictionary.
    pub comparisons: BTreeSet<u64>,
}

impl Observation {
    pub fn covered(&self, file: &str, line: u32) -> u64 {
        // Compare on normalized separators and by suffix, since a runtime path
        // is usually absolute while a finding's path is project-relative.
        let want = file.replace('\\', "/");
        self.coverage
            .iter()
            .filter(|((f, l), _)| {
                *l == line && {
                    let f = f.replace('\\', "/");
                    f.ends_with(&want) || want.ends_with(&f)
                }
            })
            .map(|(_, n)| *n)
            .max()
            .unwrap_or(0)
    }

    /// Whether this line was *measured at all*, which is not the same question
    /// as whether it ran.
    ///
    /// [`covered`](Self::covered) answers zero for two situations a report must
    /// keep apart: a line an external coverage tool counted and found never
    /// executed — `#####` in gcov, `DA:5,0` in lcov, which is real evidence —
    /// and a line nothing ever looked at. Probe instrumentation is line-granular
    /// and hand-placed, so on a shim-instrumented program most lines fall in the
    /// second group.
    ///
    /// Correlation's prose already says "produced no coverage record" rather
    /// than "did not execute". The structured evidence did not: every unreached
    /// finding carried `executions = 0`, which is a *measurement*, and it is the
    /// half a machine reads. Surfaced by the first real Cortex-M run, where
    /// fourteen of fifteen findings claimed a count nobody had taken.
    pub fn measured(&self, file: &str, line: u32) -> bool {
        let want = file.replace('\\', "/");
        self.coverage.keys().any(|(f, l)| {
            *l == line && {
                let f = f.replace('\\', "/");
                f.ends_with(&want) || want.ends_with(&f)
            }
        })
    }

    /// True when any line of the file was executed. Distinguishes "this file
    /// never ran" from "this line never ran", which are different verdicts.
    ///
    /// The `> 0` is load-bearing and was not always there. The probe stream only
    /// ever emits a record for a line that ran, so key existence and execution
    /// were the same thing and testing either worked. An external coverage
    /// report is not like that: `#####` in a gcov listing and `DA:5,0` in an
    /// lcov tracefile are records for lines that demonstrably did *not* run, and
    /// they are recorded precisely because that is evidence. Keeping the old
    /// key-existence test would have reported a file whose every line ran zero
    /// times as one that executed, and each finding in it as "this line produced
    /// no coverage record, though other lines in the file did" — a sentence with
    /// no true reading. An invariant that held for one producer, silently broken
    /// by the second.
    pub fn file_executed(&self, file: &str) -> bool {
        let want = file.replace('\\', "/");
        self.coverage.iter().any(|((f, _), n)| {
            *n > 0 && {
                let f = f.replace('\\', "/");
                f.ends_with(&want) || want.ends_with(&f)
            }
        })
    }

    pub fn merge(&mut self, other: Observation) {
        self.events.extend(other.events);
        for (k, v) in other.coverage {
            *self.coverage.entry(k).or_insert(0) += v;
        }
        self.comparisons.extend(other.comparisons);
        for (k, v) in other.marks {
            let e = self.marks.entry(k).or_insert(v);
            *e = e.max(v);
        }
    }

    pub fn defects(&self) -> impl Iterator<Item = &RuntimeEvent> {
        self.events.iter().filter(|e| e.is_defect())
    }
}

/// What a probe stream actually contained.
///
/// [`parse_probe_stream`] skips a line it cannot read, which is right for a live
/// subprocess: the last line of a stream is routinely half-flushed when the
/// process dies, and treating that as an error would turn every crash into a
/// parse failure. It is **wrong** for a capture handed in from somewhere else.
///
/// A UART log with framing noise, a file that is not a probe stream at all, or a
/// board that reset before the sink was routed all parse to an empty
/// [`Observation`] — and an empty observation is not nothing. It is the claim
/// *execution was measured and these lines did not run*, which is what makes
/// `Refuted` and `Unreached` available. Handing that to correlation on the
/// strength of a file the parser could not read a single record from would
/// manufacture refutations out of a truncated log.
///
/// So a caller that did not watch the process itself gets the counts and has to
/// decide. See `load_observations` in the CLI, which refuses a capture with no
/// records rather than believing it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamSummary {
    /// Non-empty lines that parsed as a probe record.
    pub records: usize,
    /// Non-empty lines that did not. One is ordinary; many mean the wrong file.
    pub unreadable: usize,
}

/// Parse the probe stream.
pub fn parse_probe_stream(text: &str, run_id: &str) -> Observation {
    parse_probe_capture(text, run_id).0
}

/// Parse the probe stream, reporting what was in it. See [`StreamSummary`].
pub fn parse_probe_capture(text: &str, run_id: &str) -> (Observation, StreamSummary) {
    let mut obs = Observation::default();
    let mut summary = StreamSummary::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<ProbeRecord>(line) else {
            summary.unreadable += 1;
            continue; // a partially-flushed final line is normal, not an error
        };
        summary.records += 1;
        match rec {
            ProbeRecord::Cov { file, line, count } => {
                *obs.coverage.entry((file, line)).or_insert(0) += count;
            }
            ProbeRecord::Val { file, line, key, value } => {
                obs.events.push(
                    RuntimeEvent::new(
                        RuntimeEventKind::ValueObservation,
                        format!("{key} = {value}"),
                    )
                    .at(Location::new(file, line, 1))
                    .from_run(run_id),
                );
            }
            ProbeRecord::Fault { file, line, kind, message } => {
                obs.events.push(
                    RuntimeEvent::new(fault_kind(&kind), format!("{kind}: {message}"))
                        .at(Location::new(file, line, 1))
                        .from_run(run_id),
                );
            }
            ProbeRecord::Mark { key, value } => {
                let e = obs.marks.entry(key).or_insert(value);
                *e = e.max(value);
            }
            ProbeRecord::Cmp { lhs, rhs, .. } => {
                // Both sides are recorded: either may be the constant the input
                // has to match, and the instrumentation does not know which.
                obs.comparisons.insert(lhs);
                obs.comparisons.insert(rhs);
            }
        }
    }
    (obs, summary)
}

fn fault_kind(kind: &str) -> RuntimeEventKind {
    match kind {
        "bounds" | "oob" | "overflow-write" => RuntimeEventKind::MemoryError,
        "uninit" | "shift" | "signed-overflow" | "null-deref" => RuntimeEventKind::UndefinedBehavior,
        "leak" => RuntimeEventKind::Leak,
        "race" => RuntimeEventKind::DataRace,
        "stack" | "timeout" | "oom" => RuntimeEventKind::ResourceExhaustion,
        _ => RuntimeEventKind::SanitizerReport,
    }
}

// --- diagnostic output parsing --------------------------------------------

/// Parse sanitizer and panic diagnostics out of a run's stderr.
///
/// This is what lets an ASan-instrumented build — produced through `sda-build`
/// with an arbitrary compiler — feed the same correlation engine as our own
/// probes.
pub fn parse_diagnostics(stderr: &str, run_id: &str) -> Vec<RuntimeEvent> {
    let mut out = Vec::new();

    for (i, line) in stderr.lines().enumerate() {
        let l = line.trim();

        // AddressSanitizer / LeakSanitizer / ThreadSanitizer / MemorySanitizer.
        if let Some(rest) = l.split_once("ERROR: ").map(|(_, r)| r) {
            let kind = if rest.contains("LeakSanitizer") {
                RuntimeEventKind::Leak
            } else if rest.contains("ThreadSanitizer") || rest.contains("data race") {
                RuntimeEventKind::DataRace
            } else if rest.contains("MemorySanitizer") {
                RuntimeEventKind::UndefinedBehavior
            } else if rest.contains("AddressSanitizer") {
                RuntimeEventKind::MemoryError
            } else {
                RuntimeEventKind::SanitizerReport
            };
            let mut e = RuntimeEvent::new(kind, rest.to_string()).from_run(run_id);
            if let Some(loc) = find_frame(stderr.lines().skip(i).take(12)) {
                e = e.at(loc);
            }
            out.push(e);
            continue;
        }

        // UndefinedBehaviorSanitizer: `file:line:col: runtime error: ...`
        if let Some(idx) = l.find(": runtime error: ") {
            let (where_, what) = l.split_at(idx);
            let mut e = RuntimeEvent::new(
                RuntimeEventKind::UndefinedBehavior,
                what.trim_start_matches(": runtime error: ").to_string(),
            )
            .from_run(run_id);
            if let Some(loc) = parse_file_line_col(where_) {
                e = e.at(loc);
            }
            out.push(e);
            continue;
        }

        // Rust panic.
        if let Some(rest) = l.strip_prefix("thread ")
            && let Some(at) = rest.find(" panicked at ") {
                let where_ = rest[at + " panicked at ".len()..].trim_end_matches(':');
                let mut e = RuntimeEvent::new(
                    RuntimeEventKind::Crash,
                    format!("Rust panic: {}", stderr.lines().nth(i + 1).unwrap_or("").trim()),
                )
                .from_run(run_id);
                if let Some(loc) = parse_file_line_col(where_) {
                    e = e.at(loc);
                }
                out.push(e);
            }
    }
    out
}

/// `path:line:col` → a [`Location`]. Handles Windows drive letters, whose colon
/// would otherwise split the path in half.
fn parse_file_line_col(s: &str) -> Option<Location> {
    let s = s.trim();
    let parts: Vec<&str> = s.rsplitn(3, ':').collect();
    match parts.len() {
        3 => {
            let col = parts[0].trim().parse().unwrap_or(1);
            let line = parts[1].trim().parse().ok()?;
            Some(Location::new(parts[2].trim(), line, col))
        }
        2 => {
            let line = parts[0].trim().parse().ok()?;
            Some(Location::new(parts[1].trim(), line, 1))
        }
        _ => None,
    }
}

/// The first source location in a sanitizer stack trace.
fn find_frame<'a>(lines: impl Iterator<Item = &'a str>) -> Option<Location> {
    for l in lines {
        let l = l.trim();
        if !l.starts_with('#') {
            continue;
        }
        // `#0 0xdeadbeef in func /path/file.c:42:9`
        let tail = l.rsplit(' ').next()?;
        if tail.contains(':') && !tail.starts_with("0x")
            && let Some(loc) = parse_file_line_col(tail) {
                return Some(loc);
            }
    }
    None
}

// --- execution -------------------------------------------------------------

/// Run the target once, capturing output and honouring the timeout.
pub fn run_once(spec: &RunSpec) -> sda_core::Result<(RunOutcome, Observation)> {
    let probe_path = std::env::temp_dir().join(format!("sda-probe-{}.jsonl", spec.run_id));
    let _ = std::fs::remove_file(&probe_path);

    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .envs(&spec.env)
        .env("SDA_PROBE_OUT", &probe_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if spec.stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }

    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|e| sda_core::Error::ProviderFailed {
        provider: "sda.dynamic".into(),
        reason: format!("could not launch {}: {e}", spec.program.display()),
    })?;

    // Every pipe is serviced on its own thread. A target that fills stdout, or
    // never reads an input larger than the stdin pipe, blocks on a pipe nobody
    // is servicing — and the timeout below is never reached while it does.
    if let (Some(bytes), Some(mut si)) = (spec.stdin.clone(), child.stdin.take()) {
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = si.write_all(&bytes);
        });
    }
    let stdout_rx = drain(child.stdout.take());
    let stderr_rx = drain(child.stderr.take());

    let failed = |e: std::io::Error| sda_core::Error::ProviderFailed {
        provider: "sda.dynamic".into(),
        reason: e.to_string(),
    };
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started.elapsed() >= spec.timeout {
                    let _ = child.kill();
                    timed_out = true;
                    break child.wait().map_err(failed)?;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(failed(e)),
        }
    };

    // A process the target started can hold the pipes open after it is killed,
    // so a timed-out run waits for its output only briefly.
    let collect = |rx: std::sync::mpsc::Receiver<Vec<u8>>| {
        let bytes = if timed_out {
            rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default()
        } else {
            rx.recv().unwrap_or_default()
        };
        String::from_utf8_lossy(&bytes).into_owned()
    };

    let outcome = RunOutcome {
        run_id: spec.run_id.clone(),
        exit_code: status.code(),
        stdout: collect(stdout_rx),
        stderr: collect(stderr_rx),
        duration_ms: started.elapsed().as_millis() as u64,
        timed_out,
    };

    let mut obs = match std::fs::read_to_string(&probe_path) {
        Ok(text) => parse_probe_stream(&text, &spec.run_id),
        Err(_) => Observation::default(),
    };
    let _ = std::fs::remove_file(&probe_path);
    obs.events.extend(parse_diagnostics(&outcome.stderr, &spec.run_id));
    obs.events.extend(outcome_events(&outcome));

    Ok((outcome, obs))
}

/// Read a child's pipe to the end on its own thread. The bytes arrive when the
/// pipe closes, which is when every process holding it has exited.
fn drain<R: std::io::Read + Send + 'static>(
    pipe: Option<R>,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

/// Events implied by the process outcome itself.
fn outcome_events(o: &RunOutcome) -> Vec<RuntimeEvent> {
    let mut v = Vec::new();
    if o.timed_out {
        v.push(
            RuntimeEvent::new(
                RuntimeEventKind::ResourceExhaustion,
                format!("target did not terminate within its time budget ({} ms)", o.duration_ms),
            )
            .from_run(&o.run_id),
        );
    } else if o.crashed() {
        v.push(
            RuntimeEvent::new(
                RuntimeEventKind::Crash,
                match o.exit_code {
                    Some(c) => format!("target terminated abnormally (exit {c})"),
                    None => "target terminated on a signal".to_string(),
                },
            )
            .from_run(&o.run_id),
        );
    }
    v
}

/// The native dynamic provider.
pub struct DynamicEngine {
    /// Runs to perform. Empty means the engine reports that it had nothing to
    /// execute — which is itself important, not a silent pass.
    pub specs: Vec<RunSpec>,
}

impl DynamicEngine {
    pub fn new(specs: Vec<RunSpec>) -> Self {
        DynamicEngine { specs }
    }

    /// Execute every spec and merge what was observed.
    pub fn observe(&self) -> sda_core::Result<Observation> {
        let mut all = Observation::default();
        for spec in &self.specs {
            let (_, obs) = run_once(spec)?;
            all.merge(obs);
        }
        Ok(all)
    }
}

/// Turn observed runtime events into findings.
pub fn findings_from(obs: &Observation, fallback_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in obs.defects() {
        let (rule, severity) = classify(e.kind);
        let loc = e
            .location
            .clone()
            .unwrap_or_else(|| Location::file_only(fallback_path));
        let f = Finding::new("sda.dynamic", rule, headline(e.kind), severity, loc)
            .message(e.detail.clone())
            .confidence(Confidence::Certain)
            .phase(sda_core::AnalysisPhase::Dynamic)
            .evidence(Evidence::Runtime { event: e.clone() })
            .taxonomy(cwe_for(e.kind));
        out.push(f);
    }
    out
}

/// Give runtime findings the extent of the token they name, read from source.
///
/// A runtime witness arrives as text — `file:line:col` out of a sanitizer, or a
/// file and a line out of the probe stream — and carries no extent, so dynamic
/// findings were points while static ones were spans. The source is on disk and
/// the static analyzers already bracket tokens with it; this does the same for
/// the dynamic side, after the fact, where the project root is known.
///
/// What it deliberately does *not* do is span a finding whose column is 1. The
/// probe stream has no column field and the parser writes 1 there, so column 1
/// means "somewhere on this line" far more often than it means "the first
/// character". Bracketing the first token of the line would point confidently
/// at text that nothing measured — the exact trade this codebase keeps getting
/// wrong. A point is the honest rendering of a position we do not have.
pub fn span_against_source(findings: &mut [Finding], root: &std::path::Path) {
    let mut sources: std::collections::HashMap<std::path::PathBuf, Option<String>> =
        std::collections::HashMap::new();

    for f in findings.iter_mut() {
        let loc = &f.location;
        if loc.end_column.is_some() || loc.column <= 1 || loc.line == 0 {
            continue;
        }
        let path = if loc.file.is_absolute() { loc.file.clone() } else { root.join(&loc.file) };
        let text = sources
            .entry(path.clone())
            .or_insert_with(|| std::fs::read_to_string(&path).ok());
        let Some(text) = text else { continue };

        let lines = sda_syntax::LineIndex::new(text);
        let Some(line_text) = lines.line_text(text, loc.line) else { continue };
        let end = sda_syntax::token_end_column(line_text, loc.column);
        if end > loc.column {
            f.location = f.location.clone().spanning(loc.line, end);
        }
    }
}

fn classify(k: RuntimeEventKind) -> (&'static str, Severity) {
    use RuntimeEventKind::*;
    match k {
        MemoryError => ("SDA-DYN-MEMORY", Severity::Critical),
        Crash => ("SDA-DYN-CRASH", Severity::Critical),
        DataRace => ("SDA-DYN-RACE", Severity::High),
        UndefinedBehavior => ("SDA-DYN-UB", Severity::High),
        Leak => ("SDA-DYN-LEAK", Severity::Medium),
        ResourceExhaustion => ("SDA-DYN-RESOURCE", Severity::High),
        SanitizerReport => ("SDA-DYN-SANITIZER", Severity::High),
        ModelBehavior => ("SDA-DYN-MODEL", Severity::High),
        Coverage | ValueObservation | Syscall => ("SDA-DYN-INFO", Severity::Info),
    }
}

fn headline(k: RuntimeEventKind) -> &'static str {
    use RuntimeEventKind::*;
    match k {
        MemoryError => "memory access outside an allocation, observed at runtime",
        Crash => "the target crashed",
        DataRace => "unsynchronized concurrent access, observed at runtime",
        UndefinedBehavior => "undefined behaviour, observed at runtime",
        Leak => "memory reachable at exit was never released",
        ResourceExhaustion => "the target exceeded a resource budget",
        SanitizerReport => "a sanitizer reported an error",
        ModelBehavior => "an AI model produced output matching a probe's trigger criteria",
        Coverage | ValueObservation | Syscall => "runtime observation",
    }
}

fn cwe_for(k: RuntimeEventKind) -> sda_core::TaxonomyRef {
    use RuntimeEventKind::*;
    sda_core::TaxonomyRef::cwe(match k {
        MemoryError => 787,
        DataRace => 362,
        UndefinedBehavior => 758,
        Leak => 401,
        ResourceExhaustion => 400,
        Crash => 248,
        _ => 1078,
    })
}

impl Analyzer for DynamicEngine {
    fn info(&self) -> ProviderInfo {
        ProviderInfo::native(
            "sda.dynamic",
            "NERVOSYS native dynamic engine",
            AnalyzerKind::Dynamic,
            vec![Language::C, Language::Cpp, Language::Rust],
            vec![
                Capability::MemorySafety,
                Capability::UndefinedBehavior,
                Capability::ConcurrencySafety,
                Capability::CoverageMeasurement,
                Capability::PerformanceProfiling,
            ],
            "Executes the built target under a time budget, ingests the SDA probe stream for \
             coverage and instrumentation faults, and parses sanitizer and panic diagnostics from \
             any compiler's instrumented build.",
        )
        .requires_build(true)
    }

    fn available(&self) -> Availability {
        match self.specs.first() {
            None => Availability::unavailable(
                "no run specification: the dynamic engine needs a built artifact to execute",
            ),
            Some(s) if !s.program.exists() => Availability::unavailable(format!(
                "target artifact `{}` does not exist; build it first",
                s.program.display()
            )),
            Some(_) => Availability::Available,
        }
    }

    fn analyze(&self, target: &Target, _opts: &RunOptions) -> sda_core::Result<Vec<Finding>> {
        let obs = self.observe()?;
        Ok(findings_from(&obs, &target.root.to_string_lossy()))
    }
}

impl sda_core::DynamicAnalyzer for DynamicEngine {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every runtime event kind, mapped to the finding it becomes.
    ///
    /// `classify` has nine arms and two of them were asserted anywhere. The
    /// mapping is the whole of what a dynamic finding *is* — a Memcheck
    /// invalid-write arriving as `SDA-DYN-LEAK`, or a data race at `Medium`,
    /// would be wrong in a way no other test here would notice, and this
    /// codebase has already had one defect of exactly that shape: external
    /// findings whose `AnalysisPhase` was `Static` because nothing set it.
    ///
    /// The `match` below is exhaustive on purpose. Adding a `RuntimeEventKind`
    /// will not compile until somebody states what it becomes, which is the
    /// question worth forcing.
    #[test]
    fn every_runtime_event_kind_becomes_the_finding_it_should() {
        use RuntimeEventKind::*;

        let expected = |k: RuntimeEventKind| -> Option<(&'static str, Severity)> {
            match k {
                MemoryError => Some(("SDA-DYN-MEMORY", Severity::Critical)),
                Crash => Some(("SDA-DYN-CRASH", Severity::Critical)),
                DataRace => Some(("SDA-DYN-RACE", Severity::High)),
                UndefinedBehavior => Some(("SDA-DYN-UB", Severity::High)),
                Leak => Some(("SDA-DYN-LEAK", Severity::Medium)),
                ResourceExhaustion => Some(("SDA-DYN-RESOURCE", Severity::High)),
                SanitizerReport => Some(("SDA-DYN-SANITIZER", Severity::High)),
                ModelBehavior => Some(("SDA-DYN-MODEL", Severity::High)),
                // Not defects, so they never become findings at all — see the
                // test below, which is the reason `SDA-DYN-INFO` is unreachable.
                Coverage | ValueObservation | Syscall => None,
            }
        };

        let kinds = [
            MemoryError, Crash, DataRace, UndefinedBehavior, Leak,
            ResourceExhaustion, SanitizerReport, ModelBehavior,
            Coverage, ValueObservation, Syscall,
        ];

        for kind in kinds {
            let mut obs = Observation::default();
            obs.events.push(RuntimeEvent::new(kind, "an observed event"));
            let found = findings_from(&obs, "src/target.c");

            match expected(kind) {
                Some((rule, severity)) => {
                    assert_eq!(found.len(), 1, "{kind:?} should produce one finding");
                    assert_eq!(found[0].rule.as_str(), rule, "{kind:?} became the wrong rule");
                    assert_eq!(found[0].severity, severity, "{kind:?} got the wrong severity");
                    assert_eq!(
                        found[0].phase,
                        sda_core::AnalysisPhase::Dynamic,
                        "{kind:?} is something that happened, not something suspected"
                    );
                }
                None => assert!(found.is_empty(), "{kind:?} is not a defect and must not be a finding"),
            }
        }
    }

    /// `SDA-DYN-INFO` cannot reach a report, and that is worth stating.
    ///
    /// `classify` maps `Coverage | ValueObservation | Syscall` to it, and its
    /// only caller iterates `defects()`, which filters on `is_defect()`, which
    /// excludes exactly those three. The arm exists to satisfy exhaustiveness
    /// and is dead.
    ///
    /// Left in place rather than made `unreachable!()`, because a panic in this
    /// path would be worse than a dead arm. What matters is the invariant behind
    /// it: were `is_defect` ever widened, a coverage record would quietly become
    /// an `Info` finding — a fact about the instrument presented as a fact about
    /// the code, which is the failure this whole codebase is organised against.
    /// This test is what would object.
    #[test]
    fn an_observation_of_non_defects_produces_no_findings() {
        let mut obs = Observation::default();
        obs.events.push(RuntimeEvent::new(RuntimeEventKind::Coverage, "line 12 executed"));
        obs.events.push(RuntimeEvent::new(RuntimeEventKind::ValueObservation, "x = 7"));
        obs.events.push(RuntimeEvent::new(RuntimeEventKind::Syscall, "openat"));

        let found = findings_from(&obs, "src/target.c");
        assert!(
            found.is_empty(),
            "a coverage record is not a defect; it became {:?}",
            found.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>()
        );
    }

    /// A sanitizer states `file:line:col` and stops there, so dynamic findings
    /// were points while static findings on the same line were spans. The
    /// source is on disk; the token is recoverable from it.
    #[test]
    fn a_stated_column_gets_the_extent_of_its_token_from_the_source() {
        let dir = std::env::temp_dir().join(format!("sda-dyn-span-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src").join("main.c"), "int main(void) {\n    buffer[index] = 1;\n}\n")
            .unwrap();

        let mut findings = vec![
            // Column 5 is `buffer`, six characters wide.
            Finding::new(
                "sda.dynamic",
                "SDA-DYN-MEMORY",
                "t",
                Severity::Critical,
                Location::new("src/main.c", 2, 5),
            ),
            // Column 1 is what the probe stream writes when it has no column at
            // all; bracketing the line's first token would be a confident claim
            // about text nothing measured.
            Finding::new(
                "sda.dynamic",
                "SDA-DYN-MEMORY",
                "t",
                Severity::Critical,
                Location::new("src/main.c", 2, 1),
            ),
            // A file that is not there must be left alone, not guessed at.
            Finding::new(
                "sda.dynamic",
                "SDA-DYN-CRASH",
                "t",
                Severity::Critical,
                Location::new("src/nowhere.c", 2, 5),
            ),
        ];
        span_against_source(&mut findings, &dir);

        assert_eq!(findings[0].location.end_line, Some(2));
        assert_eq!(findings[0].location.end_column, Some(11), "`buffer` spans columns 5..11");
        assert_eq!(findings[1].location.end_column, None, "column 1 states no column");
        assert_eq!(findings[2].location.end_column, None, "an unreadable file yields no span");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// An extent the finding already carries is the producer's own and must not
    /// be overwritten by a text-derived guess.
    #[test]
    fn an_existing_span_is_not_replaced() {
        let dir = std::env::temp_dir().join(format!("sda-dyn-keep-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.c"), "int x = 0;\n").unwrap();

        let mut findings = vec![Finding::new(
            "sda.dynamic",
            "r",
            "t",
            Severity::High,
            Location::new("a.c", 1, 5).spanning(1, 99),
        )];
        span_against_source(&mut findings, &dir);
        assert_eq!(findings[0].location.end_column, Some(99));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn probe_stream_parses_coverage_and_faults() {
        let stream = r#"
{"t":"cov","f":"src/main.c","l":42,"n":7}
{"t":"cov","f":"src/main.c","l":42,"n":3}
{"t":"fault","f":"src/main.c","l":51,"k":"bounds","m":"write of 4 bytes at index 16 of a 16-byte buffer"}
{"t":"mark","k":"stack_high_water","v":2048}
"#;
        let obs = parse_probe_stream(stream, "r1");
        assert_eq!(obs.covered("src/main.c", 42), 10, "repeated coverage accumulates");
        assert_eq!(obs.covered("src/main.c", 43), 0);
        assert_eq!(obs.marks.get("stack_high_water"), Some(&2048.0));
        assert_eq!(obs.defects().count(), 1);
        assert_eq!(obs.events[0].kind, RuntimeEventKind::MemoryError);
    }

    #[test]
    fn a_truncated_final_line_does_not_lose_the_whole_stream() {
        let stream = "{\"t\":\"cov\",\"f\":\"a.c\",\"l\":1}\n{\"t\":\"cov\",\"f\":\"a.c\",\"l\"";
        let obs = parse_probe_stream(stream, "r1");
        assert_eq!(obs.covered("a.c", 1), 1);
    }

    /// The summary is what a *file* handed in by a user needs and a live
    /// subprocess does not. Skipping an unreadable line is right for a stream
    /// whose last record is half-flushed; it is wrong for a capture, where the
    /// same silence covers "this is not a probe stream at all".
    #[test]
    fn a_capture_reports_how_much_of_it_was_readable() {
        let (obs, sum) = parse_probe_capture(
            "{\"t\":\"cov\",\"f\":\"a.c\",\"l\":1}\nnot json at all\n{\"t\":\"cov\",\"f\":\"a.c\",\"l\":2}\n",
            "cap",
        );
        assert_eq!(sum.records, 2);
        assert_eq!(sum.unreadable, 1);
        assert_eq!(obs.covered("a.c", 1), 1);
    }

    /// An observation with no coverage is not nothing: it is the claim that
    /// execution *was* measured and these lines did not run, which is what makes
    /// `Refuted` and `Unreached` available. A caller must be able to tell that
    /// claim from a file the parser could read nothing out of, or a truncated
    /// UART log manufactures refutations.
    #[test]
    fn a_capture_of_noise_is_distinguishable_from_a_run_that_covered_nothing() {
        let (noise, sum) = parse_probe_capture("garbage\nmore garbage\n", "cap");
        assert_eq!(sum.records, 0, "nothing in this file is a probe record");
        assert_eq!(sum.unreadable, 2);
        assert!(noise.coverage.is_empty());

        // Byte-identical observation, entirely different provenance: this run
        // was measured and emitted a mark rather than any coverage.
        let (measured, sum) = parse_probe_capture("{\"t\":\"mark\",\"k\":\"stack\",\"v\":64}\n", "cap");
        assert_eq!(sum.records, 1);
        assert!(measured.coverage.is_empty());
        assert_eq!(sum.unreadable, 0);
    }

    /// Empty input is the same question with no evidence at all, and must not
    /// read as a measured run either.
    #[test]
    fn an_empty_capture_holds_no_records() {
        let (obs, sum) = parse_probe_capture("", "cap");
        assert_eq!(sum, StreamSummary { records: 0, unreadable: 0 });
        assert!(obs.coverage.is_empty() && obs.events.is_empty());
    }

    #[test]
    fn coverage_matches_across_absolute_and_relative_paths() {
        let obs = parse_probe_stream(
            "{\"t\":\"cov\",\"f\":\"C:\\\\build\\\\proj\\\\src/main.c\",\"l\":9}\n",
            "r1",
        );
        assert_eq!(obs.covered("src/main.c", 9), 1);
        assert!(obs.file_executed("src/main.c"));
        assert!(!obs.file_executed("src/other.c"));
    }

    #[test]
    fn address_sanitizer_reports_are_located() {
        let stderr = "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff4\n\
                      WRITE of size 4 at 0x60200000eff4 thread T0\n\
                      #0 0x4f1a2b in store /home/x/src/buf.c:88:5\n\
                      #1 0x4f2000 in main /home/x/src/main.c:12:3\n";
        let events = parse_diagnostics(stderr, "r1");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, RuntimeEventKind::MemoryError);
        let loc = events[0].location.as_ref().unwrap();
        assert_eq!(loc.line, 88);
        assert!(loc.file.to_string_lossy().ends_with("buf.c"));
    }

    #[test]
    fn sanitizer_families_are_distinguished() {
        let race = parse_diagnostics("==1==ERROR: ThreadSanitizer: data race on x\n", "r");
        assert_eq!(race[0].kind, RuntimeEventKind::DataRace);
        let leak = parse_diagnostics("==1==ERROR: LeakSanitizer: detected memory leaks\n", "r");
        assert_eq!(leak[0].kind, RuntimeEventKind::Leak);
    }

    #[test]
    fn ubsan_runtime_errors_are_parsed_with_position() {
        let events =
            parse_diagnostics("src/math.c:17:9: runtime error: signed integer overflow\n", "r1");
        assert_eq!(events[0].kind, RuntimeEventKind::UndefinedBehavior);
        let loc = events[0].location.as_ref().unwrap();
        assert_eq!((loc.line, loc.column), (17, 9));
    }

    #[test]
    fn rust_panics_are_parsed() {
        let stderr = "thread 'main' panicked at src/lib.rs:22:14:\ncalled `Option::unwrap()` on a `None` value\n";
        let events = parse_diagnostics(stderr, "r1");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, RuntimeEventKind::Crash);
        assert!(events[0].detail.contains("Option::unwrap"));
        assert_eq!(events[0].location.as_ref().unwrap().line, 22);
    }

    #[test]
    fn windows_paths_survive_location_parsing() {
        let loc = parse_file_line_col("C:\\build\\src\\main.c:42:7").unwrap();
        assert_eq!(loc.line, 42);
        assert_eq!(loc.column, 7);
        assert!(loc.file.to_string_lossy().starts_with("C:\\build"));
    }

    #[test]
    fn timeouts_are_resource_exhaustion_not_crashes() {
        let o = RunOutcome {
            run_id: "r".into(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 10_000,
            timed_out: true,
        };
        assert!(!o.crashed());
        let events = outcome_events(&o);
        assert_eq!(events[0].kind, RuntimeEventKind::ResourceExhaustion);
    }

    #[test]
    fn a_clean_exit_produces_no_events() {
        let o = RunOutcome {
            run_id: "r".into(),
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 5,
            timed_out: false,
        };
        assert!(o.succeeded());
        assert!(outcome_events(&o).is_empty());
    }

    #[test]
    fn runtime_defects_become_certain_findings_with_evidence() {
        let obs = parse_probe_stream(
            "{\"t\":\"fault\",\"f\":\"src/a.c\",\"l\":5,\"k\":\"bounds\",\"m\":\"oob write\"}\n",
            "r1",
        );
        let f = findings_from(&obs, "/proj");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, Confidence::Certain);
        assert_eq!(f[0].phase, sda_core::AnalysisPhase::Dynamic);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].has_runtime_evidence());
        assert!(f[0].taxonomy.iter().any(|t| t.id == "CWE-787"));
    }

    #[test]
    fn coverage_alone_never_becomes_a_finding() {
        let obs = parse_probe_stream("{\"t\":\"cov\",\"f\":\"a.c\",\"l\":1}\n", "r1");
        assert!(findings_from(&obs, "/proj").is_empty());
    }

    #[test]
    fn an_engine_with_no_runs_declares_itself_unavailable() {
        let e = DynamicEngine::new(vec![]);
        match e.available() {
            Availability::Unavailable { reason } => assert!(reason.contains("built artifact")),
            other => panic!("expected unavailable, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_artifact_is_reported_rather_than_silently_skipped() {
        let e = DynamicEngine::new(vec![RunSpec::new("./definitely-not-here-xyz")]);
        assert!(!e.available().is_usable());
    }

    #[test]
    fn observations_merge_additively() {
        let mut a = parse_probe_stream("{\"t\":\"cov\",\"f\":\"a.c\",\"l\":1,\"n\":2}\n", "r1");
        let b = parse_probe_stream("{\"t\":\"cov\",\"f\":\"a.c\",\"l\":1,\"n\":3}\n", "r2");
        a.merge(b);
        assert_eq!(a.covered("a.c", 1), 5);
    }
}

