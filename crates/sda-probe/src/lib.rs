//! The SDA probe instrumentation.
//!
//! The correlation engine needs to know whether a line *executed*. Without that
//! it cannot tell "this defect did not occur" from "this code never ran", and
//! the whole statodynamic claim collapses into a static one.
//!
//! On a hosted target the compiler supplies coverage. On the targets this
//! toolkit exists for — armclang, IAR, TI CGT, anything bare-metal — there is no
//! coverage flag and no sanitizer runtime. `sda-build` says so explicitly and
//! points here. This crate is what it points at.
//!
//! ```no_run
//! fn read_sample(buffer: &[u8], index: usize) -> u8 {
//!     sda_probe::cov(file!(), line!());
//!     if index >= buffer.len() {
//!         sda_probe::fault(file!(), line!(), "bounds", "index past end of buffer");
//!         return 0;
//!     }
//!     buffer[index]
//! }
//!
//! sda_probe::init();
//! let _ = read_sample(&[1, 2, 3], 7);
//! sda_probe::flush();
//! ```
//!
//! # What it writes, and why in that order
//!
//! Records go to the path in `SDA_PROBE_OUT`, which the dynamic engine sets
//! before launching the target. Faults are written **through** and flushed
//! immediately; coverage is aggregated in memory and flushed in batches.
//!
//! That asymmetry is deliberate. A fault is usually followed closely by a crash,
//! and a buffered fault record is a lost one — losing the evidence of the very
//! thing being hunted. Coverage is high-frequency and individually cheap to
//! lose, so it is batched, and a fault flush also flushes coverage so the
//! context around a crash survives with it.
//!
//! The C counterpart, for targets with no Rust toolchain, is `shim/sda_probe.h`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

/// How many distinct coverage sites to accumulate before flushing.
const COVERAGE_BATCH: usize = 256;

/// The environment variable naming the output stream. Set by the dynamic engine.
pub const OUTPUT_ENV: &str = "SDA_PROBE_OUT";

struct Session {
    out: Option<std::fs::File>,
    /// `(file, line) -> count`, aggregated between flushes.
    coverage: BTreeMap<(String, u32), u64>,
    /// Records written since the process started, for `stats`.
    written: u64,
    /// Whether a write has already failed. Instrumentation must never take the
    /// program down, so a broken stream disables itself silently after saying
    /// so once.
    broken: bool,
}

impl Session {
    fn new() -> Session {
        let out = std::env::var(OUTPUT_ENV).ok().and_then(|path| {
            std::fs::OpenOptions::new().create(true).append(true).open(path).ok()
        });
        Session { out, coverage: BTreeMap::new(), written: 0, broken: false }
    }

    fn enabled(&self) -> bool {
        self.out.is_some() && !self.broken
    }

    fn write_line(&mut self, line: &str) {
        if !self.enabled() {
            return;
        }
        let Some(file) = self.out.as_mut() else { return };
        if writeln!(file, "{line}").is_err() || file.flush().is_err() {
            // Say it once, on stderr, then go quiet. An instrumented run that
            // silently stops recording would look like a run with no findings.
            eprintln!("sda-probe: output stream failed; instrumentation is now disabled");
            self.broken = true;
            return;
        }
        self.written += 1;
    }

    fn flush_coverage(&mut self) {
        if self.coverage.is_empty() || !self.enabled() {
            self.coverage.clear();
            return;
        }
        let batch: Vec<String> = self
            .coverage
            .iter()
            .map(|((f, l), n)| {
                format!(r#"{{"t":"cov","f":{},"l":{l},"n":{n}}}"#, quote(f))
            })
            .collect();
        self.coverage.clear();
        for line in batch {
            self.write_line(&line);
        }
    }
}

fn session() -> &'static Mutex<Session> {
    static SESSION: OnceLock<Mutex<Session>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(Session::new()))
}

/// Open the probe stream. Optional — any probe call initialises on demand — but
/// calling it explicitly at start-up moves the file open off the hot path.
pub fn init() {
    // Take and immediately release the lock: the point is the `OnceLock`
    // initialisation it forces, which is what opens the file.
    drop(session().lock());
}

/// Whether instrumentation is active. False when `SDA_PROBE_OUT` is unset, which
/// is the normal state for a production build.
pub fn is_enabled() -> bool {
    session().lock().map(|s| s.enabled()).unwrap_or(false)
}

/// Record that a source location executed.
pub fn cov(file: &str, line: u32) {
    let Ok(mut s) = session().lock() else { return };
    if !s.enabled() {
        return;
    }
    *s.coverage.entry((file.to_string(), line)).or_insert(0) += 1;
    if s.coverage.len() >= COVERAGE_BATCH {
        s.flush_coverage();
    }
}

/// Record a fault detected by instrumentation: a bounds violation, an overflow,
/// a contract breach. Written through and flushed, because what follows a fault
/// is often a crash.
///
/// `kind` should be one the engine classifies: `bounds`, `uninit`, `shift`,
/// `signed-overflow`, `null-deref`, `leak`, `race`, `stack`, `oom`, `timeout`.
pub fn fault(file: &str, line: u32, kind: &str, message: &str) {
    let Ok(mut s) = session().lock() else { return };
    if !s.enabled() {
        return;
    }
    // Coverage first, so the path leading to the fault survives alongside it.
    s.flush_coverage();
    let line = format!(
        r#"{{"t":"fault","f":{},"l":{line},"k":{},"m":{}}}"#,
        quote(file),
        quote(kind),
        quote(message)
    );
    s.write_line(&line);
}

/// Record a value observed at a probe point.
pub fn value(file: &str, line: u32, key: &str, v: f64) {
    let Ok(mut s) = session().lock() else { return };
    if !s.enabled() {
        return;
    }
    let line = format!(
        r#"{{"t":"val","f":{},"l":{line},"k":{},"v":{}}}"#,
        quote(file),
        quote(key),
        number(v)
    );
    s.write_line(&line);
}

/// Record the operands of a comparison the program performed.
///
/// This is what makes low-throughput fuzzing effective. Guessing a four-byte
/// magic value blind takes about 2^32 attempts; a fuzzer that can *see* the
/// program compare something against `0x5A474D46` can simply write that value
/// into the input. The technique is worth far more here than in a conventional
/// fuzzer, because executing a process per input caps throughput at tens of runs
/// per second — brute force is not available, so knowledge has to substitute.
///
/// Instrument the comparisons that gate interesting code: magic numbers, length
/// fields, protocol tags. Instrumenting every comparison in a hot loop will cost
/// more than it returns.
pub fn cmp(file: &str, line: u32, lhs: u64, rhs: u64) {
    let Ok(mut s) = session().lock() else { return };
    if !s.enabled() {
        return;
    }
    let record = format!(
        r#"{{"t":"cmp","f":{},"l":{line},"a":{lhs},"b":{rhs}}}"#,
        quote(file)
    );
    s.write_line(&record);
}

/// Record a resource high-water mark, e.g. stack usage.
pub fn mark(key: &str, v: f64) {
    let Ok(mut s) = session().lock() else { return };
    if !s.enabled() {
        return;
    }
    let line = format!(r#"{{"t":"mark","k":{},"v":{}}}"#, quote(key), number(v));
    s.write_line(&line);
}

/// Flush pending coverage. Call before a clean exit; faults are already durable.
pub fn flush() {
    if let Ok(mut s) = session().lock() {
        s.flush_coverage();
    }
}

/// Records written so far, for tests and diagnostics.
pub fn written() -> u64 {
    session().lock().map(|s| s.written).unwrap_or(0)
}

/// Minimal JSON string escaping. Written by hand so the shim has no dependency
/// and the C header can mirror it exactly.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// JSON has no NaN or Infinity; emit null rather than invalid JSON that would
/// make the parser discard the record — and with it every record after it in a
/// partially-read stream.
fn number(v: f64) -> String {
    if v.is_finite() { format!("{v}") } else { "null".to_string() }
}

/// Record that the current line executed.
#[macro_export]
macro_rules! cov {
    () => {
        $crate::cov(file!(), line!())
    };
}

/// Record a fault at the current line.
#[macro_export]
macro_rules! fault {
    ($kind:expr, $msg:expr) => {
        $crate::fault(file!(), line!(), $kind, $msg)
    };
}

/// Compare two values, reporting the operands to the fuzzer and yielding the
/// comparison's result. Wraps a condition so instrumenting it does not change
/// what the code does.
#[macro_export]
macro_rules! cmp_eq {
    ($lhs:expr, $rhs:expr) => {{
        let (a, b) = ($lhs, $rhs);
        $crate::cmp(file!(), line!(), a as u64, b as u64);
        a == b
    }};
}

/// Check a condition, recording a fault if it does not hold. Unlike `assert!`,
/// this does not terminate: the point is to keep running and collect more.
#[macro_export]
macro_rules! check {
    ($cond:expr, $kind:expr, $msg:expr) => {
        if !$cond {
            $crate::fault(file!(), line!(), $kind, $msg);
        }
    };
}

/// Bounds-check an index, recording a fault rather than panicking.
pub fn check_bounds(file: &str, line: u32, index: usize, len: usize) -> bool {
    if index < len {
        return true;
    }
    fault(
        file,
        line,
        "bounds",
        &format!("index {index} is outside a container of length {len}"),
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Point the process-global session at a fresh file.
    ///
    /// The session is deliberately a singleton — an instrumented target has one
    /// output stream, not one per call site — so tests that exercise it cannot
    /// run in parallel against separate files. They are therefore gathered into
    /// one sequential test rather than papered over with a locking crate.
    fn rebind(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("sda-probe-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.jsonl"));
        let _ = std::fs::remove_file(&path);

        // Opened before the lock is taken, and `unwrap`ped rather than `.ok()`d.
        // A session whose stream failed to open is *disabled*, so every emitter
        // below becomes a no-op and every assertion fails as though the emitter
        // had a bug — `covered() == 0` reads as "repeat hits do not aggregate"
        // when the truth is "nothing was ever written". That is this toolkit's
        // own central failure mode reproduced inside its own test harness: an
        // inability to check, presented as a check. It fails as itself now.
        let out = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("probe stream {} could not be opened: {e}", path.display()));

        let mut s = session().lock().unwrap();
        s.out = Some(out);
        s.coverage.clear();
        s.broken = false;
        drop(s);
        assert!(is_enabled(), "the probe session must be live before a test emits into it");
        path
    }

    fn collect(path: &std::path::Path) -> sda_engine::Observation {
        flush();
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let _ = std::fs::remove_file(path);
        sda_engine::dynamic::parse_probe_stream(&text, "test")
    }

    /// Emitting and parsing are a contract between two crates. Testing them
    /// against each other is the only way to know the shim is not writing
    /// something the engine quietly discards.
    #[test]
    fn the_emitter_and_the_engines_parser_agree() {
        // --- every record type survives the round trip ---
        let path = rebind("all-records");
        cov("src/main.c", 42);
        cov("src/main.c", 42);
        cov("src/main.c", 43);
        fault("src/main.c", 51, "bounds", "index past end of buffer");
        mark("stack_high_water", 2048.0);
        value("src/main.c", 60, "retries", 3.0);
        // The fifth emitter. "Every record type" covered four of them: `cmp` was
        // written, parsed into `Observation::comparisons`, and exercised by no
        // test at all — which is the thing this test's own comment says it is
        // here to rule out.
        cmp("src/main.c", 70, 4096, 8192);

        let obs = collect(&path);
        assert_eq!(obs.covered("src/main.c", 42), 2, "repeat hits aggregate");
        assert_eq!(obs.covered("src/main.c", 43), 1);
        assert_eq!(obs.marks.get("stack_high_water"), Some(&2048.0));
        assert!(
            obs.comparisons.contains(&4096) && obs.comparisons.contains(&8192),
            "both sides of a comparison reach the observation — the instrumentation \
             cannot tell which one is the constant an input has to match: {:?}",
            obs.comparisons
        );
        let faults: Vec<_> = obs.defects().collect();
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].kind, sda_core::RuntimeEventKind::MemoryError);
        assert_eq!(faults[0].location.as_ref().unwrap().line, 51);

        // --- a fault flushes the coverage that led to it ---
        // The crash case: the path into a fault is what makes it diagnosable, so
        // it must already be durable when the fault is written — not at exit,
        // which a crashing target never reaches.
        let path = rebind("fault-flush");
        cov("a.c", 10);
        fault("a.c", 11, "bounds", "boom");
        let text = std::fs::read_to_string(&path).unwrap();
        let unflushed = sda_engine::dynamic::parse_probe_stream(&text, "test");
        assert_eq!(
            unflushed.covered("a.c", 10),
            1,
            "coverage must be on disk by the time the fault is, without an explicit flush"
        );
        assert_eq!(unflushed.defects().count(), 1);
        let _ = std::fs::remove_file(&path);

        // --- escaping produces valid JSON ---
        let path = rebind("escaping");
        fault(
            r#"src\win\path.c"#,
            7,
            "bounds",
            "wrote \"12\" bytes\ninto a 4-byte buffer\t(twice)",
        );
        let obs = collect(&path);
        let faults: Vec<_> = obs.defects().collect();
        assert_eq!(faults.len(), 1, "an escaping bug would make the record unparseable");
        assert!(faults[0].detail.contains("into a 4-byte buffer"));

        // --- a non-finite value does not poison the records after it ---
        let path = rebind("non-finite");
        mark("ratio", f64::NAN);
        mark("good", 1.5);
        let obs = collect(&path);
        assert_eq!(obs.marks.get("good"), Some(&1.5));

        // --- the bounds helper reports only real violations ---
        let path = rebind("bounds");
        assert!(check_bounds("a.c", 3, 2, 8));
        assert!(!check_bounds("a.c", 4, 8, 8));
        let obs = collect(&path);
        let faults: Vec<_> = obs.defects().collect();
        assert_eq!(faults.len(), 1);
        assert!(faults[0].detail.contains("length 8"));

        // --- with no stream, instrumentation is inert rather than fatal ---
        let path = rebind("inert");
        {
            let mut s = session().lock().unwrap();
            s.out = None;
        }
        assert!(!is_enabled());
        cov("a.c", 1);
        fault("a.c", 1, "bounds", "should not be written");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn escaping_matches_json_rules() {
        assert_eq!(quote("a\"b"), r#""a\"b""#);
        assert_eq!(quote("a\\b"), r#""a\\b""#);
        assert_eq!(quote("a\nb"), r#""a\nb""#);
        assert_eq!(quote("a\tb"), r#""a\tb""#);
        // Control characters take the \uXXXX form, the only escape JSON accepts
        // for them.
        assert_eq!(quote("\u{1}"), r#""\u0001""#);
    }

    #[test]
    fn non_finite_numbers_become_null_rather_than_invalid_json() {
        assert_eq!(number(1.5), "1.5");
        assert_eq!(number(f64::NAN), "null");
        assert_eq!(number(f64::INFINITY), "null");
        assert_eq!(number(f64::NEG_INFINITY), "null");
    }
}



