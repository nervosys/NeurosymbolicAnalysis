//! The autonomous software-engineering loop.
//!
//! Build → diagnose → patch → verify, with the toolkit supplying everything
//! except the patch. That division is deliberate: proposing a change is what a
//! language model is good at, and *deciding whether the change worked* is what
//! it is worst at, because it is the step where a plausible story is most likely
//! to be believed over the evidence.
//!
//! So the loop here owns the evidence. It decides when to stop, it refuses to
//! declare success while errors remain, and it detects the two failure modes
//! that make unattended loops dangerous: thrashing between states, and
//! "progress" that only moves the error somewhere else.

use sda_build::{BuildContext, BuildOutcome, Diagnostic, Level};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One problem for the agent to work on, with everything needed to fix it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkItem {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Source lines around the problem, so the agent does not have to read the
    /// file separately and risk acting on a stale copy.
    pub context: String,
    /// Line number of the first line of `context`.
    pub context_start: u32,
    /// How many other diagnostics share this file, for prioritisation.
    pub siblings_in_file: usize,
}

/// Why the loop stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stop {
    /// The build succeeded with no errors. The only success condition.
    Clean,
    /// No further progress: the same diagnostics keep coming back.
    Stalled,
    /// The loop oscillated between two states, which means each fix undoes the last.
    Thrashing,
    /// The iteration budget ran out with work remaining.
    BudgetExhausted,
    /// The build could not be run at all.
    Unbuildable,
}

impl Stop {
    pub fn succeeded(&self) -> bool {
        matches!(self, Stop::Clean)
    }
    pub fn explain(&self) -> &'static str {
        match self {
            Stop::Clean => "the build completed with no errors",
            Stop::Stalled => {
                "the same diagnostics reappeared after a change, so the last patch did not \
                 address them; a human should look at the first error"
            }
            Stop::Thrashing => {
                "the diagnostic set oscillated between two states, which means successive patches \
                 are undoing each other; stop and reconsider the approach rather than iterating"
            }
            Stop::BudgetExhausted => "the iteration budget ran out with errors still present",
            Stop::Unbuildable => "the project could not be built at all, so no diagnostics exist",
        }
    }
}

/// One turn of the loop.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Iteration {
    pub number: u32,
    pub build_succeeded: bool,
    pub error_count: usize,
    pub warning_count: usize,
    /// The single most actionable problem, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<WorkItem>,
    /// Whether this iteration reduced the error count.
    pub progressed: bool,
    pub summary: String,
}

/// The loop's state across iterations.
///
/// Persisted between invocations. The stall and thrash detectors compare the
/// current diagnostic set against previous ones, so a session that starts empty
/// every time can never fire either of them — the loop would iterate forever
/// without noticing it was going in circles. An agent calls `sda swe`
/// repeatedly, applying a patch between calls, and the state has to survive
/// those process boundaries for the detection to mean anything.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Session {
    /// Fingerprints of the diagnostic sets seen so far, to detect thrashing.
    history: Vec<u64>,
    /// Error counts, to detect stalling.
    error_counts: Vec<usize>,
    pub iterations: Vec<Iteration>,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    /// Where a project's session lives.
    pub fn state_path(root: &Path) -> PathBuf {
        root.join(".sda").join("swe-session.json")
    }

    /// Resume a session, or start one. A malformed or unreadable state file
    /// starts fresh rather than failing: losing loop history is a nuisance,
    /// refusing to run is worse.
    pub fn resume(root: &Path) -> Session {
        std::fs::read_to_string(Self::state_path(root))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Persist the session so the next invocation can detect a loop.
    pub fn save(&self, root: &Path) -> Result<(), String> {
        let path = Self::state_path(root);
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // Through the symlink guard: the repository being scanned can commit `.sda`.
        sda_core::safe_write::write_refusing_symlinks(&path, text)
            .map_err(|e| format!("could not write {}: {e}", path.display()))
    }

    /// Discard persisted state, for starting a fresh attempt.
    pub fn reset(root: &Path) -> Result<(), String> {
        let path = Self::state_path(root);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("could not remove {}: {e}", path.display())),
        }
    }

    /// How many iterations this session has recorded.
    pub fn len(&self) -> usize {
        self.iterations.len()
    }
    pub fn is_empty(&self) -> bool {
        self.iterations.is_empty()
    }

    /// Record an outcome and decide whether to continue.
    pub fn record(&mut self, outcome: &BuildOutcome, root: &Path, context_lines: u32) -> Iteration {
        let errors: Vec<&Diagnostic> =
            outcome.diagnostics.iter().filter(|d| d.level == Level::Error).collect();
        let warnings = outcome.diagnostics.iter().filter(|d| d.level == Level::Warning).count();

        let fingerprint = fingerprint(&outcome.diagnostics);
        let progressed = self
            .error_counts
            .last()
            .map(|prev| errors.len() < *prev)
            .unwrap_or(true);

        self.history.push(fingerprint);
        self.error_counts.push(errors.len());

        // An error outranks a warning; a warning is better than nothing.
        let next = errors
            .first()
            .copied()
            .or_else(|| outcome.diagnostics.first())
            .map(|d| work_item(d, &outcome.diagnostics, root, context_lines));

        let it = Iteration {
            number: self.iterations.len() as u32 + 1,
            build_succeeded: outcome.success,
            error_count: errors.len(),
            warning_count: warnings,
            next,
            progressed,
            summary: outcome.summary(),
        };
        self.iterations.push(it.clone());
        it
    }

    /// Whether to stop, and why.
    pub fn should_stop(&self, budget: u32) -> Option<Stop> {
        let last = self.iterations.last()?;

        if last.build_succeeded && last.error_count == 0 {
            return Some(Stop::Clean);
        }
        // Oscillation: state N matches state N-2 but not N-1. Two patches that
        // each undo the other will do this forever.
        if self.history.len() >= 3 {
            let n = self.history.len();
            if self.history[n - 1] == self.history[n - 3] && self.history[n - 1] != self.history[n - 2] {
                return Some(Stop::Thrashing);
            }
        }
        // Stalling: the identical diagnostic set twice running.
        if self.history.len() >= 2 {
            let n = self.history.len();
            if self.history[n - 1] == self.history[n - 2] {
                return Some(Stop::Stalled);
            }
        }
        if self.iterations.len() as u32 >= budget {
            return Some(Stop::BudgetExhausted);
        }
        None
    }

    /// A record of the whole session, for the report.
    pub fn transcript(&self) -> String {
        let mut s = String::new();
        for it in &self.iterations {
            s.push_str(&format!(
                "#{} — {} error(s), {} warning(s){}\n    {}\n",
                it.number,
                it.error_count,
                it.warning_count,
                if it.progressed { "" } else { " (no progress)" },
                it.summary
            ));
        }
        s
    }
}

/// A 64-bit digest of the diagnostic set, ignoring ordering and column noise.
fn fingerprint(diags: &[Diagnostic]) -> u64 {
    let mut keys: BTreeSet<String> = BTreeSet::new();
    for d in diags {
        keys.insert(format!("{}|{}|{}|{:?}", d.file, d.line, d.message, d.level));
    }
    // FNV-1a: no dependency, and stable across runs, which a HashMap hash is not.
    let mut h: u64 = 0xcbf29ce484222325;
    for k in keys {
        for b in k.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

fn work_item(d: &Diagnostic, all: &[Diagnostic], root: &Path, context_lines: u32) -> WorkItem {
    let path = resolve(root, &d.file);
    let (context_start, context) = read_context(&path, d.line, context_lines);
    WorkItem {
        file: d.file.clone(),
        line: d.line,
        column: d.column,
        message: d.message.clone(),
        code: d.code.clone(),
        context,
        context_start,
        siblings_in_file: all.iter().filter(|o| o.file == d.file).count(),
    }
}

fn resolve(root: &Path, file: &str) -> PathBuf {
    let p = PathBuf::from(file);
    if p.is_absolute() { p } else { root.join(p) }
}

fn read_context(path: &Path, line: u32, radius: u32) -> (u32, String) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (line, String::new());
    };
    let lines: Vec<&str> = text.lines().collect();
    let first = line.saturating_sub(radius).max(1);
    let last = line.saturating_add(radius).min(lines.len() as u32);
    if first > last {
        return (line, String::new());
    }
    let body: Vec<String> = (first..=last)
        .map(|n| format!("{n:>5} | {}", lines[(n - 1) as usize]))
        .collect();
    (first, body.join("\n"))
}

/// Run one iteration against a project: build, diagnose, and hand back the next
/// thing to fix. Applying the patch is the caller's job.
pub fn iterate(
    root: &Path,
    session: &mut Session,
    context_lines: u32,
    timeout: Duration,
) -> Result<Iteration, String> {
    let ctx = BuildContext::probe(root);
    let Some(detected) = ctx.primary() else {
        return Err(format!(
            "no build system was recognised at {}. The autonomous loop needs something it can \
             build; `sda build detect` lists what was looked for.",
            root.display()
        ));
    };
    let compiler = ctx.compilers.first();
    let outcome = sda_build::build(detected, compiler, None, timeout)?;
    Ok(session.record(&outcome, root, context_lines))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_build::toolchain::DiagnosticFormat;

    fn outcome(text: &str, success: bool) -> BuildOutcome {
        BuildOutcome {
            command: "make".into(),
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: String::new(),
            stderr: text.into(),
            duration_ms: 100,
            diagnostics: sda_build::parse_diagnostics(text, DiagnosticFormat::GccLike),
            unsupported: Vec::new(),
        }
    }

    fn root() -> PathBuf {
        std::env::temp_dir()
    }

    #[test]
    fn a_clean_build_is_the_only_success_condition() {
        let mut s = Session::new();
        s.record(&outcome("", true), &root(), 2);
        assert_eq!(s.should_stop(10), Some(Stop::Clean));
        assert!(Stop::Clean.succeeded());
    }

    #[test]
    fn a_successful_exit_with_errors_present_is_not_success() {
        let mut s = Session::new();
        // A build system that returns 0 despite errors must not fool the loop.
        s.record(&outcome("a.c:1:1: error: boom", true), &root(), 2);
        assert_ne!(s.should_stop(10), Some(Stop::Clean));
    }

    #[test]
    fn identical_diagnostics_twice_running_is_a_stall() {
        let mut s = Session::new();
        let o = outcome("a.c:1:1: error: boom", false);
        s.record(&o, &root(), 2);
        assert_eq!(s.should_stop(10), None, "one iteration is not yet a stall");
        s.record(&o, &root(), 2);
        assert_eq!(s.should_stop(10), Some(Stop::Stalled));
        assert!(Stop::Stalled.explain().contains("did not address"));
    }

    #[test]
    fn oscillating_between_two_states_is_detected_as_thrashing() {
        let mut s = Session::new();
        let a = outcome("a.c:1:1: error: alpha", false);
        let b = outcome("b.c:2:1: error: beta", false);
        s.record(&a, &root(), 2);
        s.record(&b, &root(), 2);
        s.record(&a, &root(), 2);
        assert_eq!(s.should_stop(10), Some(Stop::Thrashing));
        assert!(Stop::Thrashing.explain().contains("undoing each other"));
    }

    #[test]
    fn steady_progress_keeps_the_loop_running() {
        let mut s = Session::new();
        s.record(&outcome("a.c:1:1: error: one\nb.c:2:1: error: two", false), &root(), 2);
        let second = s.record(&outcome("b.c:2:1: error: two", false), &root(), 2);
        assert!(second.progressed);
        assert_eq!(s.should_stop(10), None);
    }

    #[test]
    fn the_budget_stops_a_loop_that_would_otherwise_run_forever() {
        let mut s = Session::new();
        for i in 0..3 {
            s.record(&outcome(&format!("a.c:{}:1: error: e{i}", i + 1), false), &root(), 2);
        }
        assert_eq!(s.should_stop(3), Some(Stop::BudgetExhausted));
    }

    #[test]
    fn the_next_item_is_the_first_error_not_the_first_warning() {
        let mut s = Session::new();
        let it = s.record(
            &outcome("a.c:1:1: warning: w\nb.c:9:4: error: real problem", false),
            &root(),
            2,
        );
        let next = it.next.unwrap();
        assert_eq!(next.file, "b.c");
        assert_eq!(next.line, 9);
        assert!(next.message.contains("real problem"));
    }

    #[test]
    fn work_items_carry_source_context_read_from_disk() {
        let d = std::env::temp_dir().join("sda-swe-ctx");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.c"), "line1\nline2\nline3\nline4\nline5\n").unwrap();

        let mut s = Session::new();
        let it = s.record(&outcome("a.c:3:1: error: boom", false), &d, 1);
        let next = it.next.unwrap();
        assert_eq!(next.context_start, 2);
        assert!(next.context.contains("line2"));
        assert!(next.context.contains("line3"));
        assert!(!next.context.contains("line5"));

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_missing_source_file_yields_empty_context_rather_than_failing() {
        let mut s = Session::new();
        let it = s.record(&outcome("ghost.c:3:1: error: boom", false), &root(), 2);
        assert!(it.next.unwrap().context.is_empty());
    }

    #[test]
    fn sibling_counts_help_prioritise_a_file_with_many_problems() {
        let mut s = Session::new();
        let it = s.record(
            &outcome("a.c:1:1: error: e1\na.c:5:1: error: e2\nb.c:1:1: error: e3", false),
            &root(),
            1,
        );
        assert_eq!(it.next.unwrap().siblings_in_file, 2);
    }

    #[test]
    fn fingerprints_ignore_ordering_but_not_content() {
        let a = sda_build::parse_diagnostics(
            "a.c:1:1: error: x\nb.c:2:1: error: y",
            DiagnosticFormat::GccLike,
        );
        let b = sda_build::parse_diagnostics(
            "b.c:2:1: error: y\na.c:1:1: error: x",
            DiagnosticFormat::GccLike,
        );
        let c = sda_build::parse_diagnostics("a.c:1:1: error: z", DiagnosticFormat::GccLike);
        assert_eq!(fingerprint(&a), fingerprint(&b));
        assert_ne!(fingerprint(&a), fingerprint(&c));
    }

    #[test]
    fn an_unbuildable_project_is_reported_with_what_to_do() {
        let d = std::env::temp_dir().join("sda-swe-empty");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let err = iterate(&d, &mut Session::new(), 2, Duration::from_secs(5)).unwrap_err();
        assert!(err.contains("no build system"));
        assert!(err.contains("sda build detect"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_session_survives_the_process_boundary_so_loops_are_detectable() {
        // The defect this guards: the CLI runs one iteration per invocation. A
        // session that reset each time would make the stall detector below
        // unreachable, and an agent could iterate forever without being told it
        // was making no progress.
        let d = std::env::temp_dir().join("sda-swe-persist");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();

        let o = outcome("a.c:1:1: error: boom", false);

        let mut first = Session::resume(&d);
        assert!(first.is_empty(), "a project with no state starts fresh");
        first.record(&o, &d, 1);
        assert_eq!(first.should_stop(10), None, "one iteration cannot be a stall");
        first.save(&d).unwrap();

        // A separate invocation, as the CLI would do it.
        let mut second = Session::resume(&d);
        assert_eq!(second.len(), 1, "the earlier iteration must be remembered");
        second.record(&o, &d, 1);
        assert_eq!(
            second.should_stop(10),
            Some(Stop::Stalled),
            "identical diagnostics across invocations is exactly what stalling means"
        );

        Session::reset(&d).unwrap();
        assert!(Session::resume(&d).is_empty());
        // Resetting twice is not an error.
        Session::reset(&d).unwrap();

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_corrupt_state_file_starts_fresh_rather_than_failing() {
        let d = std::env::temp_dir().join("sda-swe-corrupt");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".sda")).unwrap();
        std::fs::write(Session::state_path(&d), "{ not json").unwrap();
        assert!(Session::resume(&d).is_empty());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_transcript_records_every_iteration() {
        let mut s = Session::new();
        s.record(&outcome("a.c:1:1: error: e", false), &root(), 1);
        s.record(&outcome("", true), &root(), 1);
        let t = s.transcript();
        assert!(t.contains("#1"));
        assert!(t.contains("#2"));
    }
}
