//! Four verdicts in one report, with every piece of runtime evidence external.
//!
//! `external_coverage.rs` proves the parsers read what gcov and LCOV really
//! write. This proves the thing those parsers exist for: that an external
//! dynamic tool, which reports defects and counts no lines, can *refute* and show
//! *unreached* once a coverage report supplies the counts. Before that seam
//! existed, `correlate` received `None` for such a run and only `Confirmed` was
//! reachable — a dynamic tool could corroborate a static finding and could never
//! contradict one.
//!
//! Both fixtures are captures, not reconstructions, from one build of
//! `examples/coverage/main.c` under WSL Debian:
//!
//! ```text
//! gcc -g -O0 --coverage -c main.c -o build/main.o && gcc --coverage -o build/prog build/main.o
//! (cd build && ./prog) && gcov -o build main.c
//! valgrind --leak-check=full --show-leak-kinds=all ./prog
//! ```
//!
//! The program was written around the three lines the assertions name, and what
//! each is for is documented in its own header comment:
//!
//! | line | evidence | verdict |
//! |---|---|---|
//! | 21 | gcov measured it at zero | `Unreached` — the claim is untested, not clean |
//! | 30 | Memcheck lost 16 bytes here | `Confirmed` |
//! | 37 | gcov counted 40 executions, Memcheck found nothing | `Refuted` |
//!
//! Line 21 is the one that matters most. A tool that treated "no runtime defect"
//! as evidence of correctness would call it clean; it was never executed.

use sda_core::{AnalyzerKind, Analyzer, Capability, Finding, Language, ProviderInfo, Target, TargetFile};
use sda_core::{CorrelationVerdict, RunOptions};
use sda_engine::run::{RunConfig, analyze};
use sda_engine::{coverage, default_registry};

const GCOV: &str = include_str!("fixtures/gcov-14.2.0.gcov");
const MEMCHECK: &str = include_str!("fixtures/valgrind-3.24.0-coverage.txt");
const SOURCE: &str = include_str!("../../../examples/coverage/main.c");

/// Replays a captured Memcheck run in place of spawning Valgrind.
///
/// It is a stand-in for the *process*, not for the tool: the bytes are the real
/// tool's, and they are parsed by the same `parse_valgrind` a live run goes
/// through. Spawning WSL from a unit test would make this a test of whichever
/// machine runs it — `tools/valgrind-wsl/` exists for that, and drove this
/// capture.
struct ReplayedMemcheck;

impl Analyzer for ReplayedMemcheck {
    fn info(&self) -> ProviderInfo {
        ProviderInfo::native(
            "ext.valgrind",
            "Valgrind Memcheck (replayed capture)",
            AnalyzerKind::Dynamic,
            vec![Language::C],
            vec![Capability::MemorySafety],
            "a captured Memcheck 3.24.0 run over examples/coverage",
        )
    }
    fn analyze(&self, _t: &Target, _o: &RunOptions) -> sda_core::Result<Vec<Finding>> {
        let mut findings = sda_adapters::parse::parse_valgrind(MEMCHECK, "ext.valgrind")
            .expect("real memcheck stderr");
        // The same call the live adapter makes, and not a copy of it: a parsed
        // external finding is born `Static` and carries no runtime event, and
        // correlation needs both — it sorts on the phase and then asks the
        // event whether the witness is the same class of defect as the
        // suspicion. Re-deriving that here would test this file's idea of the
        // shape instead of the shipping one.
        sda_adapters::as_runtime_evidence(&mut findings);
        Ok(findings)
    }
}

fn target(dir: &std::path::Path) -> Target {
    let file = dir.join("main.c");
    std::fs::write(&file, SOURCE).unwrap();
    Target::new(dir).with_files(vec![TargetFile {
        path: file,
        language: Language::C,
        bytes: SOURCE.len() as u64,
    }])
}

fn verdicts_at(report: &sda_core::Report, line: u32) -> Vec<CorrelationVerdict> {
    let ids: Vec<&sda_core::FindingId> = report
        .findings
        .iter()
        .filter(|f| f.location.line == line)
        .map(|f| &f.id)
        .collect();
    report
        .correlations
        .iter()
        .filter(|c| c.static_finding.as_ref().is_some_and(|i| ids.contains(&i)))
        .map(|c| c.verdict)
        .collect()
}

/// Each test gets its own directory.
///
/// One shared path here made this file fail intermittently and differently on
/// each run: `cargo test` runs these four in parallel threads, and they were all
/// removing, recreating and writing the same directory underneath one another.
/// The failures looked like correlation defects and were not, which is the worst
/// kind of flake — it was misread once as a stale build artifact.
fn report(name: &str) -> sda_core::Report {
    let dir = std::env::temp_dir().join(format!("sda-external-dynamic-refutes-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut registry = default_registry();
    registry.register(std::sync::Arc::new(ReplayedMemcheck));

    let counts = coverage::parse(GCOV).expect("gcov 14.2.0").observation;
    let config = RunConfig::default().with_external().with_observation(counts);
    analyze(&registry, &target(&dir), &config)
}

#[test]
fn a_line_memcheck_witnessed_is_confirmed() {
    let r = report("confirmed");
    let at_30 = verdicts_at(&r, 30);
    assert!(!at_30.is_empty(), "the leaked allocation's line carries static findings");
    assert!(
        at_30.iter().all(|v| *v == CorrelationVerdict::Confirmed),
        "Memcheck lost 16 bytes at main.c:30: {at_30:?}"
    );
}

#[test]
fn a_hot_line_no_tool_faulted_on_is_refuted() {
    let r = report("refuted");
    assert!(
        verdicts_at(&r, 37).contains(&CorrelationVerdict::Refuted),
        "line 37 executed 40 times and nothing faulted"
    );
}

/// The row most tools get wrong, and the reason coverage had to be wired in at
/// all: without counts this line is indistinguishable from a clean one.
#[test]
fn a_line_that_never_ran_is_unreached_rather_than_clean() {
    let r = report("unreached");
    let at_21 = verdicts_at(&r, 21);
    assert!(!at_21.is_empty(), "`never()`'s malloc is flagged statically");
    assert!(
        at_21.iter().all(|v| *v == CorrelationVerdict::Unreached),
        "gcov measured line 21 at zero: {at_21:?}"
    );
    assert!(
        !at_21.contains(&CorrelationVerdict::Refuted),
        "a line that never executed must never be refuted: that converts a coverage hole \
         into a clean bill of health"
    );
}

/// All four at once, which is the claim the toolkit is named for and which no
/// external dynamic tool could make before the coverage seam existed.
#[test]
fn one_run_of_external_tools_produces_every_verdict() {
    let r = report("every");
    let seen: std::collections::BTreeSet<&str> =
        r.correlations.iter().map(|c| c.verdict.as_str()).collect();
    for want in ["confirmed", "refuted", "unreached"] {
        assert!(seen.contains(want), "missing `{want}` from {seen:?}");
    }
}
