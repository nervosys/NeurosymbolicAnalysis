//! Correlation declines to re-raise a finding the process already settled —
//! but only if it was ever told about the deviation.
//!
//! `correlate` has this rule written into it, with the reason beside it:
//!
//! ```text
//! // A suppressed finding has an approved deviation; correlating it would
//! // only re-raise something the process already settled.
//! if sf.is_suppressed() { ... }
//! ```
//!
//! Deviations are applied in `analyze` *before* correlation runs, so in a scan
//! the rule fires. A caller that builds its `RunConfig` from `default()` never
//! loads the register, so nothing in that run is ever marked suppressed, and
//! the refusal above never has anything to refuse. The engine's stated rule is
//! defeated one layer up, by a config that arrived empty.
//!
//! Two callers did that: `sda fuzz` and `fuzz.campaign`, both of which correlate
//! a campaign's coverage into confirmed and refuted verdicts. A verdict table
//! that re-raises accepted findings is the thing the comment above exists to
//! prevent, printed under a heading about what the campaign proved.
//!
//! This tests the mechanism rather than the two commands, deliberately. Driving
//! `sda fuzz` end to end needs a built and instrumented artifact; what actually
//! went wrong is one config away from the engine, and that is measurable here
//! against a fixture already calibrated against gcov 14.2.0.

use sda_core::{Language, Target, TargetFile};
use sda_engine::run::{RunConfig, analyze};
use sda_engine::{coverage, default_registry};
use std::path::{Path, PathBuf};

const GCOV: &str = include_str!("fixtures/gcov-14.2.0.gcov");

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

/// `examples/coverage`, the tree the gcov fixture was recorded against.
fn target() -> Target {
    let dir = repo_root().join("examples").join("coverage");
    let main = dir.join("main.c");
    let bytes = std::fs::metadata(&main).map(|m| m.len()).unwrap_or(0);
    Target::new(&dir).with_files(vec![TargetFile {
        path: main,
        language: Language::C,
        bytes,
    }])
}

fn verdict_total(report: &sda_core::Report) -> usize {
    report.summary.by_verdict.values().sum()
}

/// `21.6` fires three times in this file; deviating it for the file removes
/// every one of them from correlation and nothing else.
const REGISTER: &str = "[[deviation]]\n\
                        rule = \"MISRA-C-2023-21.6\"\n\
                        scope = \"file\"\n\
                        path = \"main.c\"\n\
                        rationale = \"diagnostic build only; compiled out when shipping\"\n\
                        approver = \"a.erickson\"\n";

#[test]
fn a_run_without_the_register_correlates_findings_the_register_had_settled() {
    let observation = coverage::parse(GCOV).expect("gcov 14.2.0 parses").observation;
    let registry = default_registry();

    let without =
        analyze(&registry, &target(), &RunConfig::default().with_observation(observation.clone()));

    let register = sda_rules::DeviationRegister::parse(REGISTER).expect("the register parses");
    let with = analyze(
        &registry,
        &target(),
        &RunConfig::default().with_observation(observation).with_deviations(register),
    );

    // The premise: this run correlates something at all, or the comparison
    // below is between two zeroes and proves nothing.
    assert!(
        verdict_total(&without) > 0,
        "the fixture must produce verdicts: {:?}",
        without.summary.by_verdict
    );

    assert!(
        verdict_total(&with) < verdict_total(&without),
        "the deviated findings were correlated anyway. Without the register: {:?}. With it: \
         {:?}. `correlate` refuses to re-raise a suppressed finding, and a config that never \
         carried the register leaves nothing suppressed for it to refuse",
        without.summary.by_verdict,
        with.summary.by_verdict
    );

    // And the suppression is real rather than the findings vanishing: a
    // compliance record shows what was deviated.
    let suppressed = with.findings.iter().filter(|f| f.is_suppressed()).count();
    assert!(
        suppressed > 0,
        "the deviated findings stay in the report, marked: {:?}",
        with.summary
    );
    assert_eq!(
        with.findings.len(),
        without.findings.len(),
        "a deviation settles a finding; it does not delete it"
    );
}
