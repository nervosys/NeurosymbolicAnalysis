//! The Verus parser against output captured from the real prover.
//!
//! `every_adapter_parses.rs` and `sda-engine`'s `external_coverage.rs` are the
//! model, and this one earned its place the same way they did — by finding that
//! the obvious integration is silently wrong.
//!
//! Both fixtures come from one run of `tools/verus-guard/guard.rs` under Verus
//! 0.2026.08.30.b432e82 on rustc 1.97.1 in WSL Debian. The program is written so
//! the prover must both succeed and fail: `clamp` satisfies its postcondition,
//! `unchecked` cannot, and the assertions below name lines of that file.
//!
//! **Three things the real tool taught, none of which reading would have.**
//!
//! 1. **Verus exits 0 on a failed proof.** `verification results:: 3 verified, 1
//!    errors`, `error: aborting due to 1 previous error`, and `$? == 0`. A CI
//!    gate keyed on the exit code passes a build whose proof failed.
//! 2. **`--output-json` records that something failed and never which thing.**
//!    Its `func-details` map has an entry per function with
//!    `obligation_proof_notes` and `failed_proof_notes` lists — and on this run
//!    `guard::unchecked`, the function that failed, carries `failed_proof_notes:
//!    []`, identical to every function that passed. The only failure signal in
//!    the JSON is the aggregate `errors: 1`.
//! 3. **The location exists only in the stderr text.** So the parser takes both
//!    channels, and a run where the counts and the diagnostics disagree is
//!    reported rather than reconciled.
//!
//! Compose those and a proof failure is invisible from every direction an
//! integrator would naturally look: exit code clean, per-function JSON clean,
//! and only an aggregate integer and an unstructured text stream saying
//! otherwise.

use sda_adapters::{parse_verus, parse_verus_findings};
use sda_core::verification::ObligationStatus;
use sda_core::{Confidence, Severity};

const JSON: &str = include_str!("fixtures/ext.verus.json");
const DIAGNOSTICS: &str = include_str!("fixtures/ext.verus.txt");

#[test]
fn the_json_counts_the_failure_and_the_diagnostics_locate_it() {
    let run = parse_verus(JSON, DIAGNOSTICS).expect("real verus json");
    assert_eq!(run.version, "0.2026.08.30.b432e82");
    assert_eq!(run.verified, 3);
    assert_eq!(run.errors, 1);
    assert!(!run.success);
    assert!(run.problems.is_empty(), "the channels agree here: {:?}", run.problems);

    assert_eq!(run.failures.len(), 1);
    let f = &run.failures[0];
    assert_eq!(f.statement, "postcondition not satisfied");
    let loc = f.location.as_ref().expect("located");
    assert_eq!(loc.file.to_string_lossy(), "guard.rs");
    assert_eq!(loc.line, 41, "the `ensures in_range(result)` on `unchecked`");
    assert_eq!(loc.column, 9);
    assert!(matches!(f.status, ObligationStatus::Failed { .. }));
    assert_eq!(f.prover.as_deref(), Some("ext.verus"));
}

/// The fact that motivated taking two channels instead of one.
#[test]
fn the_json_alone_cannot_say_which_function_failed() {
    let v: serde_json::Value = serde_json::from_str(JSON).unwrap();
    let details = &v["func-details"];
    assert!(
        details.get("guard::unchecked").is_some(),
        "the failing function is present in the map"
    );
    assert_eq!(
        details["guard::unchecked"]["failed_proof_notes"],
        serde_json::json!([]),
        "and its failed_proof_notes is empty — identical to every function that passed"
    );
    assert_eq!(details["guard::clamp"]["failed_proof_notes"], serde_json::json!([]));

    // Which is why a parser given only the JSON must report a failure it cannot
    // locate, rather than a clean run.
    let run = parse_verus(JSON, "").expect("json alone still parses");
    assert_eq!(run.errors, 1);
    assert!(run.failures.is_empty());
    assert_eq!(run.problems.len(), 1);
    assert!(
        run.problems[0].contains("only 0 could be located"),
        "an unlocatable failure is still a failure: {}",
        run.problems[0]
    );
}

/// `error: aborting due to 1 previous error` is rustc's summary, not a proof
/// obligation. Counting it would inflate every failing run by exactly one.
#[test]
fn the_rustc_summary_line_is_not_mistaken_for_an_obligation() {
    assert!(DIAGNOSTICS.contains("error: aborting due to 1 previous error"));
    let run = parse_verus(JSON, DIAGNOSTICS).unwrap();
    assert_eq!(run.failures.len(), 1, "one obligation, not two");
    assert!(!run.failures.iter().any(|f| f.statement.contains("aborting")));
}

/// Verus names what it could not prove and only counts what it could, so the
/// ledger gets failures and nothing else. Three anonymous `Discharged`
/// obligations would be claims no tool made.
#[test]
fn only_failures_become_obligations() {
    let run = parse_verus(JSON, DIAGNOSTICS).unwrap();
    let obligations = run.obligations();
    assert_eq!(obligations.len(), 1);
    assert!(obligations.iter().all(|o| !o.status.is_discharged()));
    assert_eq!(run.verified, 3, "the successes are a number, and stay one");
}

#[test]
fn contradicting_channels_are_reported_rather_than_reconciled() {
    // Verus says it succeeded; the diagnostics carry a failure. Neither is
    // silently preferred.
    let optimistic = JSON.replace("\"success\": false", "\"success\": true");
    let run = parse_verus(&optimistic, DIAGNOSTICS).unwrap();
    assert!(
        run.problems.iter().any(|p| p.contains("contradict each other")),
        "{:?}",
        run.problems
    );
}

#[test]
fn a_failure_that_is_not_a_proof_obligation_is_not_read_as_one() {
    let broken = JSON.replace("\"errors\": 1", "\"errors\": 0");
    let run = parse_verus(&broken, "").unwrap();
    assert!(
        run.problems.iter().any(|p| p.contains("not a proof obligation")),
        "a crash or a toolchain error must not read as a verification result: {:?}",
        run.problems
    );
}

#[test]
fn malformed_json_is_an_error_rather_than_an_empty_run() {
    assert!(parse_verus("{", DIAGNOSTICS).is_err());
    assert!(
        parse_verus("{}", DIAGNOSTICS).is_err(),
        "no `verification-results` means this is not a verus run"
    );
}

/// A failed obligation is a defect claim with a location, which is what a
/// finding is — so it can reach a report, a SARIF export and the GUI.
#[test]
fn a_failed_obligation_becomes_a_finding_that_states_what_it_does_not_claim() {
    let findings = parse_verus_findings(JSON, DIAGNOSTICS, "ext.verus").unwrap();
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.rule.as_str(), "VERUS-POSTCONDITION-NOT-SATISFIED");
    assert_eq!(f.location.line, 41);
    assert_eq!(f.severity, Severity::High);
    assert_eq!(
        f.confidence,
        Confidence::Certain,
        "a prover searched and could not establish it; that is not a heuristic's suspicion"
    );
    assert!(
        f.message.contains("not the same as showing the defect occurs"),
        "an obligation can fail because the specification is too weak, and the finding says so"
    );
    assert!(
        f.evidence.iter().any(|e| matches!(e, sda_core::Evidence::Proof { .. })),
        "the obligation travels with the finding"
    );
}

#[test]
fn the_obligations_that_passed_produce_no_findings() {
    let findings = parse_verus_findings(JSON, DIAGNOSTICS, "ext.verus").unwrap();
    assert_eq!(
        findings.len(),
        1,
        "3 verified, and none of them named — three clean findings would be three claims about \
         lines no tool mentioned"
    );
}

#[test]
fn an_unreadable_report_produces_a_finding_rather_than_fewer_findings() {
    // JSON alone: one error, zero locations. The shortfall must be visible in
    // the same channel the findings are, not only in a side list.
    let findings = parse_verus_findings(JSON, "", "ext.verus").unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule.as_str(), "VERUS-REPORT-INCOMPLETE");
    assert!(findings[0].message.contains("only 0 could be located"));
}

// ---------------------------------------------------------------------------
// The same prover, driven through cargo instead of directly. Different bytes,
// and the difference broke the parser.
// ---------------------------------------------------------------------------

const CARGO_JSON: &str = include_str!("fixtures/ext.verus-cargo.json");
const CARGO_DIAGNOSTICS: &str = include_str!("fixtures/ext.verus-cargo.txt");

/// `cargo verus verify` ends its stderr with cargo's summary, not rustc's.
///
/// Standalone `verus` writes `error: aborting due to 1 previous error`, which
/// the parser always skipped. Through cargo the last line is instead
/// ``error: could not compile `vnew` (bin "vnew") due to 1 previous error`` —
/// also an `error:` line, also not a proof obligation, and **not** skipped until
/// a real `cargo verus` run was captured. The standalone fixture never contained
/// it, so nothing here could have caught it.
#[test]
fn cargos_summary_line_is_not_counted_as_a_second_obligation() {
    assert_eq!(
        CARGO_DIAGNOSTICS.matches("\nerror: ").count()
            + usize::from(CARGO_DIAGNOSTICS.starts_with("error: ")),
        2,
        "two `error:` lines in the stream, one of which is cargo's"
    );
    assert!(CARGO_DIAGNOSTICS.contains("could not compile `vnew`"));

    let run = parse_verus(CARGO_JSON, CARGO_DIAGNOSTICS).unwrap();
    assert_eq!(run.errors, 1);
    assert_eq!(run.failures.len(), 1, "one obligation, not two");
    assert!(run.problems.is_empty(), "and no shortfall either way: {:?}", run.problems);
}

#[test]
fn the_cargo_run_locates_the_same_obligation_in_the_crate_layout() {
    let run = parse_verus(CARGO_JSON, CARGO_DIAGNOSTICS).unwrap();
    let f = &run.failures[0];
    assert_eq!(f.statement, "postcondition not satisfied");
    let loc = f.location.as_ref().unwrap();
    assert_eq!(
        loc.file.to_string_lossy(),
        "src/main.rs",
        "cargo reports a crate-relative path where the standalone run reported `guard.rs`"
    );
    assert_eq!(loc.line, 41);
}

/// The guard that would have caught the bug above, had it existed first.
#[test]
fn more_diagnostics_than_errors_is_reported_rather_than_believed() {
    let inflated = format!("{CARGO_DIAGNOSTICS}\nerror: something else entirely\n");
    let run = parse_verus(CARGO_JSON, &inflated).unwrap();
    assert_eq!(run.failures.len(), 2);
    assert!(
        run.problems.iter().any(|p| p.contains("would overstate what failed")),
        "{:?}",
        run.problems
    );
}

/// A crate nobody specified must not report as a crate that passed.
///
/// `cargo verus verify` on ordinary Rust builds it, verifies nothing, and exits
/// cleanly — which is what the adapter would have surfaced as a clean deductive
/// result. It is the deductive analogue of a clean scan over an empty file set.
#[test]
fn a_crate_with_no_specifications_is_reported_as_vacuous_not_clean() {
    let unspecified = CARGO_JSON
        .replace("\"success\": false", "\"success\": true")
        .replace("\"verified\": 3", "\"verified\": 0")
        .replace("\"errors\": 1", "\"errors\": 0");
    let run = parse_verus(&unspecified, "").unwrap();
    assert_eq!(run.verified, 0);
    assert!(run.success);
    assert!(
        run.problems.iter().any(|p| p.contains("verifies vacuously")),
        "{:?}",
        run.problems
    );

    // And it reaches a report rather than only a side list.
    let findings = parse_verus_findings(&unspecified, "", "ext.verus").unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule.as_str(), "VERUS-REPORT-INCOMPLETE");
}
