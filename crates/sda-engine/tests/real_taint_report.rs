//! The interposition refutation path, against output from the real Semgrep.
//!
//! `crates/sda-adapters/tests/every_adapter_parses.rs` and
//! `external_coverage.rs` are the model for this, and it earned its place the
//! same way they did — by contradicting what the documentation says.
//!
//! `sda_engine::interposition` refutes an interposition proof from a taint
//! *flow*: it needs the path, because the endpoint alone cannot say whether a
//! guard was crossed. SARIF has a place for exactly that, `codeFlows`, and
//! Semgrep's `--dataflow-traces` flag documents itself as "only affects text and
//! SARIF output". Both of those are true and neither helps:
//!
//! * Semgrep OSS 1.176.0 with `--dataflow-traces` prints the trace in its **text**
//!   output — `Taint comes from:`, then the intermediate variables — and emits
//!   **no `codeFlows` at all** in its SARIF. `properties` is `{}`. The same run
//!   with `--json` carries no `dataflow_trace` either.
//! * So the finding this fixture holds arrives with a sink location and nothing
//!   else, and the refutation channel is inert for the canonical free taint
//!   provider.
//!
//! Had `codeFlows` parsing been written from the SARIF specification instead,
//! it would have been correct, complete, and never once exercised by this tool —
//! and `sda verify --taint` would have reported `interposed` while reading a
//! report it could not use. That is the `ext.modelscan` failure exactly.
//!
//! Captured by `tools/semgrep-taint/`, which holds the program, the rule, and
//! the command.

use sda_core::{Evidence, Finding, Location, Severity};
use sda_engine::interposition::{self, FlowGraph};
use sda_engine::neurosymbolic::{Component, SystemMap};
use sda_core::verification::Boundary;

const SEMGREP: &str = include_str!("fixtures/semgrep-1.176.0-taint.sarif");

/// The rule ids and paths below are the ones in `tools/semgrep-taint/`.
fn system() -> SystemMap {
    SystemMap::new()
        .with(Component::neural("policy", "models/policy"))
        .with(Component::symbolic("guard::clamp", "src/guard").guard())
        .with(Component::symbolic("actuator::drive", "src/actuator").effector())
        // Semgrep reports the sink at `src/main.py`, where the call is written,
        // rather than inside the module that defines `write_actuator`. That is
        // correct of it and worth pinning: a declaration that only named
        // `src/actuator` would not have matched the finding at all.
        .with(Component::symbolic("app", "src/main.py").effector())
}

fn guarded_declaration() -> FlowGraph {
    FlowGraph::new().edge("policy", "guard::clamp").edge("guard::clamp", "app")
}

/// What the real file actually contains, asserted rather than assumed.
#[test]
fn the_real_semgrep_sarif_carries_a_sink_and_no_flow() {
    let v: serde_json::Value = serde_json::from_str(SEMGREP).expect("valid SARIF");
    let result = &v["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "model-output-to-actuator");
    assert!(
        result.get("codeFlows").is_none(),
        "Semgrep OSS 1.176.0 emits no codeFlows, `--dataflow-traces` notwithstanding"
    );
    assert_eq!(
        result["properties"],
        serde_json::json!({}),
        "and nothing is tucked into properties either"
    );
    assert_eq!(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/main.py");
    assert_eq!(
        v["runs"][0]["tool"]["driver"]["semanticVersion"], "1.176.0",
        "the version this behaviour was observed in"
    );
}

/// The finding as it reaches `verify`, built to match what the parser produces
/// from the file above: one location, one note, no trace.
fn as_parsed() -> Finding {
    Finding::new(
        "ext.semgrep",
        "model-output-to-actuator",
        "model output reaches the actuator without passing through the guard",
        Severity::High,
        Location::new("src/main.py", 24, 5),
    )
    .evidence(Evidence::note("    write_actuator(forwarded)"))
}

#[test]
fn a_traceless_finding_is_reported_rather_than_silently_skipped() {
    let i = interposition::verify(&system(), &guarded_declaration(), &[as_parsed()]);

    // It cannot refute: nothing here says whether the guard was crossed.
    assert!(i.bypasses.is_empty());
    // But it must not vanish. Before this was handled, the run below produced a
    // clean proof from a report that could not be read.
    assert_eq!(i.unevaluable_taint.len(), 1);
    assert!(i.unevaluable_taint[0].contains("no dataflow trace"));
    assert!(i.unevaluable_taint[0].contains("neither refuted nor supported"));
    assert!(
        i.not_checked.iter().any(|l| l.contains("sda.taint-inert")),
        "every finding was unreadable, so the report contributed nothing at all: {:?}",
        i.not_checked
    );
    assert!(
        interposition::summarize(&i).contains("not a proof that was tested"),
        "the summary must not read as a proof the taint run endorsed"
    );
}

#[test]
fn a_traceless_finding_outside_an_effector_is_not_reported_as_unevaluable() {
    // Same shape, landing somewhere that could never have been a bypass. Noise
    // here would train a reader to skim the section that must not be skimmed.
    let elsewhere = Finding::new(
        "ext.semgrep",
        "python/unused-import",
        "unused import",
        Severity::Low,
        Location::new("src/guard/clamp.py", 1, 1),
    );
    let i = interposition::verify(&system(), &guarded_declaration(), &[elsewhere]);
    assert!(i.unevaluable_taint.is_empty());
    assert!(!i.not_checked.iter().any(|l| l.contains("sda.taint-untraced")));
}

#[test]
fn a_flow_that_does_carry_a_trace_still_refutes() {
    // Nothing about handling the blind case weakens the case this was built
    // for: a provider that does emit a path is read and does refute.
    let with_trace = as_parsed().evidence(Evidence::Trace {
        frames: vec![
            sda_core::TraceFrame {
                location: Location::new("models/policy/infer.py", 5, 12),
                note: "taint comes from `infer(prompt)`".into(),
                step: 0,
            },
            sda_core::TraceFrame {
                location: Location::new("src/main.py", 24, 5),
                note: "write_actuator(forwarded)".into(),
                step: 1,
            },
        ],
    });
    let i = interposition::verify(&system(), &guarded_declaration(), &[with_trace]);
    assert_eq!(i.bypasses.len(), 1);
    assert!(!i.is_interposed());
    assert!(i.unevaluable_taint.is_empty(), "it was evaluable, and it was evaluated");
}

#[test]
fn the_declaration_alone_would_have_called_this_system_guarded() {
    // The point of the whole exercise: `bypass()` in the real program routes
    // model output to the actuator through `relay`, and the declaration does not
    // mention `relay`. Semgrep found it. The declaration cannot.
    let i = interposition::verify(&system(), &guarded_declaration(), &[]);
    assert!(
        i.is_interposed(),
        "the declared graph is guarded, and the code — which Semgrep read — is not"
    );
    assert_eq!(i.obligations.len(), 1);
    assert_eq!(i.obligations[0].component, "app");
    assert_eq!(
        i.assumptions[0].id,
        interposition::FAITHFULNESS,
        "and this is the premise that was false"
    );
    assert_eq!(system().component_for("models/policy/infer.py").unwrap().boundary, Boundary::Neural);
}
