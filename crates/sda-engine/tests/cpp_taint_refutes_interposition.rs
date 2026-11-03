//! The refutation path against a *second* producer of `codeFlows`.
//!
//! `codeql_refutes_interposition.rs` drives the same chain with a Python taint
//! run. This is the C++ one, and it exists because a parser with a single witness
//! is a parser that fits one tool: `real_taint_report.rs` records that Semgrep OSS
//! emits no `codeFlows` at all, so before this fixture the whole refutation
//! channel rested on one capture from one language.
//!
//! It earned its place immediately. The Python result carries **one** code flow.
//! This C++ result carries **three** — and the first of them goes *through the
//! guard*, with the bypass second:
//!
//! ```text
//! codeFlow 0: 20 steps :: app.cpp -> policy -> app.cpp -> guard    -> app.cpp -> actuator
//! codeFlow 1: 20 steps :: app.cpp -> policy -> app.cpp -> telemetry -> app.cpp -> actuator
//! codeFlow 2: 24 steps :: app.cpp -> policy -> app.cpp -> guard    -> ... -> actuator
//! ```
//!
//! Both the SARIF parser and `taint_bypasses` used to read the *first* flow only,
//! and both were documented as doing so deliberately. For rendering that is
//! defensible. For refutation it is wrong: interposition fails if **any** route
//! reaches the effector without crossing a guard, so keeping one route made the
//! verdict depend on the order CodeQL happened to emit them — and here that order
//! would have reported a clean proof from a report containing its own
//! counterexample.
//!
//! The program is `tools/codeql-taint-cpp/`, the same four components as the
//! Python one, and the fixture is the real
//! `codeql database analyze ... cpp/command-line-injection` output of CodeQL
//! 2.26.4 over it, parsed by the same `parse_sarif` a user's report goes through.

use sda_engine::interposition::{self, FlowGraph};
use sda_engine::neurosymbolic::{Component, SystemMap};

const CPP: &str = include_str!("fixtures/codeql-2.26.4-cpp-taint.sarif");

/// The declaration a reviewer would write for `tools/codeql-taint-cpp/`:
/// everything reaches the actuator through the guard.
fn system() -> SystemMap {
    SystemMap::new()
        .with(Component::neural("policy", "policy"))
        .with(Component::symbolic("guard::clamp", "guard").guard())
        .with(Component::symbolic("telemetry", "telemetry"))
        .with(Component::symbolic("actuator", "actuator").effector())
}

fn flow() -> FlowGraph {
    FlowGraph::new().edge("policy", "guard::clamp").edge("guard::clamp", "actuator")
}

fn findings() -> Vec<sda_core::Finding> {
    sda_adapters::parse_sarif(CPP, "ext.codeql").expect("real codeql c++ sarif")
}

#[test]
fn the_declaration_alone_proves_interposition() {
    let proved = interposition::verify(&system(), &flow(), &[]);
    assert!(proved.is_interposed(), "over the declared dataflow the guard cannot be bypassed");
}

/// The claim this fixture was captured for.
#[test]
fn every_reported_flow_is_kept_not_just_the_first() {
    let found = findings();
    assert_eq!(found.len(), 1, "one result");

    let traces: Vec<&Vec<sda_core::TraceFrame>> = found[0]
        .evidence
        .iter()
        .filter_map(|e| match e {
            sda_core::Evidence::Trace { frames } => Some(frames),
            _ => None,
        })
        .collect();
    assert_eq!(traces.len(), 3, "CodeQL reported three code flows and all three are evidence");

    // The distinguishing property, stated as itself: the guarded route is first.
    let touches_guard = |frames: &Vec<sda_core::TraceFrame>| {
        frames
            .iter()
            .any(|f| f.location.file.to_string_lossy().replace('\\', "/").starts_with("guard/"))
    };
    assert!(touches_guard(traces[0]), "the first flow crosses the guard");
    assert!(!touches_guard(traces[1]), "and the second is the bypass");
}

#[test]
fn the_bypass_refutes_the_proof_even_though_it_is_not_the_first_flow() {
    let refuted = interposition::verify(&system(), &flow(), &findings());
    assert!(!refuted.is_interposed(), "the code disagrees with the declaration, and the code wins");
    assert_eq!(refuted.bypasses.len(), 1, "one bypass, not one per code flow: {:?}", refuted.bypasses);

    let b = &refuted.bypasses[0];
    assert_eq!(b.model, "policy");
    assert_eq!(b.effector, "actuator");
    assert!(b.path.contains(&"telemetry".to_string()), "the relay the declaration forgot: {:?}", b.path);
    assert!(!b.path.contains(&"guard::clamp".to_string()), "and the guard is not on it");
    assert!(b.describe().contains("observed by taint analysis"));
    assert!(interposition::summarize(&refuted).contains("NOT established"));
}

/// The two flows that *do* cross the guard must not become bypasses, and must not
/// become anything else either. A refutation channel that reported the guarded
/// route as a counterexample would fail every declaration it was ever shown.
#[test]
fn the_guarded_flows_refute_nothing() {
    let refuted = interposition::verify(&system(), &flow(), &findings());
    assert!(
        refuted.bypasses.iter().all(|b| !b.path.contains(&"guard::clamp".to_string())),
        "{:?}",
        refuted.bypasses
    );
    assert!(
        refuted.unevaluable_taint.is_empty(),
        "the finding carries traces, so nothing here is unevaluable: {:?}",
        refuted.unevaluable_taint
    );
}

/// CodeQL writes CWEs as `external/cwe/cwe-078`, and the C++ rule carries two.
/// This is the tag form that once meant no real CodeQL finding could be
/// confirmed; the C++ pack writes it the same way the Python one does.
#[test]
fn the_cwe_tag_form_is_the_same_in_the_cpp_pack() {
    let found = findings();
    assert_eq!(found[0].taxonomy_id(sda_core::Taxonomy::Cwe), Some("CWE-78"));
}
