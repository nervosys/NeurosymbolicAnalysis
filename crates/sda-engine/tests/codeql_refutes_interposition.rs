//! The whole loop, on real bytes: a declared architecture, a real taint run, and
//! a proof that the declaration was wrong.
//!
//! Everything else in this repository tests one link. This tests the chain that
//! the neurosymbolic design exists to produce:
//!
//! 1. `.sda/architecture.toml` declares the shape of a shielded system, and
//!    `sda_engine::interposition` **proves** every model output reaches the
//!    effector through the guard. Over the declaration, it does.
//! 2. CodeQL 2.26.4, run over the actual program, reports a path that does not.
//! 3. The proof is **refuted** — by the code, against the declaration, with the
//!    bypassing path named.
//!
//! The fixture is the same file `sda-adapters` tests its `codeFlows` parser
//! against, and it is parsed here by the same `parse_sarif` a user's report goes
//! through. A hand-built `Finding` would have tested this file's own idea of
//! what CodeQL emits, which is the failure mode the whole fixture discipline
//! exists to prevent — and which this exact seam already walked into once, when
//! `parse_sarif` silently dropped every flow it was given.
//!
//! The program is `tools/codeql-taint/`: `policy/serve.py` stands in for the
//! model, `guard/clamp.py` is the shield, `actuator/drive.py` is the effector,
//! and `telemetry/relay.py` is the relay the declaration forgets.

use sda_core::verification::Boundary;
use sda_engine::interposition::{self, FlowGraph};
use sda_engine::neurosymbolic::SystemMap;
use sda_rules::ArchitectureDeclaration;

const CODEQL: &str = include_str!("fixtures/codeql-2.26.4-taint.sarif");

/// The architecture as someone would write it: everything goes through the guard.
const DECLARED: &str = r#"
[[component]]
name = "policy"
path = "policy"
boundary = "neural"
architecture = "transformer"
parameters = 7000000000

[[component]]
name = "guard::clamp"
path = "guard"
boundary = "symbolic"
role = "guard"

[[component]]
name = "telemetry"
path = "telemetry"
boundary = "symbolic"

[[component]]
name = "actuator"
path = "actuator"
boundary = "symbolic"
role = "effector"

[[flow]]
from = "policy"
to = "guard::clamp"

[[flow]]
from = "guard::clamp"
to = "actuator"
"#;

fn system() -> SystemMap {
    let decl = ArchitectureDeclaration::parse(DECLARED).expect("well-formed");
    assert!(decl.rejected().is_empty());
    assert!(decl.warnings().is_empty(), "{:?}", decl.warnings());
    let built = sda_engine::from_declaration(&decl);
    assert!(built.problems.is_empty());
    built.map
}

fn flow() -> FlowGraph {
    let decl = ArchitectureDeclaration::parse(DECLARED).unwrap();
    sda_engine::from_declaration(&decl).flow
}

fn codeql_findings() -> Vec<sda_core::Finding> {
    sda_adapters::parse_sarif(CODEQL, "ext.codeql").expect("real codeql sarif")
}

#[test]
fn the_declaration_alone_proves_interposition() {
    let proved = interposition::verify(&system(), &flow(), &[]);
    assert!(proved.is_interposed(), "over the declared dataflow, the guard cannot be bypassed");
    assert_eq!(proved.obligations.len(), 1);
    assert!(proved.obligations[0].status.is_discharged());
    assert!(interposition::summarize(&proved).contains("proved guarded"));
}

#[test]
fn the_real_taint_run_refutes_it_and_names_the_path() {
    let taint = codeql_findings();
    assert_eq!(taint.len(), 1);

    let refuted = interposition::verify(&system(), &flow(), &taint);
    assert!(!refuted.is_interposed(), "the code disagrees with the declaration, and the code wins");
    assert_eq!(refuted.bypasses.len(), 1);

    let bypass = &refuted.bypasses[0];
    assert_eq!(bypass.model, "policy");
    assert_eq!(bypass.effector, "actuator");
    assert!(
        bypass.path.contains(&"telemetry".to_string()),
        "the relay the declaration forgot: {:?}",
        bypass.path
    );
    assert!(
        !bypass.path.contains(&"guard::clamp".to_string()),
        "and the guard is not on it, which is the whole claim"
    );
    assert!(bypass.describe().contains("observed by taint analysis"));
    assert!(interposition::summarize(&refuted).contains("NOT established"));
}

/// The premise the interposition proof rests on is exactly what turned out false.
#[test]
fn the_refutation_lands_on_the_premise_the_proof_named() {
    let proved = interposition::verify(&system(), &flow(), &[]);
    assert_eq!(
        proved.assumptions[0].id,
        interposition::FAITHFULNESS,
        "the proof said its premise was that the declaration matches the code"
    );
    // And it did not. That is the premise being useful rather than decorative:
    // it named in advance the thing a real tool then contradicted.
    let refuted = interposition::verify(&system(), &flow(), &codeql_findings());
    assert!(!refuted.bypasses.is_empty());
    assert!(refuted.unevaluable_taint.is_empty(), "this report carried its path and was read");
}

#[test]
fn the_flow_crosses_the_boundaries_the_declaration_draws() {
    let map = system();
    assert_eq!(map.component_for("policy/serve.py").unwrap().boundary, Boundary::Neural);
    assert_eq!(map.component_for("actuator/drive.py").unwrap().name, "actuator");
    assert!(
        map.component_for("app.py").is_none(),
        "the wiring module belongs to no declared component, which is itself worth reporting"
    );

    // `sda.vacuous` is the ledger's line, not the interposition check's, so it
    // appears once the refuted proof is folded in and adjudicated — which is
    // where a report assembles the two.
    let refuted = interposition::verify(&map, &flow(), &codeql_findings());
    let ledger = refuted.merge_into(Default::default());
    let adjudication = sda_engine::adjudicate(&[], &ledger, &map);
    assert!(
        adjudication.not_checked.iter().any(|l| l.contains("sda.vacuous[guard::clamp]")),
        "the guard carries no obligation of its own, and a report must say so: {:?}",
        adjudication.not_checked
    );
    assert!(
        adjudication.not_checked.iter().any(|l| l.contains("sda.intractable[policy]")),
        "and the 7B model is beyond every prover"
    );
}
