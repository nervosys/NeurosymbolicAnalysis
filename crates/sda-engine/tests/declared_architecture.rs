//! `.sda/architecture.toml`, from the file on disk to the proof it licenses.
//!
//! The unit tests either side of this seam check the parser and the walk. This
//! checks that a declaration a person would actually write produces the proof
//! they expect — and, in the second test, that a declaration which *looks*
//! fine but omits a path is caught by the thing that reads the code rather than
//! the thing that reads the declaration.

use sda_engine::interposition::{self, FAITHFULNESS};
use sda_rules::ArchitectureDeclaration;

const DECLARED: &str = r#"
[[component]]
name = "policy"
path = "models/policy"
boundary = "neural"
architecture = "transformer"
parameters = 7000000000

[[component]]
name = "guard::clamp"
path = "src/guard"
boundary = "symbolic"
role = "guard"

[[component]]
name = "telemetry"
path = "src/telemetry"
boundary = "symbolic"

[[component]]
name = "actuator::drive"
path = "src/actuator"
boundary = "symbolic"
role = "effector"

[[flow]]
from = "policy"
to = "guard::clamp"

[[flow]]
from = "guard::clamp"
to = "actuator::drive"
"#;

#[test]
fn a_declaration_on_disk_licenses_a_conditional_claim_and_names_its_condition() {
    let decl = ArchitectureDeclaration::parse(DECLARED).expect("well-formed");
    assert!(decl.rejected().is_empty());
    assert!(decl.warnings().is_empty());

    let system = sda_engine::from_declaration(&decl);
    assert!(system.problems.is_empty(), "every word in the file mapped onto a type");

    let result = interposition::verify(&system.map, &system.flow, &[]);
    assert!(result.is_interposed());

    let ledger = result.merge_into(Default::default());
    let claim = ledger.conditional_claim("the actuator is never commanded out of range");
    assert!(claim.contains("PROVIDED"), "{claim}");
    assert!(
        ledger.weak_assumptions().iter().any(|a| a.id == FAITHFULNESS),
        "the proof is only ever as good as the declaration it walked"
    );
}

#[test]
fn a_relay_the_declaration_omits_is_caught_by_the_thing_that_reads_the_code() {
    use sda_core::{Evidence, Finding, Location, Severity, TraceFrame};

    let decl = ArchitectureDeclaration::parse(DECLARED).unwrap();
    let system = sda_engine::from_declaration(&decl);

    // The declaration routes everything through the guard, and nothing in the
    // file is wrong. A path exists in the code that the file does not describe.
    let observed = Finding::new(
        "ext.codeql",
        "rust/model-output-to-actuator",
        "model output reaches the actuator",
        Severity::High,
        Location::new("src/actuator/drive.rs", 88, 5),
    )
    .evidence(Evidence::Trace {
        frames: vec![
            TraceFrame {
                location: Location::new("models/policy/head.safetensors", 1, 1),
                note: "model output".into(),
                step: 0,
            },
            TraceFrame {
                location: Location::new("src/telemetry/relay.rs", 12, 3),
                note: "forwarded for logging, and not only for logging".into(),
                step: 1,
            },
            TraceFrame {
                location: Location::new("src/actuator/drive.rs", 88, 5),
                note: "written to the actuator".into(),
                step: 2,
            },
        ],
    });

    assert!(interposition::verify(&system.map, &system.flow, &[]).is_interposed());

    let refuted =
        interposition::verify(&system.map, &system.flow, std::slice::from_ref(&observed));
    assert!(!refuted.is_interposed(), "the declaration was faithful right up until it was not");
    assert_eq!(refuted.bypasses[0].path, ["policy", "telemetry", "actuator::drive"]);
    assert!(interposition::summarize(&refuted).contains("NOT established"));
}

#[test]
fn a_declaration_that_omits_the_guard_cannot_produce_a_clean_result() {
    let text = DECLARED.replace("role = \"guard\"\n", "");
    let decl = ArchitectureDeclaration::parse(&text).unwrap();
    assert!(
        decl.warnings().iter().any(|w| w.contains("bypass by construction")),
        "the parser says so before anything is walked: {:?}",
        decl.warnings()
    );

    let system = sda_engine::from_declaration(&decl);
    let result = interposition::verify(&system.map, &system.flow, &[]);
    assert!(!result.is_interposed());
    assert!(result.not_checked.iter().any(|l| l.contains("sda.no-guard")));
}
