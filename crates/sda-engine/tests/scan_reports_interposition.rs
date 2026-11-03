//! A plain scan must say whether the declared guard holds.
//!
//! The interposition proof and the neurosymbolic adjudication used to live only
//! in `sda verify` and the MCP `analysis.verify` tool, so a project could ship an
//! `.sda/architecture.toml`, run `sda scan`, and get a clean report that never
//! mentioned the safety claim the project had written down. These tests drive
//! `run::analyze` — the one function all three run paths go through — rather than
//! the CLI, because the wiring being checked is the config-to-report seam.

use sda_core::{Language, Severity, Target, TargetFile};
use sda_engine::run::{RunConfig, analyze};
use sda_rules::ArchitectureDeclaration;
use std::fs;

/// A declaration whose *own graph* lets the model reach the effector directly.
/// No taint report is needed to refute this one: the project wrote the bypass
/// down itself.
const BYPASSED: &str = r#"
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
name = "actuator"
path = "actuator"
boundary = "symbolic"
role = "effector"

[[flow]]
from = "policy"
to = "actuator"
"#;

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sda-scan-interpose-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// A target with one trivial C file, so the run has something to analyze and the
/// interposition result is not the only thing in the report.
fn target(dir: &std::path::Path) -> Target {
    let file = dir.join("main.c");
    let src = "int main(void) { return 0; }\n";
    fs::write(&file, src).unwrap();
    Target::new(dir).with_files(vec![TargetFile {
        path: file,
        language: Language::C,
        bytes: src.len() as u64,
    }])
}

fn model_target(dir: &std::path::Path) -> Target {
    let file = dir.join("model.pkl");
    fs::write(&file, b"\x80\x04.").unwrap();
    Target::new(dir).with_files(vec![TargetFile {
        path: file,
        language: Language::ModelArtifact,
        bytes: 3,
    }])
}

fn reasons(report: &sda_core::Report, provider: &str) -> Vec<String> {
    report
        .exclusions
        .iter()
        .filter(|e| e.provider.as_str() == provider)
        .map(|e| e.reason.clone())
        .collect()
}

#[test]
fn a_scan_over_a_declared_bypass_reports_it_as_a_finding() {
    let dir = scratch("bypass");
    let decl = ArchitectureDeclaration::parse(BYPASSED).expect("well-formed");
    let config = RunConfig::default().with_architecture(decl);
    let report = analyze(&sda_engine::default_registry(), &target(&dir), &config);

    let bypass = report
        .findings
        .iter()
        .find(|f| f.rule.as_str() == "SDA-INTERPOSE-01")
        .expect("a refuted interposition proof must reach the findings, not only a summary line");
    // Critical because it is the safety property the declaration exists to
    // assert, and it does not hold.
    assert_eq!(bypass.severity, Severity::Critical);
    assert!(bypass.message.contains("policy"), "{}", bypass.message);
    assert!(bypass.message.contains("actuator"), "{}", bypass.message);
    // Located at the declaration: what is wrong is the claim, and no source line
    // is wrong in the way a bypass derived from the declared graph alone is.
    assert!(bypass.location.file.to_string_lossy().contains("architecture.toml"));

    let said = reasons(&report, "sda.interposition").join("\n");
    assert!(said.contains("NOT established"), "{said}");

    // The bypass is the deduction's output, so it must not also be its input.
    // Adjudicating it asks which declared component owns `.sda/architecture.toml`
    // — nothing does, and the answer arrived as an `sda.unmapped` line reporting
    // a gap in the analysis of a file that is not part of the system.
    let judged = reasons(&report, "sda.neurosymbolic").join("\n");
    assert!(
        !judged.contains("architecture.toml"),
        "the declaration is not code under analysis: {judged}"
    );
}

#[test]
fn a_scan_over_a_sound_declaration_reports_the_residual_premise() {
    let dir = scratch("guarded");
    let sound = BYPASSED.replace(
        "[[flow]]\nfrom = \"policy\"\nto = \"actuator\"",
        "[[flow]]\nfrom = \"policy\"\nto = \"guard::clamp\"\n\n[[flow]]\nfrom = \"guard::clamp\"\nto = \"actuator\"",
    );
    let decl = ArchitectureDeclaration::parse(&sound).expect("well-formed");
    let config = RunConfig::default().with_architecture(decl);
    let report = analyze(&sda_engine::default_registry(), &target(&dir), &config);

    assert!(
        !report.findings.iter().any(|f| f.rule.as_str() == "SDA-INTERPOSE-01"),
        "nothing is bypassed here"
    );
    let said = reasons(&report, "sda.interposition").join("\n");
    assert!(said.contains("proved guarded"), "{said}");
    // A proof over a declaration is only as good as the declaration, and a scan
    // that printed the proof without that premise would be claiming more than it
    // established.
    assert!(
        said.contains(sda_engine::interposition::FAITHFULNESS),
        "the residual assumption must reach NOT CHECKED: {said}"
    );
}

#[test]
fn a_project_that_ships_a_model_and_declares_nothing_is_told_so() {
    let dir = scratch("undeclared");
    let report = analyze(&sda_engine::default_registry(), &model_target(&dir), &RunConfig::default());
    let said = reasons(&report, "sda.interposition").join("\n");
    assert!(said.contains("no `.sda/architecture.toml`"), "{said}");
}

/// The counterpart, and the reason the notice above is conditional: a project
/// with no model has nothing to interpose, and a notice that appears on every
/// scan is one people learn to skip past.
#[test]
fn a_project_with_no_model_is_not_nagged_about_interposition() {
    let dir = scratch("no-model");
    let report = analyze(&sda_engine::default_registry(), &target(&dir), &RunConfig::default());
    assert!(reasons(&report, "sda.interposition").is_empty());
}
