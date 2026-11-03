//! `analysis.verify` end to end, on the real CodeQL taint report.
//!
//! The agent surface is where a caller can least afford a result that reads
//! cleaner than it is: an agent has no source to check the answer against, only
//! the JSON and the description. So this drives the real dispatch path against
//! the same fixture `sda-engine` and `sda-adapters` use, and asserts the three
//! things an agent must be able to tell apart —
//!
//! * what was **proved**, over a declaration rather than over the code,
//! * what a tool **observed** in the code, which can only refute,
//! * and what **nobody checked**, which is present on every run.

use sda_agent::dispatch::dispatch;
use serde_json::json;

const CODEQL: &str = include_str!("../../sda-adapters/tests/fixtures/ext.codeql-taint.sarif");

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

/// A project directory with a declaration, and optionally a taint report.
fn project(name: &str, declaration: Option<&str>) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("sda-verify-mcp-{name}"));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".sda")).unwrap();
    if let Some(d) = declaration {
        std::fs::write(root.join(".sda/architecture.toml"), d).unwrap();
    }
    std::fs::write(root.join("codeql.sarif"), CODEQL).unwrap();
    root
}

#[test]
fn a_declaration_alone_reports_a_proof_and_the_premise_under_it() {
    let root = project("proved", Some(DECLARED));
    let out = dispatch("analysis.verify", &json!({ "path": root.to_string_lossy() })).unwrap();

    assert_eq!(out["declared"], true);
    assert_eq!(out["interposed"], true);
    assert_eq!(out["obligations"], 1);
    assert_eq!(out["bypasses"].as_array().unwrap().len(), 0);

    let not_checked = out["not_checked"].as_array().unwrap();
    assert!(
        not_checked.iter().any(|l| l.as_str().unwrap().contains("flow::declaration-faithful")),
        "an agent reading `interposed: true` must find the premise in the same object: {not_checked:?}"
    );
    assert!(
        not_checked.iter().any(|l| l.as_str().unwrap().contains("sda.intractable[policy]")),
        "and that nothing can be proved about the 7B model at all"
    );
}

#[test]
fn the_real_taint_report_refutes_it_and_the_json_says_which_path() {
    let root = project("refuted", Some(DECLARED));
    let out = dispatch(
        "analysis.verify",
        &json!({
            "path": root.to_string_lossy(),
            "taint": root.join("codeql.sarif").to_string_lossy(),
        }),
    )
    .unwrap();

    assert_eq!(out["interposed"], false);
    assert_eq!(out["taint_findings"], 1);
    assert_eq!(
        out["taint_findings_with_flow"], 1,
        "a finding without a flow could not have refuted anything, so the count is reported"
    );

    let bypasses = out["bypasses"].as_array().unwrap();
    assert_eq!(bypasses.len(), 1);
    assert_eq!(bypasses[0]["model"], "policy");
    assert_eq!(bypasses[0]["effector"], "actuator");
    assert_eq!(bypasses[0]["observed"], true, "this came from the code, not the declaration");
    assert_eq!(bypasses[0]["path"], json!(["policy", "telemetry", "actuator"]));
}

/// The case an agent is most likely to misread.
#[test]
fn an_undeclared_project_is_null_rather_than_true() {
    let root = project("undeclared", None);
    let out = dispatch("analysis.verify", &json!({ "path": root.to_string_lossy() })).unwrap();

    assert_eq!(out["declared"], false);
    assert!(
        out["interposed"].is_null(),
        "`false` would read as a refutation and `true` as a proof; neither happened"
    );
    assert!(out["summary"].as_str().unwrap().contains("not a clean result"));
    assert!(!out["not_checked"].as_array().unwrap().is_empty());
}

#[test]
fn a_rejected_declaration_entry_reaches_the_caller_rather_than_shrinking_the_proof() {
    // A neural guard: refused, because a guard that is itself a model moves the
    // premise rather than discharging it. Silently dropping it would leave a
    // proof walking a graph with one fewer component than the file describes.
    let text = format!(
        "{DECLARED}\n[[component]]\nname = \"llm-judge\"\npath = \"judge\"\nboundary = \
         \"neural\"\nrole = \"guard\"\n"
    );
    let root = project("rejected", Some(&text));
    let out = dispatch("analysis.verify", &json!({ "path": root.to_string_lossy() })).unwrap();

    let problems = out["problems"].as_array().unwrap();
    assert!(
        problems.iter().any(|p| p.as_str().unwrap().contains("llm-judge")),
        "the rejection must be visible to the caller: {problems:?}"
    );
}
