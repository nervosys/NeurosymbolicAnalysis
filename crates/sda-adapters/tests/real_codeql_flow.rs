//! `codeFlows`, against output from a real CodeQL taint run.
//!
//! `sda_engine::interposition` refutes an interposition proof from a dataflow
//! *path*, because an endpoint cannot say what it crossed on the way. Two
//! earlier attempts to feed it one failed, and both failures are the reason this
//! file exists rather than a hand-written SARIF:
//!
//! * `parse_sarif` never read `codeFlows` at all, so every taint finding arrived
//!   as an endpoint and was skipped.
//! * The fixture that stood for CodeQL here contains **zero** `codeFlows`, and
//!   real Semgrep OSS 1.176.0 emits none either. Nothing in the repository could
//!   have exercised the field.
//!
//! So this was captured from CodeQL 2.26.4 running its own
//! `Security/CWE-078/CommandInjection.ql` over `tools/codeql-taint/`, a program
//! split across four components with one guarded path and one bypass. CodeQL
//! reports the bypass and not the guarded path, which is the behaviour the whole
//! design depends on.
//!
//! Two things the run taught that no reading would have:
//!
//! * **`sys.argv` is not a source for this query.** A first version of the
//!   program used it and produced zero results — CodeQL's Python command
//!   injection query wants a `RemoteFlowSource`, so the program had to acquire a
//!   real remote entry point before the tool would say anything at all.
//! * **The layout has to be importable.** A version with the model under
//!   `models/policy/` also produced zero results: CodeQL resolves imports to
//!   track flow between files, and `from policy.serve import command` does not
//!   resolve when `policy` is not on the path from the source root. The flow
//!   only appeared once the packages were where Python would find them.
//! * **Step messages are internal node descriptions**, not prose:
//!   `ControlFlowNode for raw`. They are kept verbatim; a mechanical label from
//!   the tool is worth more than a sentence invented here.

use sda_adapters::parse_sarif;
use sda_core::Evidence;

const CODEQL: &str = include_str!("fixtures/ext.codeql-taint.sarif");

fn trace_frames(text: &str) -> Vec<sda_core::TraceFrame> {
    let findings = parse_sarif(text, "ext.codeql").expect("real codeql sarif");
    assert_eq!(findings.len(), 1, "one result: the bypass, not the guarded path");
    findings[0]
        .evidence
        .iter()
        .find_map(|e| match e {
            Evidence::Trace { frames } => Some(frames.clone()),
            _ => None,
        })
        .expect("a taint result carries its path")
}

#[test]
fn a_real_code_flow_becomes_an_ordered_trace() {
    let frames = trace_frames(CODEQL);
    assert_eq!(frames.len(), 12, "twelve steps, as CodeQL wrote them");

    // Source first, sink last — the order `interposition` walks.
    assert_eq!(frames[0].location.file.to_string_lossy(), "policy/serve.py");
    assert!(frames[0].note.contains("ImportMember"));
    let last = frames.last().unwrap();
    assert_eq!(last.location.file.to_string_lossy(), "actuator/drive.py");
    assert_eq!(last.location.line, 7, "the `os.system` argument");
    assert!(last.note.contains("BinaryExpr"));

    // Steps are numbered ascending from the source, which is what `TraceFrame`
    // documents and what the bypass check relies on to pick its endpoints.
    for (i, f) in frames.iter().enumerate() {
        assert_eq!(f.step, i as u32);
    }

    // The flow is interprocedural and crosses four files. That is what makes it
    // usable as a refutation: a path confined to one file cannot cross a
    // component boundary, and cannot say whether a guard was passed.
    let files: Vec<String> =
        frames.iter().map(|f| f.location.file.to_string_lossy().into_owned()).collect();
    assert!(files.iter().any(|f| f == "policy/serve.py"));
    assert!(files.iter().any(|f| f == "app.py"));
    assert!(files.iter().any(|f| f == "telemetry/relay.py"));
    assert!(files.iter().any(|f| f == "actuator/drive.py"));
    assert!(
        !files.iter().any(|f| f.starts_with("guard/")),
        "the guarded route exists in the program and CodeQL correctly did not report it — this          path is the bypass"
    );
}

#[test]
fn the_finding_still_carries_everything_it_did_before() {
    let findings = parse_sarif(CODEQL, "ext.codeql").unwrap();
    let f = &findings[0];
    assert_eq!(f.rule.as_str(), "py/command-line-injection");
    assert_eq!(f.location.file.to_string_lossy(), "actuator/drive.py");
    assert_eq!(f.location.line, 7);
    assert!(
        f.taxonomy.iter().any(|t| t.id == "CWE-78"),
        "the CWE still arrives from the rule tags: {:?}",
        f.taxonomy
    );
}

/// A result with no `codeFlows` gets no trace — not an empty one.
///
/// The distinction is what lets `interposition` tell "this tool reported a path
/// that crosses no guard" from "this tool cannot describe paths".
#[test]
fn a_result_without_a_flow_gets_no_trace_rather_than_an_empty_one() {
    let stripped: serde_json::Value = {
        let mut v: serde_json::Value = serde_json::from_str(CODEQL).unwrap();
        v["runs"][0]["results"][0].as_object_mut().unwrap().remove("codeFlows");
        v
    };
    let findings = parse_sarif(&stripped.to_string(), "ext.codeql").unwrap();
    assert_eq!(findings.len(), 1);
    assert!(!findings[0].evidence.iter().any(|e| matches!(e, Evidence::Trace { .. })));
}

/// A one-step flow is an endpoint wearing a path's clothes.
#[test]
fn a_single_step_flow_is_not_treated_as_a_path() {
    let truncated: serde_json::Value = {
        let mut v: serde_json::Value = serde_json::from_str(CODEQL).unwrap();
        let locations = v["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
            .as_array()
            .unwrap()
            .clone();
        v["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"] =
            serde_json::Value::Array(vec![locations[0].clone()]);
        v
    };
    let findings = parse_sarif(&truncated.to_string(), "ext.codeql").unwrap();
    assert!(
        !findings[0].evidence.iter().any(|e| matches!(e, Evidence::Trace { .. })),
        "one frame cannot say what it crossed, and must not be offered as if it could"
    );
}

/// The CWE form CodeQL actually writes, and the one it does not.
///
/// Correlation matches a runtime witness to a static finding through the CWE, so
/// a form that is not recognised is not a cosmetic gap — it is a finding that
/// can never be confirmed. Real CodeQL writes `external/cwe/cwe-078`; the
/// recogniser only knew `CWE-78:` until this run.
#[test]
fn both_cwe_tag_conventions_are_recognised_and_agree() {
    let findings = parse_sarif(CODEQL, "ext.codeql").unwrap();
    assert!(findings[0].taxonomy.iter().any(|t| t.id == "CWE-78"));

    let semgrep_style: serde_json::Value = {
        let mut v: serde_json::Value = serde_json::from_str(CODEQL).unwrap();
        v["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"] =
            serde_json::json!(["security", "CWE-78: Improper Neutralization"]);
        v
    };
    let other = parse_sarif(&semgrep_style.to_string(), "ext.codeql").unwrap();
    assert_eq!(
        other[0].taxonomy.iter().find(|t| t.id.starts_with("CWE")).map(|t| t.id.as_str()),
        Some("CWE-78"),
        "the zero-padded and unpadded forms must name the same weakness"
    );
}

/// A tag that merely mentions a CWE in prose is still not a taxonomy claim.
#[test]
fn a_cwe_mentioned_in_prose_is_not_promoted_to_a_claim() {
    let prose: serde_json::Value = {
        let mut v: serde_json::Value = serde_json::from_str(CODEQL).unwrap();
        v["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"] =
            serde_json::json!(["see also CWE-78 for background", "docs/cwe/notes"]);
        v
    };
    let findings = parse_sarif(&prose.to_string(), "ext.codeql").unwrap();
    assert!(!findings[0].taxonomy.iter().any(|t| t.id.starts_with("CWE")));
}
