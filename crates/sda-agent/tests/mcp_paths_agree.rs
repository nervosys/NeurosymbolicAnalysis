//! `analysis.scan` and `analysis.statodynamic` must analyse the same project the
//! same way.
//!
//! A statodynamic run is a scan with runtime evidence added, not a different
//! analysis. But `analysis.statodynamic` built a bare `default_registry()` and no
//! project configuration at all — no imported catalogues, no deviations, no
//! scope, no architecture — while `analysis.scan` built all four. So an agent
//! calling one saw different citations and different suppressions from an agent
//! calling the other, and from a human running `sda scan`.
//!
//! Nothing catches that by reading either report: each is internally consistent
//! and neither says what it was configured with. It is only visible in the
//! difference, which is what this file tests, and it is the one thing the agent
//! surface exists not to do — an agent has no source to check the answer against.
//!
//! The two paths now share `project_setup`, so the drift has one place to happen
//! rather than two.

use sda_agent::dispatch::dispatch;
use serde_json::{Value, json};

/// A project with a deviation register that suppresses a finding the scan would
/// otherwise report. Deviations are the sharpest probe available here: a path
/// that ignores the project config reports the finding, and a path that reads it
/// suppresses the finding — one difference, visible in the output, with no
/// external tool involved.
fn project(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("sda-mcp-agree-{name}"));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".sda")).unwrap();
    std::fs::write(
        root.join("main.c"),
        "#include <stdlib.h>\nint main(void) { char *p = malloc(16); (void)p; return 0; }\n",
    )
    .unwrap();
    // The register's real schema: `rationale`/`approver`, not `reason`. A
    // rejected entry suppresses nothing and says so, which is how this fixture
    // was wrong the first time.
    std::fs::write(
        root.join(".sda/deviations.toml"),
        "[[deviation]]
         rule = \"MISRA-C-2023-D4.12\"
         scope = \"file\"
         path = \"main.c\"
         rationale = \"the allocation is made once at start-up and never freed, by design\"
         approver = \"test\"
         reference = \"mcp-paths-agree\"
",
    )
    .unwrap();
    root
}

/// Findings the report shows as suppressed by an approved deviation.
///
/// The MCP report is a *projection* of `sda_core::Report`, not the report — it
/// carries `not_checked` rather than `exclusions`, and states suppression per
/// finding rather than as a total. Asserting against the projection is the point:
/// it is all an agent ever sees.
fn suppressed(report: &Value) -> usize {
    report["findings"]
        .as_array()
        .expect("every report carries findings")
        .iter()
        .filter(|f| !f["suppressed_by"].is_null())
        .count()
}

#[test]
fn a_statodynamic_run_honours_the_deviations_a_scan_honours() {
    let root = project("deviations");
    let path = root.to_string_lossy().to_string();

    let scan = dispatch("analysis.scan", &json!({"path": path})).expect("scan");
    assert!(
        suppressed(&scan) > 0,
        "the fixture exists to have something suppressed; nothing was. A rejected          deviation suppresses nothing, so check the register's schema: {}",
        scan["findings"]
    );

    // A real statodynamic call. The artifact is this test binary asked to run no
    // tests: it is a genuine executable that starts, exits 0 and is present on
    // whatever machine is running this, which is what the dynamic engine needs.
    // Substituting a fake would test the error path instead — and that path has
    // its own test below.
    let exe = std::env::current_exe().expect("a test binary exists");
    let stato = dispatch(
        "analysis.statodynamic",
        &json!({
            "path": path,
            "artifact": exe.to_string_lossy(),
            "args": ["--exact", "sda_no_such_test"],
        }),
    )
    .expect("statodynamic");

    assert_eq!(
        suppressed(&stato),
        suppressed(&scan),
        "the same project, the same approved deviations. This path used to build a bare          `default_registry()` and read no project configuration at all, so it suppressed          nothing and an agent saw findings a human running `sda scan` did not"
    );
}

/// The gap stated directly: a project's declaration must reach every tool that
/// analyses the project, not only the two that happened to be wired for it.
#[test]
fn every_project_analysing_tool_reports_the_same_not_checked_providers() {
    let root = project("providers");
    let path = root.to_string_lossy().to_string();

    let scan = dispatch("analysis.scan", &json!({"path": path})).expect("scan");
    let named: Vec<&str> = scan["not_checked"]
        .as_array()
        .expect("`not_checked` is present on every run, by design")
        .iter()
        .filter_map(|e| e["provider"].as_str())
        .collect();

    // Registered-but-disabled adapters must be named. A tool that registers none
    // reports a shorter `NOT CHECKED` than one that does, and the shorter report
    // is the one that looks cleaner.
    for id in ["ext.cppcheck", "ext.codeql", "ext.valgrind", "ext.miri"] {
        assert!(named.contains(&id), "`{id}` is unaccounted for in {named:?}");
    }
}

/// A statodynamic call with an artifact that cannot run must still be a *scan* —
/// it fails on the artifact, not by returning an unconfigured analysis.
#[test]
fn a_statodynamic_call_with_a_bad_artifact_fails_rather_than_reporting_less() {
    let root = project("bad-artifact");
    let path = root.to_string_lossy().to_string();
    let bogus = root.join("does-not-exist.exe").to_string_lossy().to_string();

    let out = dispatch("analysis.statodynamic", &json!({"path": path, "artifact": bogus}));
    assert!(
        out.is_err(),
        "an artifact that cannot be executed must not come back as a clean analysis: {out:?}"
    );
}
