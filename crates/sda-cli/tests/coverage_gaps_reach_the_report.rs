//! A flagged line that no run reached is shown to the reader.
//!
//! `correlate::coverage_gaps` groups unreached findings by file, and its own
//! documentation has said since it was written that a coverage hole "belongs on
//! a different work queue". It was called by nothing. The grouping existed, was
//! unit-tested, and no report ever put it in front of anyone — the same shape as
//! `DeviationRegister::expired`, found by the same sweep.
//!
//! It was also wrong. It paired `correlations[i]` with `findings[i]`, and the
//! two stop being parallel at the first suppressed finding, so gaps were
//! attributed to the wrong line. `sda-engine` covers that directly. What this
//! covers is the half a unit test cannot: that the section reaches the output a
//! person actually reads. A display nothing asserts is one refactor away from
//! being the uncalled function again.

use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

/// `sda scan` over the coverage example, with the gcov tracefile committed
/// beside it. Four findings are unreached across three distinct lines, one of
/// which carries two guidelines.
fn scan_with_coverage() -> String {
    let root = repo_root();
    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .current_dir(&root)
        .args(["scan", "examples/coverage"])
        .args(["--coverage", "examples/coverage/build/main.c.gcov"])
        .output()
        .expect("the sda binary runs");

    assert!(
        out.status.success() || out.status.code() == Some(0),
        "scan exited {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn the_report_names_the_lines_no_run_reached() {
    let text = scan_with_coverage();

    assert!(
        text.contains("Coverage gaps"),
        "a run with execution counts and unreached findings must show them: {text}"
    );
    assert!(
        text.contains("main.c: 13, 21, 28"),
        "the gap lines are named, and deduplicated: {text}"
    );
}

/// The gap count and the `unreached` count differ, and the report says why.
///
/// Four findings are unreached and three lines are listed, because `21.3` and
/// `D4.12` both fire on line 21. A reader comparing the two numbers would
/// otherwise have to guess which one is wrong.
#[test]
fn the_gap_count_counts_lines_and_says_so() {
    let text = scan_with_coverage();

    let gaps = text
        .lines()
        .find(|l| l.starts_with("Coverage gaps"))
        .expect("the coverage-gaps heading");
    assert!(
        gaps.contains("distinct line(s)"),
        "the heading has to say it counts lines, not findings: {gaps}"
    );
    assert!(
        text.contains("unreached: 4"),
        "and the correlation section still counts findings: {text}"
    );
    assert!(gaps.contains("3 distinct line(s)"), "three lines over four findings: {gaps}");
}

/// A static-only run claims no coverage gaps.
///
/// Nothing measured execution, so "this line never ran" is not a fact anyone
/// established. Printing an empty gap list would be harmless; printing a
/// populated one would be the error this whole engine exists to avoid.
#[test]
fn a_run_that_measured_nothing_reports_no_gaps() {
    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .current_dir(repo_root())
        .args(["scan", "examples/coverage"])
        .output()
        .expect("the sda binary runs");
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(
        !text.contains("Coverage gaps"),
        "without measurement there is no coverage claim to make: {text}"
    );
    assert!(
        text.contains("static-only result"),
        "and the run says that is what it was: {text}"
    );
}
