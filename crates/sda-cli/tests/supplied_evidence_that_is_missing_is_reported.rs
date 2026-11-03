//! What the report says when evidence you named is not there.
//!
//! Three flags hand `sda` a file it did not find for itself: `--coverage`,
//! `--observation` and `--compile-commands`. Each can be pointed at something
//! that does not exist, and what happens then is the product's central promise
//! in miniature — an inability to check must not be presented as a clean check.
//!
//! None of the three was asserted anywhere. That was found by asking which
//! *NOT CHECKED* providers any test names, counting only occurrences inside a
//! `tests/` file or after a `#[cfg(test)]` marker, because "mentioned in a file
//! that has tests" is proximity rather than coverage.
//!
//! The three behave differently on purpose, and the difference is the point:
//!
//! * A **compile database** decides what *can* be analysed — eighty-seven MISRA
//!   guidelines need the type information it carries. Proceeding without the one
//!   the user named would quietly narrow the run, so this refuses: exit 1, and a
//!   message saying how to generate one.
//! * **Coverage** and a **probe stream** are additional evidence. Without them
//!   the run is static-only, which is a real result, so it proceeds and says in
//!   *NOT CHECKED* exactly what is missing and what that costs.
//!
//! All three were measured before being written down.

use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

fn scan(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .current_dir(repo_root())
        .args(["scan", "examples/firmware"])
        .args(args)
        .output()
        .expect("the sda binary runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text)
}

/// A coverage file that is not there costs the run its refutations, and says so.
#[test]
fn an_unreadable_coverage_report_is_named_in_not_checked() {
    let (code, text) = scan(&["--coverage", "no-such-file.info"]);
    assert_eq!(code, 0, "a missing coverage file is a narrower run, not a failed one");
    assert!(
        text.contains("sda.coverage:") && text.contains("could not be read"),
        "the report must say the counts are missing: {text}"
    );
    assert!(
        text.contains("refuted or shown unreached"),
        "and what that costs — a finding it would have refuted is now reported without \
         that evidence: {text}"
    );
}

/// Pointing `--coverage` at a build directory makes the number of reports the
/// tree's and not the user's, so unreadable ones are counted rather than listed.
#[test]
fn many_unreadable_coverage_reports_are_one_paragraph() {
    let paths = ["a.info", "b.info", "c.info", "d.info", "e.info"];
    let args: Vec<&str> = paths.iter().flat_map(|p| ["--coverage", *p]).collect();
    let (code, text) = scan(&args);
    assert_eq!(code, 0, "missing coverage is a narrower run, not a failed one");
    assert_eq!(
        text.matches("sda.coverage:").count(),
        1,
        "five unreadable reports are one notice: {text}"
    );
    assert!(
        text.contains("5 coverage report(s)") && text.contains("`a.info`"),
        "the notice carries the count and the first of them: {text}"
    );
    assert!(text.contains("refuted or shown unreached"), "and what that costs: {text}");
}

/// So does a probe stream that is not there.
#[test]
fn an_unreadable_observation_is_named_in_not_checked() {
    let (code, text) = scan(&["--observation", "no-such-file.txt"]);
    assert_eq!(code, 0, "a missing probe stream is a narrower run, not a failed one");
    assert!(
        text.contains("sda.observation:") && text.contains("could not be read"),
        "the report must say nothing it witnessed reached this run: {text}"
    );
}

/// A compile database that is not there stops the run instead.
///
/// The asymmetry is deliberate. Coverage and observations are evidence a run can
/// do without; a compile database decides which guidelines are reachable at all,
/// so continuing without the one that was named would narrow the analysis behind
/// the user's back.
#[test]
fn a_missing_compile_database_refuses_rather_than_narrowing_the_run() {
    let (code, text) = scan(&["--compile-commands", "no-such-file.json"]);
    assert_eq!(code, 1, "this one refuses: {text}");
    assert!(
        text.contains("does not exist"),
        "and says what is wrong: {text}"
    );
    assert!(
        text.contains("sda build compile-commands"),
        "and how to fix it, which is the difference between a refusal and a complaint: {text}"
    );
}
