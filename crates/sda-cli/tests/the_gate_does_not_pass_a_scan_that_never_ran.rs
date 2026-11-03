//! `--fail-on` is the output a CI pipeline actually consumes, and it passed a
//! scan that read nothing.
//!
//! The README records this trap about somebody else's tool:
//!
//! > The standalone `verus` binary exits 0 on a failed proof. One error, an
//! > abort message, `$? == 0`. ... a CI gate on its exit code would have passed
//! > it.
//!
//! This gate had the same property for a different input. `sda scan ./srcc
//! --fail-on low` — a mistyped path — printed `gate: no findings at or above
//! low` and exited **0**. Zero findings from nothing read, rendered as a
//! sentence about code, in the one output nobody reads with their eyes.
//!
//! The gate already knew how to qualify itself: it appends *(static-only run)*
//! when no correlation happened. It just never asked the prior question, which
//! is whether anything was scanned at all.
//!
//! So there are three outcomes now, because two cannot express it. `Pass` is
//! measured and clean, `Fail` is measured and not, and `NotChecked` is neither
//! — and `NotChecked` stops the pipeline, because a gate that could not run has
//! not been passed. The exit codes follow: `1` means this code has findings and
//! `3` means the scan never happened, which is fixed in the pipeline rather
//! than in the code. `2` is left alone; the argument parser already uses it.
//!
//! The narrowness matters as much as the fix. A project that really is clean
//! must still exit 0, or the gate is useless in exactly the case it exists for.

use std::path::PathBuf;
use std::process::Command;

fn scan_exit(path: &std::path::Path, threshold: &str) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .args(["scan", &path.to_string_lossy(), "--fail-on", threshold])
        .output()
        .expect("the sda binary runs");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).to_string())
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sda-gate-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("a scratch directory");
    d
}

/// A path that is not there does not pass.
#[test]
fn a_mistyped_path_does_not_produce_a_green_build() {
    let missing = std::env::temp_dir().join("sda-gate-no-such-path-at-all");
    let _ = std::fs::remove_dir_all(&missing);
    assert!(!missing.exists(), "the premise");

    let (code, err) = scan_exit(&missing, "low");

    assert_ne!(code, 0, "a scan that read nothing must not pass a gate: {err}");
    assert_eq!(code, 3, "and it is a different failure from finding problems: {err}");
    assert!(
        err.contains("nothing was scanned"),
        "the pipeline log has to say which of the two happened: {err}"
    );
    assert!(
        !err.contains("no findings at or above"),
        "that sentence is a statement about code, and no code was read: {err}"
    );
}

/// A tree of the wrong languages is the same answer: the commoner case, and the
/// one that reads most like a real scan because discovery reports files.
#[test]
fn a_tree_this_toolkit_cannot_read_does_not_produce_a_green_build() {
    let d = dir("wrong-languages");
    std::fs::write(d.join("README.txt"), "not source\n").expect("a file");
    std::fs::write(d.join("data.json"), "{}\n").expect("another");

    let (code, err) = scan_exit(&d, "low");
    assert_eq!(code, 3, "two files were found and none could be read: {err}");

    let _ = std::fs::remove_dir_all(&d);
}

/// A project with findings fails the way it always did.
#[test]
fn findings_at_or_above_the_threshold_still_exit_one() {
    let d = dir("findings");
    std::fs::write(
        d.join("a.c"),
        "int f(int x) {\n  if (x == 1) { goto done; }\n  return 0;\ndone:\n  return 1;\n}\n",
    )
    .expect("a source file with findings");

    let (code, err) = scan_exit(&d, "low");
    assert_eq!(code, 1, "this is the ordinary failing gate: {err}");
    assert!(err.contains("finding(s) at or above"), "{err}");

    let _ = std::fs::remove_dir_all(&d);
}

/// And a project that was read and is clean still passes.
///
/// Without this the fix could be "never pass", which would be safe, useless,
/// and indistinguishable from working until somebody tried to use it.
#[test]
fn a_project_that_was_read_and_is_clean_still_passes() {
    let d = dir("clean");
    // Real C, read by the engine, with nothing at or above `critical` in it.
    std::fs::write(d.join("a.c"), "int32_t f(int32_t x) { return x; }\n")
        .expect("a source file");

    let (code, err) = scan_exit(&d, "critical");
    assert_eq!(code, 0, "a scan that ran and found nothing severe must pass: {err}");
    assert!(
        err.contains("no findings at or above"),
        "and it is allowed to say so, because here it was measured: {err}"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// The README's exit-code table is checked against the binary, not trusted.
///
/// An exit code is a contract, and the table documenting it is the only place a
/// pipeline author will look. This repository has a standing result about
/// documentation: every claim it does not check drifts, and the ones that read
/// most confidently drift longest. A table of three numbers is exactly that
/// shape.
///
/// So each row is measured here. The scenarios are the ones above; this asserts
/// the document agrees with them.
#[test]
fn the_readme_documents_the_exit_codes_the_binary_actually_uses() {
    let readme = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("the workspace root")
            .join("README.md"),
    )
    .expect("README.md is readable");

    let section = readme
        .split_once("### Exit codes")
        .map(|(_, rest)| rest)
        .expect("the README documents the exit codes");
    let section = section.split("\n## ").next().unwrap_or(section);

    for code in ["`0`", "`1`", "`3`"] {
        assert!(
            section.contains(code),
            "the table has to name every code the binary can return; missing {code}"
        );
    }
    assert!(
        section.contains("nothing was scanned"),
        "and say what the third one means, since it is the one nobody expects"
    );

    // Measured, so the table cannot drift from the binary.
    let clean = dir("readme-clean");
    std::fs::write(clean.join("a.c"), "int32_t f(int32_t x) { return x; }\n").expect("a file");
    assert_eq!(scan_exit(&clean, "critical").0, 0, "row `0`");

    let dirty = dir("readme-dirty");
    std::fs::write(
        dirty.join("a.c"),
        "int f(int x) {\n  if (x == 1) { goto done; }\n  return 0;\ndone:\n  return 1;\n}\n",
    )
    .expect("a file");
    assert_eq!(scan_exit(&dirty, "low").0, 1, "row `1`");

    let nothing = dir("readme-nothing");
    std::fs::write(nothing.join("README.txt"), "not source\n").expect("a file");
    assert_eq!(scan_exit(&nothing, "low").0, 3, "row `3`");

    for d in [clean, dirty, nothing] {
        let _ = std::fs::remove_dir_all(&d);
    }
}
