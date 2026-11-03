//! `sda plan` promises what the run will do, so it has to plan over the files
//! the run will read.
//!
//! The declared analysis scope removes files before any provider is built, so a
//! file under an `[[excluded]]` rule is never analyzed. The CLI `plan` command
//! ran its own discovery and skipped that step. On a project excluding
//! `legacy/`, whose only C++ lived there, it printed:
//!
//! ```text
//! Languages: c, cpp
//! Steps:
//!   1. sda.static.c
//!   2. sda.static.cpp
//! ```
//!
//! and the scan ran one step. A plan is a promise about a run; this one
//! promised a step over a language that was not in the scanned set.
//!
//! What makes it worth a file of its own is where the correct behaviour already
//! lived. `plan.create`, the MCP copy of this same command, has applied scope
//! since it was written, with the reason in a comment beside the call: *a plan
//! over files the scan will not read would propose work on nothing*. Two
//! implementations of one command, and the argument for the right one was
//! written down in the copy that had it. Neither the comment nor the behaviour
//! reached the other.
//!
//! The MCP copy had the second half of the defect instead: it applied the scope
//! and discarded the notices, so its plan was silently narrower than the tree it
//! named. Both now say what was removed, with the rule's reason and approver.

use std::path::PathBuf;
use std::process::Command;

/// A project whose only C++ is in the excluded directory, so the scope changes
/// the answer rather than merely the file count.
fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sda-plan-scope-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch project");
    std::fs::create_dir_all(dir.join("legacy")).expect("the excluded directory");
    std::fs::create_dir_all(dir.join(".sda")).expect("the config directory");

    std::fs::write(dir.join("src").join("a.c"), "int f(void) { return 0; }\n")
        .expect("an in-scope C file");
    std::fs::write(
        dir.join("legacy").join("b.cpp"),
        "class W { public: int g(); };\nint W::g() { return 0; }\n",
    )
    .expect("the only C++, out of scope");
    std::fs::write(
        dir.join(".sda").join("scope.toml"),
        "[[excluded]]\npath = \"legacy/\"\nreason = \"third-party, not ours to fix\"\n\
         approver = \"a.erickson\"\n",
    )
    .expect("the scope declaration");
    dir
}

fn run(sub: &str, dir: &std::path::Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .args([sub, &dir.to_string_lossy()])
        .output()
        .expect("the sda binary runs");
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn a_plan_does_not_promise_a_step_the_scan_will_not_run() {
    let dir = project("steps");
    let text = run("plan", &dir);

    assert!(
        text.contains("Languages: c\n"),
        "the only C++ is out of scope, so it is not a language of this run: {text}"
    );
    assert!(
        !text.contains("sda.static.cpp"),
        "a plan that lists a step the scan will never run is not a plan: {text}"
    );
    assert!(text.contains("sda.static.c"), "and the C step is still there: {text}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Narrowed is not the same as narrowed silently.
///
/// A plan shorter than the tree it names, with nothing saying why, is one a
/// reader compares against their own directory listing and mistrusts.
#[test]
fn a_plan_narrowed_by_scope_says_so_and_names_the_rule() {
    let dir = project("stated");
    let text = run("plan", &dir);

    assert!(
        text.contains("files outside the declared analysis scope"),
        "the removal has to appear under what this plan does not cover: {text}"
    );
    assert!(
        text.contains("third-party, not ours to fix") && text.contains("a.erickson"),
        "with the reason and approver the rule records, which is why they are recorded: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// And the plan agrees with the scan it describes, which is the whole point.
///
/// Checked against the other command rather than against a literal, so that a
/// future change to either one has to move both together.
#[test]
fn the_plan_and_the_scan_agree_about_which_files_are_in() {
    let dir = project("agree");
    let plan = run("plan", &dir);
    let scan = run("scan", &dir);

    let scan_mentions_legacy = scan
        .lines()
        .any(|l| (l.starts_with("legacy/") || l.starts_with("legacy\\")) && l.contains(':'));
    assert!(!scan_mentions_legacy, "the premise: the scan reports nothing there: {scan}");

    assert!(
        !plan.contains("sda.static.cpp"),
        "so the plan must not offer to check it either: {plan}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A project with no scope declaration is untouched: no gap, no narrowing.
///
/// Without this the fix could be "always add a scope gap", which would put a
/// permanent entry under *Not covered* — and a caveat that appears on every run
/// is one people learn to skip past.
#[test]
fn a_project_without_a_scope_declaration_gains_no_such_gap() {
    let dir = std::env::temp_dir().join("sda-plan-scope-none");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch project");
    std::fs::write(dir.join("src").join("a.c"), "int f(void) { return 0; }\n")
        .expect("a source file");

    let text = run("plan", &dir);
    assert!(
        !text.contains("outside the declared analysis scope"),
        "nothing was declared, so nothing was excluded: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
