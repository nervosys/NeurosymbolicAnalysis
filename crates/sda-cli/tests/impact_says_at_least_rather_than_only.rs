//! `sda impact` answers a floor, and the fixture contains the file it misses.
//!
//! Blast radius is the question repowise calls "change it safely", and the
//! reason this one refuses that phrasing is in the fixture below. Four files:
//!
//! | file | reaches `lib.c`? | found? |
//! |---|---|---|
//! | `app.c` | yes, by name | yes |
//! | `indirect.c` | **yes, through a function pointer** | **no** |
//! | `doc.c` | no — names it in a comment | no, correctly |
//! | `lib.c` | is the subject | — |
//!
//! `indirect.c` is the point. It calls whatever `get()` returns, which is a real
//! path into the subject and spells nothing. A tool that listed `app.c` and
//! stopped would be telling a reviewer the change is contained in one file when
//! it is not.
//!
//! So the output states a floor before it states anything else, and the wording
//! is asserted here rather than left to survive an edit: *at least these*, never
//! *only these*. The caveat comes from `Impact::floor_caveat` in the engine, so a
//! second caller — the MCP surface, when it grows this — cannot render the list
//! without it and leave an agent believing the set is closed.
//!
//! The direction of the error is what makes this worth a test. Over-reporting
//! costs a reviewer an afternoon; under-reporting costs them the belief that they
//! looked.

use std::path::PathBuf;
use std::process::Command;

/// A distinct directory per test.
///
/// cargo runs the tests in a binary concurrently, and the first draft shared one
/// name between two that each create and delete it — the same race already fixed
/// once in the hotspots tests, repeated here within the hour.
fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sda-impact-cli-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch project");

    std::fs::write(
        dir.join("src").join("lib.c"),
        "int compute(int x) { return x + 1; }\nstatic int helper(void) { return 0; }\n",
    )
    .expect("the subject");
    std::fs::write(
        dir.join("src").join("app.c"),
        "int compute(int x);\nint main(void) { return compute(2); }\n",
    )
    .expect("a caller by name");
    // Reaches `compute` at runtime and never spells it.
    std::fs::write(
        dir.join("src").join("indirect.c"),
        "typedef int (*fn)(int);\nfn get(void);\nint go(void) { fn f = get(); return f(1); }\n",
    )
    .expect("a caller through a pointer");
    std::fs::write(
        dir.join("src").join("doc.c"),
        "/* compute is discussed here and not called */\nint other(void) { return 0; }\n",
    )
    .expect("a mention in prose");

    dir
}

fn impact(dir: &std::path::Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .args(["impact", &dir.to_string_lossy(), "--file", "src/lib.c"])
        .output()
        .expect("the sda binary runs");
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// With nothing else to read, there is no answer to give.
///
/// The notice said no file was searched, and the next line said `No other file
/// names any of them`, which is the claim the notice exists to withhold.
#[test]
fn a_search_of_nothing_makes_no_claim_about_other_files() {
    let dir = fixture("alone");
    for other in ["app.c", "indirect.c", "doc.c"] {
        std::fs::remove_file(dir.join("src").join(other)).expect("the fixture file");
    }
    let text = impact(&dir);
    assert!(text.contains("no file was searched"), "{text}");
    assert!(!text.contains("No other file names"), "{text}");
}

/// The list is right, and the file it misses is in the fixture.
#[test]
fn a_caller_through_a_function_pointer_is_missing_and_the_caveat_is_why() {
    let dir = fixture("floor");
    let text = impact(&dir);

    assert!(text.contains("src/app.c"), "the caller that names it is found: {text}");
    assert!(
        !text.contains("src/doc.c"),
        "a name in a comment is not a call, and a file a reviewer has to rule out by hand \
         teaches them to distrust the list: {text}"
    );
    assert!(
        !text.contains("src/indirect.c"),
        "this is the premise of the test rather than a wish: the indirect caller is not found, \
         which is exactly why the output may not claim to be complete: {text}"
    );

    // `helper` is `static`, so it is not a symbol another file could reach.
    assert!(text.contains("defines: compute"), "{text}");
    assert!(!text.contains("helper"), "a `static` name is not offered to anyone: {text}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// And the floor is stated before the list, not after it.
#[test]
fn the_floor_is_stated_before_the_list_it_qualifies() {
    let dir = fixture("order");
    let text = impact(&dir);

    let caveat = text
        .find("never as `only these`")
        .unwrap_or_else(|| panic!("the direction of the error has to be named: {text}"));
    let listing = text
        .find("src/app.c")
        .unwrap_or_else(|| panic!("there has to be a list to qualify: {text}"));

    assert!(
        caveat < listing,
        "a caveat under the list reaches a reader who has already drawn the conclusion:\n{text}"
    );
    assert!(
        text.contains("function pointer"),
        "and it names a way the list is short, so it reads as a fact rather than a \
         disclaimer: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `impact` and `hotspots` read the same scope declaration and disagree about
/// it on purpose, so the disagreement is pinned rather than left to drift.
///
/// A ranking of where to look first must not rank files the project excluded
/// from analysis — `hotspots` did, and put one on top. A blast radius must not
/// hide them: a vendored directory calling into this file is exactly the caller
/// somebody needs before changing it, and omitting it would push the floor
/// *below* the truth, which is the one direction this answer must never move.
///
/// Both behaviours are correct and they look like an inconsistency, which is
/// why the output says so. Without the notice, an operator who ran both
/// commands would see a filename here that `sda scan` never mentions and have
/// no way to reconcile them.
#[test]
fn a_caller_outside_the_declared_scope_is_still_named_and_the_crossing_is_stated() {
    let dir = std::env::temp_dir().join("sda-impact-scope");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch project");
    std::fs::create_dir_all(dir.join("legacy")).expect("the excluded directory");
    std::fs::create_dir_all(dir.join(".sda")).expect("the config directory");

    std::fs::write(dir.join("src").join("lib.c"), "int shared(int x) { return x; }\n")
        .expect("the subject");
    std::fs::write(
        dir.join("legacy").join("caller.c"),
        "int shared(int);\nint use(void) { return shared(1); }\n",
    )
    .expect("a caller the project excluded from analysis");
    std::fs::write(
        dir.join(".sda").join("scope.toml"),
        "[[excluded]]\npath = \"legacy/\"\nreason = \"vendored, not maintained here\"\n\
         approver = \"a.erickson\"\n",
    )
    .expect("the scope declaration");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sda"))
        .args(["impact", &dir.to_string_lossy(), "--file", "src/lib.c"])
        .output()
        .expect("the sda binary runs");
    let text = String::from_utf8_lossy(&out.stdout).to_string();

    assert!(
        text.contains("legacy/caller.c") || text.contains("legacy\\caller.c"),
        "hiding an out-of-scope caller would put the floor below the truth: {text}"
    );
    assert!(
        text.contains("declares an analysis scope, and this search ignored it"),
        "and crossing the declaration has to be stated, or it reads as a bug: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
