//! The MISRA C++ rules, against clang-tidy.
//!
//! Twenty-one C++ guidelines are classified `native` in this catalogue — a clean
//! result on one is offered as evidence of conformance — and not one had ever
//! been compared with anything. The MISRA C sweep cost seven defects and the
//! Rust sweep cost one. There was no reason to expect this catalogue to be in
//! better shape, only a reason nobody had looked.
//!
//! clang-tidy's `cppcoreguidelines` module decides five of them, and the mapping
//! is close to exact because both are restating the same C++ Core Guidelines:
//!
//! | guideline | check |
//! |---|---|
//! | **8.2.1** no C-style cast | `google-readability-casting` |
//! | **8.2.2** no `reinterpret_cast` | `cppcoreguidelines-pro-type-reinterpret-cast` |
//! | **8.2.3** no `const_cast` | `cppcoreguidelines-pro-type-const-cast` |
//! | **9.6.1** no `goto` | `cppcoreguidelines-avoid-goto` |
//! | **21.6.1** no dynamic allocation | `cppcoreguidelines-no-malloc` |
//!
//! It found one on the first run: **8.2.1 did not fire on `return (int)v;`**.
//! `is_c_style_cast` refused any parenthesis preceded by `return`, before the
//! contents were ever examined for a type — so the one place a cast most often
//! appears in C++ was the one place the rule could not see. 79 real casts in
//! PX4, every one of the form `return (Type *)NULL;`.

use sda_core::Severity;
use sda_engine::run::{RunConfig, analyze};
use sda_engine::{default_registry, discover};

const FIXTURE: &str = include_str!("fixtures/clang-tidy-cpp.json");

#[derive(serde::Deserialize)]
struct Fixture {
    clang_tidy: String,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    path: String,
    findings: Vec<TidyFinding>,
}

#[derive(serde::Deserialize)]
struct TidyFinding {
    line: u32,
    guideline: String,
    check: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("the captured clang-tidy answers")
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

/// Guidelines both sides decide. Naming them keeps the comparison from silently
/// widening when a new rule starts firing on this corpus.
const COMPARED: &[&str] = &[
    "8.2.1", "8.2.2", "8.2.3", "9.6.1", "21.6.1", "19.0.1", "19.6.1", "12.2.1", "9.4.1", "9.4.2",
    "9.4.3", "21.10.1",
];

/// Guidelines the two tools decide alike but *anchor* differently, or where one
/// reports strictly more sites than the other.
///
/// Both entries are differences this session already found and wrote up for the
/// **C** catalogue, appearing again in the C++ one — which is the outcome to
/// hope for, because it says the two catalogues were implemented with the same
/// presentational choices rather than drifting apart.
///
/// * **9.4.2** — the fall-through. This engine reports the statement that should
///   have been followed by a `break`; clang reports the label fallen *into*.
///   Exactly the disagreement recorded for MISRA C 16.3 against cppcheck, where
///   the conclusion was that neither the guideline nor the standard fixes where
///   a finding belongs.
/// * **21.10.1** — `<csetjmp>`. This engine flags the `#include` as well as the
///   `longjmp` call; clang-tidy flags only the call. The same broader reading
///   recorded for MISRA C 21.6 and `#include <stdio.h>`.
const ANCHORED_DIFFERENTLY: &[&str] = &["9.4.2", "21.10.1"];

/// Compared for *presence* rather than position.
///
/// `cppcoreguidelines-pro-type-union-access` objects to reading a union member;
/// MISRA C++ 12.2.1 objects to the union existing. Both fire on the same file and
/// in different places, because they prohibit different things — the same shape
/// as Rust's `UNSAFE.4` against `static_mut_refs`, where a lint objects to the
/// use and a guideline to the thing. That recurrence is worth naming: a lint
/// almost always fires at the use, and a MISRA rule almost always at the
/// declaration, so a line-for-line comparison of the two is the wrong test.
const DECLARATION_VERSUS_USE: &[&str] = &["12.2.1"];

fn ours(path: &str) -> Vec<(String, u32)> {
    let file = repo_root().join(path);
    let dir = file.parent().expect("the corpus paths have a parent");
    let target = discover::discover(dir, &discover::DiscoveryOptions::default());
    assert!(!target.files.is_empty(), "discovery found nothing under {}", dir.display());

    let name = file.file_name().expect("a file name");
    let report = analyze(&default_registry(), &target, &RunConfig::default());
    let mut v: Vec<(String, u32)> = report
        .findings
        .iter()
        .filter(|f| f.location.file.file_name() == Some(name))
        .filter(|f| f.severity != Severity::Info)
        .filter_map(|f| {
            f.rule.as_str().strip_prefix("MISRA-CPP-2023-").map(|n| (n.to_string(), f.location.line))
        })
        .filter(|(n, _)| COMPARED.contains(&n.as_str()))
        .collect();
    v.sort();
    v.dedup();
    v
}

fn theirs(c: &Case) -> Vec<(String, u32)> {
    let mut v: Vec<(String, u32)> =
        c.findings.iter().map(|f| (f.guideline.clone(), f.line)).collect();
    v.sort();
    v.dedup();
    v
}

/// The fixture has to be clang-tidy's and cover every guideline it claims to.
#[test]
fn the_oracle_is_a_real_clang_tidy() {
    let f = fixture();
    assert!(f.clang_tidy.contains("LLVM"), "captured from: {}", f.clang_tidy);

    let rules: std::collections::BTreeSet<&str> =
        f.cases.iter().flat_map(|c| c.findings.iter()).map(|x| x.guideline.as_str()).collect();
    for wanted in COMPARED {
        assert!(rules.contains(wanted), "the corpus must exercise {wanted}: {rules:?}");
    }

    let checks: std::collections::BTreeSet<&str> =
        f.cases.iter().flat_map(|c| c.findings.iter()).map(|x| x.check.as_str()).collect();
    assert!(checks.len() >= 5, "several distinct checks, not one repeated: {checks:?}");
}

/// Line for line, for the guidelines where both tools prohibit the same thing.
#[test]
fn the_two_agree_line_for_line() {
    let skip = |(n, _): &(String, u32)| {
        !DECLARATION_VERSUS_USE.contains(&n.as_str())
            && !ANCHORED_DIFFERENTLY.contains(&n.as_str())
    };
    for c in fixture().cases {
        let mine: Vec<_> = ours(&c.path).into_iter().filter(skip).collect();
        let theirs: Vec<_> = theirs(&c).into_iter().filter(skip).collect();
        assert_eq!(mine, theirs, "case `{}`: clang-tidy and this engine disagree", c.path);
    }
}

/// And for the one that differs, both still fire — in different places, for
/// stated reasons.
///
/// Dropping 12.2.1 from the comparison and saying nothing else would let the
/// rule rot: it would be excluded whether it worked or not. This asserts the
/// shape of the difference instead.
#[test]
fn a_union_is_reported_at_its_declaration_and_at_its_use() {
    let f = fixture();
    let case = f
        .cases
        .iter()
        .find(|c| c.path.ends_with("macros_and_unions.hpp"))
        .expect("the header holding the union");

    let mine: Vec<u32> =
        ours(&case.path).into_iter().filter(|(n, _)| n == "12.2.1").map(|(_, l)| l).collect();
    let theirs: Vec<u32> =
        theirs(case).into_iter().filter(|(n, _)| n == "12.2.1").map(|(_, l)| l).collect();

    assert_eq!(mine.len(), 1, "one union declared: {mine:?}");
    assert_eq!(theirs.len(), 1, "and one member read: {theirs:?}");
    assert!(
        mine[0] < theirs[0],
        "the declaration comes before the access; this engine reports the first and clang-tidy \
         the second ({mine:?} against {theirs:?})"
    );
}

/// The two anchored differences still have both tools firing, in the order the
/// difference predicts.
///
/// Excluding them from the line comparison and saying nothing else would let
/// them rot: excluded whether they work or not.
#[test]
fn the_anchored_differences_are_the_ones_already_recorded_for_c() {
    let f = fixture();
    let case = f
        .cases
        .iter()
        .find(|c| c.path.ends_with("control_flow.cpp"))
        .expect("the control-flow corpus");
    let mine = ours(&case.path);
    let theirs = theirs(case);

    // 9.4.2: the statement that should have carried a `break` comes before the
    // label that is fallen into.
    let mine_942: Vec<u32> = mine.iter().filter(|(n, _)| n == "9.4.2").map(|(_, l)| *l).collect();
    let their_942: Vec<u32> =
        theirs.iter().filter(|(n, _)| n == "9.4.2").map(|(_, l)| *l).collect();
    assert_eq!((mine_942.len(), their_942.len()), (1, 1), "{mine_942:?} {their_942:?}");
    assert!(mine_942[0] < their_942[0], "{mine_942:?} should precede {their_942:?}");

    // 21.10.1: this engine reports the include as well as the call.
    let mine_21: Vec<u32> = mine.iter().filter(|(n, _)| n == "21.10.1").map(|(_, l)| *l).collect();
    let their_21: Vec<u32> =
        theirs.iter().filter(|(n, _)| n == "21.10.1").map(|(_, l)| *l).collect();
    assert_eq!(their_21.len(), 1, "clang-tidy flags the call only: {their_21:?}");
    assert_eq!(mine_21.len(), 2, "this engine flags the include too: {mine_21:?}");
    assert!(mine_21.contains(&their_21[0]), "and agrees about the call: {mine_21:?}");
}

/// A C-style cast in a `return` is still a C-style cast.
///
/// The regression this comparison found. `is_c_style_cast` refused any
/// parenthesis preceded by `return` — a guard that predates the type check below
/// it and duplicates what that check already does, since `return (x);` has no
/// type inside the parentheses and is rejected on its own merits.
#[test]
fn a_cast_in_a_return_statement_is_found() {
    let sites = ours("tools/misra-cpp-corpus/casts_and_calls.cpp");
    assert!(
        sites.iter().any(|(n, l)| n == "8.2.1" && *l == 12),
        "`return (int)v;` on line 12 is a C-style cast: {sites:?}"
    );
}
