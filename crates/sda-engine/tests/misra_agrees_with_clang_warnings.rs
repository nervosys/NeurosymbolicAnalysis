//! The guidelines cppcheck's addon does not implement, checked against clang.
//!
//! `misra_agrees_with_cppcheck.rs` holds this engine to a second implementation
//! for the guidelines both tools implement. Fifteen `native` guidelines were
//! outside that — cppcheck's addon does not run them, so nothing independent had
//! ever disagreed with what this engine decides about them. `sda rules audit`
//! offers a clean result on a `native` guideline as evidence of conformance, and
//! for those fifteen that offer rested on a fixture proving the check fires and
//! on nothing else.
//!
//! Two of the fifteen are things a *compiler* diagnoses, and clang is already an
//! oracle here for the lexer and for `CFunction::returns`:
//!
//! | guideline | clang |
//! |---|---|
//! | **2.6** a label nothing jumps to | `-Wunused-label` |
//! | **3.2** line-splicing in a `//` comment | `-Wcomment`, "multi-line // comment" |
//! | **11.10** `_Atomic` on the incomplete type `void` | an *error*: the language forbids it |
//!
//! For the first two that is not a coincidence of wording: both guidelines exist
//! because the construct misleads a reader about what the program does, which is
//! why a compiler warns, and both are decidable from the token stream.
//! Disagreeing means one of the two is wrong about the *code*, not about the
//! guideline.
//!
//! 11.10 is a stronger case and a different one: `_Atomic(void)` is a constraint
//! violation, so clang rejects the translation unit rather than warning. Checking
//! it here is still worth something, because this toolkit's premise is that it
//! runs on code that does not build — and code that does not build is exactly
//! where a compiler has no opinion to offer.
//!
//! 3.1 comes along for free. `-Wcomment` reports `'/*' within block comment` as
//! well, which is 3.1 rather than 3.2 — keying the oracle on the flag instead of
//! the message would have asserted a 3.2 wherever clang found the other one.
//!
//! The remaining thirteen stay unmet. Compilers do not diagnose them and
//! cppcheck's addon does not implement them; see
//! `tools/misra-evidence-tiers.py`.

use sda_core::Severity;
use sda_engine::run::{RunConfig, analyze};
use sda_engine::{default_registry, discover};

const FIXTURE: &str = include_str!("fixtures/clang-warnings.json");

#[derive(serde::Deserialize)]
struct Fixture {
    clang: String,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    path: String,
    warnings: Vec<Warning>,
}

#[derive(serde::Deserialize)]
struct Warning {
    line: u32,
    guideline: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("the captured clang warnings")
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

/// What this engine reports for `path`, as `(guideline, line)`.
///
/// Discovery walks a directory, so the file's parent is scanned and the findings
/// narrowed afterwards — handing it a file yields an empty target and a
/// comparison that passes against nothing.
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
        // Both catalogues, because the same clang message names a different
        // guideline in each: `'/*' within block comment` is MISRA C 3.1 and
        // MISRA C++ 5.7.1. The compiler has no opinion about which catalogue is
        // being applied; the corpus file's language decides.
        .filter_map(|f| {
            let r = f.rule.as_str();
            r.strip_prefix("MISRA-C-2023-")
                .or_else(|| r.strip_prefix("MISRA-CPP-2023-"))
                .map(|n| (n.to_string(), f.location.line))
        })
        .filter(|(n, _)| {
            matches!(n.as_str(), "2.6" | "3.1" | "3.2" | "11.10" | "5.7.1" | "5.7.2")
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

fn theirs(c: &Case) -> Vec<(String, u32)> {
    let mut v: Vec<(String, u32)> =
        c.warnings.iter().map(|w| (w.guideline.clone(), w.line)).collect();
    v.sort();
    v.dedup();
    v
}

/// The fixture has to be clang's, and has to say something.
#[test]
fn the_oracle_is_a_real_clang() {
    let f = fixture();
    assert!(f.clang.contains("clang"), "captured from: {}", f.clang);
    assert!(f.cases.len() >= 2, "more than one file, or the corpus proves little");

    let numbers: std::collections::BTreeSet<&str> =
        f.cases.iter().flat_map(|c| c.warnings.iter()).map(|w| w.guideline.as_str()).collect();
    assert!(numbers.contains("2.6"), "the unused label is the point of this file");
    assert!(numbers.contains("3.2"), "and so is the spliced line comment");
    assert!(
        numbers.contains("5.7.2"),
        "and the same construct in C++, which the catalogue numbers differently"
    );
}

/// The same two constructs, in two languages, numbered by two catalogues.
///
/// `-Wcomment` says exactly the same thing about `lexical.c` and `comments.cpp`.
/// What differs is which guideline that sentence violates — 3.1/3.2 in MISRA C,
/// 5.7.1/5.7.2 in MISRA C++ — so an oracle keyed on the message alone would
/// assert a C number against a C++ file. The file's language decides.
#[test]
fn the_same_warning_names_a_different_guideline_in_each_catalogue() {
    let f = fixture();
    let numbers = |suffix: &str| -> std::collections::BTreeSet<String> {
        f.cases
            .iter()
            .filter(|c| c.path.ends_with(suffix))
            .flat_map(|c| c.warnings.iter())
            .map(|w| w.guideline.clone())
            .collect()
    };
    let c = numbers(".c");
    let cpp = numbers(".cpp");

    assert!(c.contains("3.1") && c.contains("3.2"), "C numbering: {c:?}");
    assert!(cpp.contains("5.7.1") && cpp.contains("5.7.2"), "C++ numbering: {cpp:?}");
    assert!(
        cpp.is_disjoint(&c),
        "a C number appearing against a C++ file means the oracle ignored the language: {cpp:?}"
    );
}

/// Line for line, on the guidelines clang and this engine both decide.
///
/// These are *lexical and structural* guidelines, so unlike the cppcheck
/// comparison there is no reason for the two to anchor them differently: a
/// spliced comment is at the comment, an unused label is at the label. Comparing
/// lines is therefore fair here where it was not there.
#[test]
fn the_two_agree_line_for_line() {
    for c in fixture().cases {
        assert_eq!(
            ours(&c.path),
            theirs(&c),
            "case `{}`: clang and this engine disagree about where these are",
            c.path
        );
    }
}

/// And the corpus must actually contain the constructs, or the agreement above
/// is agreement about an empty set.
#[test]
fn the_corpus_contains_what_is_being_compared() {
    let f = fixture();
    let found: usize = f.cases.iter().map(|c| c.warnings.len()).sum();
    assert!(found >= 3, "only {found} warning(s) to compare");

    let mine: usize = f.cases.iter().map(|c| ours(&c.path).len()).sum();
    assert_eq!(found, mine, "the two sides must be comparing the same number of things");
}
