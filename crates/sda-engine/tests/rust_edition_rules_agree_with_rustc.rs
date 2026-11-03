//! The edition and unsafe rules, against rustc's own lints.
//!
//! `rust_rules_agree_with_clippy.rs` gave the two `PANIC` guidelines a second
//! implementation. This does the same for four more, using lints the compiler
//! itself ships — which matters, because for an *edition* rule the compiler is
//! not merely a second opinion, it is the authority on what the edition did.
//!
//! | guideline | lint |
//! |---|---|
//! | **UNSAFE.1** every `unsafe` block carries a SAFETY comment | `clippy::undocumented_unsafe_blocks` |
//! | **UNSAFE.2** an `unsafe fn` documents its contract | `clippy::missing_safety_doc` |
//! | **UNSAFE.4** `static mut` | `static_mut_refs` |
//! | **ED2024.1** `gen` is a keyword | `keyword_idents_2024` |
//! | **ED2024.3** `unsafe extern` is required | `missing_unsafe_on_extern` |
//! | **ED2024.4** unsafe attributes in their unsafe form | `unsafe_attr_outside_unsafe` |
//!
//! # Why the corpus is edition 2021
//!
//! Most of these are *hard errors* at edition 2024. A crate containing them does
//! not compile, and a refusal to compile is not a diagnostic — there is nothing
//! to compare against. At 2021 they are lints, and the compiler will say where.
//!
//! # The one disagreement, which is about the rule rather than the code
//!
//! `UNSAFE.4` reads "static mut shall not be used"; `static_mut_refs` fires on a
//! *reference* to one. So this engine flags the declaration and rustc flags the
//! borrow, and on a `static mut` nobody ever references this engine reports it
//! and rustc says nothing at all. Ours is the broader rule and matches its own
//! title. What follows is that **rustc's silence about `static mut` is not
//! evidence of conformance with UNSAFE.4**, and the test says so rather than
//! quietly comparing the two line numbers and failing.

use sda_core::Severity;
use sda_engine::run::{RunConfig, analyze};
use sda_engine::{default_registry, discover};

const FIXTURE: &str = include_str!("fixtures/clippy-edition-lints.json");

#[derive(serde::Deserialize)]
struct Fixture {
    clippy: String,
    sites: Vec<Site>,
}

#[derive(serde::Deserialize)]
struct Site {
    line: u32,
    guideline: String,
    lint: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("the captured rustc and clippy answers")
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

/// Guidelines both sides decide. Anything outside this set is not being
/// compared, and saying so here keeps the comparison from silently widening.
const COMPARED: &[&str] =
    &["UNSAFE.1", "UNSAFE.2", "UNSAFE.4", "ED2024.1", "ED2024.3", "ED2024.4"];

fn ours() -> Vec<(String, u32)> {
    let dir = repo_root().join("tools/rust-edition-corpus/src");
    let target = discover::discover(&dir, &discover::DiscoveryOptions::default());
    assert!(!target.files.is_empty(), "discovery found nothing under {}", dir.display());

    let report = analyze(&default_registry(), &target, &RunConfig::default());
    let mut v: Vec<(String, u32)> = report
        .findings
        .iter()
        .filter(|f| f.severity != Severity::Info)
        .filter_map(|f| {
            f.rule.as_str().strip_prefix("RUST-2024-").map(|n| (n.to_string(), f.location.line))
        })
        .filter(|(n, _)| COMPARED.contains(&n.as_str()))
        .collect();
    v.sort();
    v.dedup();
    v
}

fn theirs() -> Vec<(String, u32)> {
    let mut v: Vec<(String, u32)> =
        fixture().sites.iter().map(|s| (s.guideline.clone(), s.line)).collect();
    v.sort();
    v.dedup();
    v
}

/// The fixture has to come from real tools and cover the rules it claims to.
#[test]
fn the_oracle_is_a_real_toolchain() {
    let f = fixture();
    assert!(f.clippy.contains("clippy"), "captured from: {}", f.clippy);

    let rules: std::collections::BTreeSet<&str> =
        f.sites.iter().map(|s| s.guideline.as_str()).collect();
    for wanted in COMPARED {
        assert!(rules.contains(wanted), "the corpus must exercise {wanted}: {rules:?}");
    }

    // Both a compiler lint and a clippy lint, or this is a comparison against
    // one tool wearing two names.
    let lints: std::collections::BTreeSet<&str> = f.sites.iter().map(|s| s.lint.as_str()).collect();
    assert!(lints.iter().any(|l| l.starts_with("clippy::")), "{lints:?}");
    assert!(lints.iter().any(|l| !l.starts_with("clippy::")), "{lints:?}");
}

/// Five of the six agree line for line.
#[test]
fn the_two_agree_wherever_they_are_asking_the_same_question() {
    let mine: Vec<_> = ours().into_iter().filter(|(n, _)| n != "UNSAFE.4").collect();
    let theirs: Vec<_> = theirs().into_iter().filter(|(n, _)| n != "UNSAFE.4").collect();
    assert_eq!(mine, theirs, "rustc and this engine place these differently");
}

/// And `UNSAFE.4` is a difference of rule, stated rather than smoothed over.
///
/// Both tools fire; they fire in different places because they prohibit
/// different things. This engine flags the declaration, which is what its title
/// says; `static_mut_refs` flags a borrow of one.
#[test]
fn unsafe_4_is_broader_than_the_lint_it_resembles() {
    let mine: Vec<u32> =
        ours().into_iter().filter(|(n, _)| n == "UNSAFE.4").map(|(_, l)| l).collect();
    let theirs: Vec<u32> =
        theirs().into_iter().filter(|(n, _)| n == "UNSAFE.4").map(|(_, l)| l).collect();

    assert_eq!(mine.len(), 1, "one `static mut` in the corpus: {mine:?}");
    assert_eq!(theirs.len(), 1, "and one borrow of it: {theirs:?}");
    assert!(
        mine[0] < theirs[0],
        "the declaration comes before the borrow; this engine reports the first and rustc the \
         second ({mine:?} against {theirs:?})"
    );
}
