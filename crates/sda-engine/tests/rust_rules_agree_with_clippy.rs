//! The Rust rules, against a second implementation.
//!
//! Everything this session did to the MISRA C rules — hold them to cppcheck,
//! then to clang — left the `RUST-2024` rules exactly where they were: seventeen
//! of them classified `native`, meaning a clean result is offered as evidence of
//! conformance, and not one ever compared with anything. The C sweep cost seven
//! defects. There was no reason to expect this half to be in better shape, only
//! a reason nobody had looked.
//!
//! Clippy is the obvious second opinion and ships with rustup, so there is
//! nothing to install. Two guidelines map onto its restriction lints exactly:
//!
//! | guideline | clippy |
//! |---|---|
//! | **PANIC.1** `unwrap` and `expect` | `unwrap_used`, `expect_used` |
//! | **PANIC.2** the diverging macros | `panic`, `unreachable`, `todo`, `unimplemented` |
//!
//! # The disagreement is the point
//!
//! Captured with `--all-targets`. Without it clippy does not compile
//! `#[cfg(test)]` code at all, so it would agree with this engine about test
//! modules *by not looking* rather than by deciding — agreement that means
//! nothing. With it, the two genuinely differ: clippy's restriction lints fire
//! everywhere, and this engine exempts test code, because a panic in a test is
//! the test working. Both readings are defensible and the test pins both.

use sda_core::Severity;
use sda_engine::run::{RunConfig, analyze};
use sda_engine::{default_registry, discover};

const FIXTURE: &str = include_str!("fixtures/clippy-lints.json");

#[derive(serde::Deserialize)]
struct Fixture {
    clippy: String,
    crate_dir: Option<String>,
    sites: Vec<Site>,
}

#[derive(serde::Deserialize)]
struct Site {
    line: u32,
    guideline: String,
    lint: String,
}

fn fixture() -> Fixture {
    let mut f: Fixture = serde_json::from_str(FIXTURE).expect("the captured clippy answers");
    if f.crate_dir.is_none() {
        f.crate_dir = Some("tools/rust-panic-corpus".into());
    }
    f
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

fn corpus_source() -> String {
    let path = repo_root().join("tools/rust-panic-corpus/src/lib.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `(guideline, line)` for every panic finding this engine reports.
///
/// Scope is deliberately not applied: `tools` is declared out of the delivered
/// product, so a `sda scan` of it reports nothing at all. The comparison is
/// about what the *rules* decide, which is a layer below that.
fn ours() -> Vec<(String, u32)> {
    let dir = repo_root().join("tools/rust-panic-corpus/src");
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
        .filter(|(n, _)| n.starts_with("PANIC."))
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

/// Lines inside a `#[cfg(test)]` module or a `#[test]` function.
fn test_lines() -> Vec<(u32, u32)> {
    sda_syntax::analyze_rust(&corpus_source()).test_line_ranges
}

/// The fixture has to be clippy's, and has to cover both rules.
#[test]
fn the_oracle_is_a_real_clippy() {
    let f = fixture();
    assert!(f.clippy.contains("clippy"), "captured from: {}", f.clippy);

    let rules: std::collections::BTreeSet<&str> =
        f.sites.iter().map(|s| s.guideline.as_str()).collect();
    assert!(rules.contains("PANIC.1"), "the corpus must exercise `unwrap`/`expect`");
    assert!(rules.contains("PANIC.2"), "and the diverging macros");

    let lints: std::collections::BTreeSet<&str> = f.sites.iter().map(|s| s.lint.as_str()).collect();
    assert!(lints.len() >= 5, "several distinct lints, not one repeated: {lints:?}");
}

/// Everything this engine reports, clippy reports too.
///
/// This is the direction that matters for a rule offered as evidence of
/// conformance: a finding nobody else agrees with is a finding to justify.
#[test]
fn every_panic_this_engine_reports_is_one_clippy_reports() {
    let theirs = theirs();
    let source = corpus_source();
    for site in ours() {
        if theirs.contains(&site) {
            continue;
        }
        // The one shipped-code difference, and it is a gap in clippy's lint set
        // rather than in either tool's judgement: `RUST-2024-PANIC.2` covers the
        // assert family, and clippy has no restriction lint for `assert!`,
        // `assert_eq!` or `assert_ne!`. Chasing this down is also what exposed
        // the rule's title naming four macros while the check flagged seven.
        let line = source.lines().nth(site.1 as usize - 1).unwrap_or_default();
        assert!(
            site.0 == "PANIC.2" && line.trim_start().starts_with("assert"),
            "this engine reports {site:?} and clippy does not. Clippy's restriction lints fire \
             on every `unwrap` in compiled code, so a site it misses is one this engine invented"
        );
    }
}

/// And everything clippy reports that this engine does not is test code.
///
/// The one real difference between the two, asserted rather than smoothed over.
/// Clippy's restriction lints fire everywhere; `RUST-2024-PANIC` exempts test
/// code, because a panic in a test is the test working — which is what
/// `PanicSite::in_test` is for, and where three defects were found earlier in
/// this same session.
#[test]
fn what_clippy_reports_and_this_engine_does_not_is_test_code() {
    let mine = ours();
    let ranges = test_lines();
    assert!(!ranges.is_empty(), "the corpus must contain a test module, or this proves nothing");

    let mut excused = 0;
    for site in theirs() {
        if mine.contains(&site) {
            continue;
        }
        assert!(
            ranges.iter().any(|(a, b)| site.1 >= *a && site.1 <= *b),
            "clippy reports {site:?} outside any test module and this engine does not — one of \
             the two is wrong about shipped code"
        );
        excused += 1;
    }
    assert!(
        excused >= 1,
        "the corpus should contain a panic in test code, or the exemption is untested"
    );
}
