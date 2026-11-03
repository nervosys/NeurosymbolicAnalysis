//! A file the lexer could not finish is a hole in the scan, not just a finding.
//!
//! `SDA-C-LEXICAL` reports that a block comment or literal is never closed, and
//! it was the only thing reported. That is not enough, because an unterminated
//! comment on line 1 swallows the rest of the file:
//!
//! | file | contents | findings |
//! |---|---|---|
//! | `plain.c` | a six-line function | 3 MISRA |
//! | `early.c` | `/*` then the same function | 0 MISRA |
//!
//! Identical code, three guideline violations gone. The finding said *"every
//! structural finding in this file is now suspect"*, which was the wrong word:
//! they were not suspect, they were absent. A reader who sees that message, looks
//! for the file's other findings and sees none concludes "suspect, but clean" —
//! having been told the exact opposite of what happened.
//!
//! And *NOT CHECKED* — the section whose entire job is to say which files a clean
//! result does not cover — did not mention the file at all. The provider already
//! had the machinery, used it for a file it could not *read*, and a file it could
//! read but not tokenise went through a different path with no notice.
//!
//! Both halves are asserted here: the gap reaches the report, and the finding
//! stops promising analysis that did not happen.
//!
//! **Rust had the same hole and was quieter about it.** No finding either — a
//! file behind an unclosed `/*` left the analysis with nothing at all to show it
//! had been skipped. The lexer had been computing
//! `RustLexed::unterminated_block_comments` the whole time and nothing outside
//! its own tests ever read it, so the fact needed to report the hole was already
//! in hand. That is the third shape this repository keeps finding: an answer
//! computed and never consulted.
//!
//! The Rust side gets the notice and no finding, deliberately. A finding needs a
//! rule id, and an id in this engine carries catalogue obligations — a fixture, a
//! near-miss, a place in `implemented()`. The notice is what closes the hole; the
//! finding would be symmetry for its own sake.

use sda_core::{Analyzer, RunOptions};
use sda_engine::cstatic::CStaticAnalyzer;
use sda_engine::discover::{self, DiscoveryOptions};

/// The same function, with and without an unterminated comment above it.
const FUNCTION: &str = "int f(int x) {\n  if (x == 1) { goto done; }\n  return 0;\ndone:\n  return 1;\n}\n";

/// A Rust file with something to find: an unsafe fn and an index expression.
const RUST_SOURCE: &str = "pub unsafe fn danger(p: *const u8) -> u8 { *p }\npub fn f() { let v: Vec<i32> = Vec::new(); let _ = v[0]; }\n";

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sda-unlexable-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// Run the C provider over a directory and return (findings, notices).
fn analyze(dir: &std::path::Path) -> (Vec<sda_core::Finding>, Vec<sda_core::Exclusion>) {
    let target = discover::discover(dir, &DiscoveryOptions::default());
    let provider = CStaticAnalyzer::c();
    let findings = provider.analyze(&target, &RunOptions::default()).expect("the C provider runs");
    let notices = provider.take_notices();
    (findings, notices)
}

/// An unclosed comment costs the file its analysis, and the report says so.
#[test]
fn a_file_that_could_not_be_tokenised_reaches_not_checked() {
    let dir = scratch("gap");
    std::fs::write(dir.join("early.c"), format!("/* opened and never closed\n{FUNCTION}"))
        .expect("the source");
    let (findings, notices) = analyze(&dir);

    let misra = findings.iter().filter(|f| f.rule.as_str().starts_with("MISRA")).count();
    assert_eq!(
        misra, 0,
        "the premise of this test is that the analysis is lost; if it is not, the notice \
         below is wrong and should be removed rather than kept as decoration"
    );

    let notice = notices
        .iter()
        .find(|n| n.reason.contains("early.c"))
        .unwrap_or_else(|| panic!("the file must reach NOT CHECKED: {notices:?}"));
    assert!(
        notice.reason.contains("could not be tokenised"),
        "and say what happened to it: {}",
        notice.reason
    );
    assert!(
        notice.reason.contains("not the same as there being nothing there"),
        "and what that costs the reader, which is the whole point of the section: {}",
        notice.reason
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The finding no longer calls absent findings suspect.
#[test]
fn the_lexical_finding_says_the_analysis_stopped_rather_than_that_it_is_doubtful() {
    let dir = scratch("wording");
    std::fs::write(dir.join("early.c"), format!("/* opened and never closed\n{FUNCTION}"))
        .expect("the source");
    let (findings, _) = analyze(&dir);

    let lexical = findings
        .iter()
        .find(|f| f.rule.as_str() == "SDA-C-LEXICAL")
        .expect("the lexical finding still fires");
    assert!(
        !lexical.message.contains("is now suspect"),
        "that was the old wording, and it called absent findings doubtful. The message may \
         still use the word — it now says `not merely suspect` — but it must not make the \
         claim: {}",
        lexical.message
    );
    assert!(
        lexical.message.contains("not checked at all"),
        "it has to say the analysis stopped: {}",
        lexical.message
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A file that lexes cleanly produces neither the finding nor the notice.
///
/// Without this the two above would pass on a provider that reported every file
/// as unlexable, which would be a worse defect than the one being fixed — it
/// would empty the scan and say so convincingly.
#[test]
fn a_file_that_lexes_cleanly_is_not_reported_as_a_gap() {
    let dir = scratch("clean");
    std::fs::write(dir.join("plain.c"), FUNCTION).expect("the source");
    let (findings, notices) = analyze(&dir);

    assert!(
        findings.iter().any(|f| f.rule.as_str().starts_with("MISRA")),
        "the same function does produce findings when nothing swallows it"
    );
    assert!(
        !findings.iter().any(|f| f.rule.as_str() == "SDA-C-LEXICAL"),
        "and it lexes"
    );
    assert!(notices.is_empty(), "so there is no gap to report: {notices:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

// --- Rust -------------------------------------------------------------------

/// The same hole in the Rust analyzer, which was quieter still.
///
/// C at least emitted `SDA-C-LEXICAL`. Here a file behind an unclosed `/*` left
/// the analysis with no finding and no notice: one measured Rust file holding an
/// `unsafe fn` and an index expression reports a finding, and the identical file
/// behind an unterminated comment reports nothing at all.
///
/// `RustLexed::unterminated_block_comments` had been computed since it was
/// written and read by nothing outside the lexer's own tests — the same
/// "computed an answer nobody consulted" shape as `DeviationRegister::expired`.
/// The fact needed to report the hole was already in hand.
#[test]
fn a_rust_file_that_could_not_be_tokenised_reaches_not_checked() {
    let dir = scratch("rust-gap");
    std::fs::create_dir_all(dir.join("src")).expect("a src directory");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("a manifest");
    std::fs::write(
        dir.join("src").join("early.rs"),
        format!("/* opened and never closed\n{RUST_SOURCE}"),
    )
    .expect("the source");

    let target = discover::discover(&dir, &DiscoveryOptions::default());
    let provider = sda_engine::rstatic::RustStaticAnalyzer::new();
    let findings = provider
        .analyze(&target, &sda_core::RunOptions::default())
        .expect("the Rust provider runs");
    let notices = provider.take_notices();

    assert!(
        !findings.iter().any(|f| f.location.file.to_string_lossy().contains("early.rs")),
        "the premise: the file's analysis is lost. If it is not, this notice is wrong"
    );
    let notice = notices
        .iter()
        .find(|n| n.reason.contains("early.rs"))
        .unwrap_or_else(|| panic!("the file must reach NOT CHECKED: {notices:?}"));
    assert!(
        notice.reason.contains("could not be tokenised"),
        "and say why: {}",
        notice.reason
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// And a Rust file that lexes is not reported as a gap.
#[test]
fn a_rust_file_that_lexes_cleanly_is_not_reported_as_a_gap() {
    let dir = scratch("rust-clean");
    std::fs::create_dir_all(dir.join("src")).expect("a src directory");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("a manifest");
    std::fs::write(dir.join("src").join("plain.rs"), RUST_SOURCE).expect("the source");

    let target = discover::discover(&dir, &DiscoveryOptions::default());
    let provider = sda_engine::rstatic::RustStaticAnalyzer::new();
    let findings = provider
        .analyze(&target, &sda_core::RunOptions::default())
        .expect("the Rust provider runs");
    let notices = provider.take_notices();

    assert!(
        findings.iter().any(|f| f.location.file.to_string_lossy().contains("plain.rs")),
        "the same source does produce a finding when nothing swallows it: {findings:?}"
    );
    assert!(
        !notices.iter().any(|n| n.reason.contains("could not be tokenised")),
        "and there is no gap to report: {notices:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
