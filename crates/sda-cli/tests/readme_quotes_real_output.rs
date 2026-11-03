//! The README quotes what the tool prints, and quotes rot.
//!
//! `README.md` shows `sda rules audit`'s summary in a fenced block, as the
//! evidence for its central claim — that a clean result means conformance for a
//! *stated* subset of the catalogue. That sentence is generated from the
//! catalogue, so every reclassification changes it.
//!
//! It changed three times in one session — 74 provable guidelines, then 72, then
//! 70 — and each time the README was corrected by hand, because nothing would
//! have noticed if it had not been. A number in the first document a reader
//! trusts is the worst place to keep an unchecked copy of something.
//!
//! This compares the quoted block against what `Catalog::audit().caveat()`
//! actually produces. It does not spawn the binary: the sentence is the
//! library's, and shelling out would test the terminal instead.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

/// Collapse the line wrapping the README applies, so a quote broken across three
/// lines compares equal to the one-line sentence the tool prints.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn the_quoted_audit_is_what_the_audit_says() {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");

    let anchor = "`sda rules audit` will tell you plainly:";
    let at = readme.find(anchor).expect("the sentence introducing the quoted audit");
    let after = &readme[at + anchor.len()..];

    let open = after.find("```").expect("a fenced block after it");
    let rest = &after[open + 3..];
    let close = rest.find("```").expect("the block must close");
    let quoted = flatten(&rest[..close]);

    let audit = sda_rules::Catalog::load(sda_rules::Standard::MisraC2023).audit();
    let actual = flatten(&audit.caveat());

    assert!(
        actual.starts_with(&quoted) || quoted == actual,
        "README quotes:\n  {quoted}\nbut `sda rules audit` says:\n  {actual}\n\
         Reclassifying a guideline changes this sentence; the quote has to move with it"
    );
}

/// And the quote must be substantial enough to be worth checking.
#[test]
fn the_quote_carries_the_numbers_it_is_cited_for() {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    let audit = sda_rules::Catalog::load(sda_rules::Standard::MisraC2023).audit();

    for n in [audit.total, audit.checked_by_default, audit.conformance_provable] {
        assert!(
            readme.contains(&n.to_string()),
            "the README should carry {n}, which is one of the figures it cites the audit for"
        );
    }
}
