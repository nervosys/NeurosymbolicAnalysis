//! Zero findings from zero files is the most reassuring wrong report there is.
//!
//! `discover::inventory` prints "no analyzable files found" and the CLI writes it
//! to stderr — where `sda scan --format json > report.json` throws it away. What
//! reached the file was a report with no findings, no `languages`, and nine
//! `ext.*` notices about providers that were not enabled: indistinguishable from
//! a clean scan of a real codebase, and considerably more reassuring than one.
//!
//! The ways to arrive there are ordinary rather than exotic — a mistyped path, a
//! build directory, a scan rooted one level too deep, a tree whose languages this
//! toolkit does not read. Each produces a clean result that describes the scan
//! and not the code.
//!
//! The condition is *no enabled provider reads anything here*, and the first
//! version of it was `target.files.is_empty()`, which is wrong and was caught by
//! this file. Discovery counts `.md` and `.txt` among plenty else, so a
//! documentation directory is not empty: it reports `1 md, 1 txt` on stderr,
//! which tells the operator two files were analysed, and then produces a report
//! with nothing in it. That case is commoner than the empty directory and reads
//! worse, because the stderr line is reassuring.
//!
//! It is the same defect as the configuration problems that were stderr-only
//! until earlier in this session, and it wants the same fix: the artifact has to
//! carry it, because the artifact is what gets attached to a review and read six
//! months later.
//!
//! Found by pointing every subcommand at an empty directory — the same method
//! that found `sda impact` answering for a language it cannot read. A suite
//! measures what somebody thought to ask, and nobody had asked this.

use sda_engine::run::{RunConfig, analyze};
use sda_engine::{default_registry, discover};

fn scan(dir: &std::path::Path) -> sda_core::Report {
    let target = discover::discover(dir, &discover::DiscoveryOptions::default());
    analyze(&default_registry(), &target, &RunConfig::default())
}

/// A tree with nothing to read says so, in the report.
#[test]
fn a_tree_with_no_analyzable_files_is_named_in_not_checked() {
    let dir = std::env::temp_dir().join("sda-empty-scan-none");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    // Not empty — just nothing this reads. A directory of PNGs is the ordinary
    // version of this mistake.
    std::fs::write(dir.join("notes.txt"), "not source\n").expect("a file");

    let report = scan(&dir);
    assert!(report.findings.is_empty(), "the premise: nothing was found");

    let notice = report
        .exclusions
        .iter()
        .find(|e| e.provider.as_str() == "sda.discovery")
        .unwrap_or_else(|| panic!("a scan of nothing must say so: {:?}", report.exclusions));
    assert!(
        notice.reason.contains("count of nothing"),
        "and say what the zero means: {}",
        notice.reason
    );
    assert!(
        notice.reason.contains("describes the scan, not the code"),
        "which is the whole difference between this and a clean result: {}",
        notice.reason
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty directory is the same answer, worded for what happened.
///
/// Both branches say nothing was checked; they differ in whether there was
/// anything to check. A reader chasing a mistyped path needs the second half.
#[test]
fn an_empty_directory_says_no_file_was_found_at_all() {
    let dir = std::env::temp_dir().join("sda-empty-scan-bare");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");

    let report = scan(&dir);
    let notice = report
        .exclusions
        .iter()
        .find(|e| e.provider.as_str() == "sda.discovery")
        .expect("an empty tree is still a scan of nothing");
    assert!(
        notice.reason.contains("no file was found"),
        "the wording distinguishes an empty tree from one this cannot read: {}",
        notice.reason
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A path that is not there is not an empty directory.
///
/// This is the case the header of this file names twice — "a mistyped path" —
/// and the case the test above says a reader needs the wording for, and it was
/// the one case here nothing asserted. It got the empty-directory sentence: `no
/// file was found under X`, which describes looking inside a place. A wrong
/// argument and a correct-but-empty target want opposite actions, and the
/// advice attached to the empty case — check which languages this toolkit reads
/// — is not merely unhelpful for a typo, it sends the reader somewhere else.
///
/// Worth sitting with: a test file can name a case in its own prose, twice, as
/// the motivating example, and still not check it. Prose is not a check.
#[test]
fn a_path_that_does_not_exist_says_that_rather_than_that_it_is_empty() {
    let missing = std::env::temp_dir().join("sda-empty-scan-no-such-directory");
    let _ = std::fs::remove_dir_all(&missing);
    assert!(!missing.exists(), "the premise: this path is not there");

    let report = scan(&missing);
    let notice = report
        .exclusions
        .iter()
        .find(|e| e.provider.as_str() == "sda.discovery")
        .expect("a scan of a path that is not there is still a scan of nothing");

    assert!(
        notice.reason.contains("does not exist"),
        "the reader has to learn the path was wrong: {}",
        notice.reason
    );
    assert!(
        !notice.reason.contains("no file was found under"),
        "that sentence is about an empty directory, which this is not: {}",
        notice.reason
    );
    assert!(
        !notice.reason.contains("reads the languages in it"),
        "language advice sends a reader chasing a typo in the wrong direction: {}",
        notice.reason
    );
    // The part every branch shares still has to be there.
    assert!(notice.reason.contains("count of nothing"), "{}", notice.reason);
}

/// And a scan that did read something does not carry it.
///
/// Without this the notice could be unconditional, which would put a permanent
/// entry in the section whose value is that everything in it is true of *this*
/// run — and a caveat that appears every time is one people learn to skip.
#[test]
fn a_scan_that_read_files_carries_no_such_notice() {
    let dir = std::env::temp_dir().join("sda-empty-scan-some");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    std::fs::write(dir.join("a.c"), "int f(int x) { return x + 1; }\n").expect("a source file");

    let report = scan(&dir);
    assert!(
        !report.exclusions.iter().any(|e| e.provider.as_str() == "sda.discovery"),
        "this tree has a file in it: {:?}",
        report.exclusions
    );

    let _ = std::fs::remove_dir_all(&dir);
}
