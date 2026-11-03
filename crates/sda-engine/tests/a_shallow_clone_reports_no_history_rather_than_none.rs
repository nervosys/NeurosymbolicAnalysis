//! A shallow clone has no history, and that is not the same as no changes.
//!
//! This is the test the churn feature exists around, so it builds a real shallow
//! clone rather than describing one.
//!
//! `git clone --depth 1` is what CI does by default. On the clone it produces:
//!
//! * `git log` **succeeds** — exit zero, no warning, nothing on stderr;
//! * it reports one commit;
//! * that commit names every file in the tree, because the first commit of a
//!   shallow clone is the whole snapshot.
//!
//! Measured on this repository: one commit, 288 files. So a churn count built
//! from that log says every one of those 288 files changed exactly once, by one
//! author, on one day — and every file not in it changed *never*. Uniform,
//! confident, and wrong in the direction that reads as *settled*.
//!
//! The rule this repository keeps is that an inability to check must not be
//! presented as a clean check. `vcs::detect` states it for the tree: reporting
//! `dirty: false` from a status query that failed "would assert a clean tree on
//! the strength of a check that did not run". A count of zero commits, from a
//! clone with no commits to show, is that sentence again.
//!
//! So depth is asked *before* anything is counted, and the answer is a stated
//! reason rather than a map of zeros.

use sda_engine::history::{History, read};

/// Clone this repository shallowly and read its history.
#[test]
fn a_depth_one_clone_says_its_history_is_a_fragment() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root");

    let dir = std::env::temp_dir().join("sda-history-shallow");
    let _ = std::fs::remove_dir_all(&dir);

    // `file://` so this needs no network and no remote.
    let out = std::process::Command::new("git")
        .args(["clone", "--depth", "1", "--quiet"])
        .arg(format!("file://{}", repo.display()))
        .arg(&dir)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "the clone has to succeed for this test to mean anything: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The premise, asserted rather than assumed: git is perfectly happy here.
    let log = std::process::Command::new("git")
        .arg("-C")
        .arg(&dir)
        .args(["log", "--oneline"])
        .output()
        .expect("git runs");
    assert!(log.status.success(), "`git log` succeeds on a shallow clone — that is the trap");
    assert_eq!(
        String::from_utf8_lossy(&log.stdout).lines().count(),
        1,
        "and shows exactly the one commit it was given"
    );

    match read(&dir, 3650) {
        History::Unavailable { reason } => {
            assert!(
                reason.contains("shallow"),
                "the reason has to name what is wrong, because the caller cannot see it: {reason}"
            );
        }
        History::Read { files, .. } => panic!(
            "a shallow clone produced {} file histories. Every one of them is a count of the \
             single snapshot commit, and every file absent from it reads as never edited",
            files.len()
        ),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// And the report is told, in the section built for exactly this.
#[test]
fn the_report_is_told_that_nothing_was_ranked() {
    let dir = std::env::temp_dir().join("sda-history-shallow-notice");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");

    let notice = read(&dir, 180).notice().expect("an unreadable history is a stated gap");
    assert_eq!(notice.provider.as_str(), "sda.history");
    assert!(
        notice.reason.contains("must not be read as one"),
        "an ordering that is not a measurement has to say so, or the first file in the list \
         looks chosen: {}",
        notice.reason
    );

    let _ = std::fs::remove_dir_all(&dir);
}
