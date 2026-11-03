//! How often each file changed, for triage rather than for judgement.
//!
//! A scan of PX4 reports 78,211 findings. Sorted by severity, confidence, then
//! *path*, the forty-two thousand `low` ones are in alphabetical order, which is
//! no order at all. A reader who must start somewhere has nothing to start from.
//!
//! Churn is the cheapest evidence that helps. A file carrying findings that
//! twelve people touched forty times this year is a different proposition from
//! one carrying the same findings and last modified in 2019 — not because the
//! findings differ, but because one of them is still moving.
//!
//! # What this is not
//!
//! **Churn is not a defect and must never be reported as one.** No rule here
//! emits a finding, nothing gains severity for being edited, and no file is
//! "risky" because git says so. It is an ordering over findings that already
//! exist, offered to a person deciding where to spend an afternoon. The moment a
//! number like this becomes a verdict it starts making claims about code from
//! facts about a team.
//!
//! # The failure this refuses
//!
//! `git log` on a shallow clone succeeds, prints a handful of commits, and exits
//! zero. Every file then looks untouched — and "untouched" reads as *stable*,
//! which is the most confident possible wrong answer. CI checks out shallow by
//! default, so this is the normal case, not the exotic one.
//!
//! `vcs::detect` already states the principle for the tree as a whole:
//! reporting `dirty: false` on the strength of a status query that failed "would
//! assert a clean tree on the strength of a check that did not run". A count of
//! zero commits, from a clone that has no commits to show, is the same sentence.
//!
//! So depth is checked first, and a shallow clone produces [`History::Unavailable`]
//! carrying the reason. Not zeros. Not an empty map that a caller might read as
//! "nothing changed".

use sda_core::Exclusion;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// What git could tell us about one file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileHistory {
    /// Commits touching this file inside the window.
    pub commits: u32,
    /// Distinct authors over those commits.
    pub authors: u32,
    /// The date of the most recent one, `YYYY-MM-DD`, as git reports it.
    pub last_change: String,
}

/// History for a tree, or a stated reason there is none.
///
/// Two variants rather than an empty map, because an empty map is exactly the
/// thing a caller misreads. `Unavailable` cannot be mistaken for "nothing
/// changed" — it has to be handled, and the only honest handling is to say so.
#[derive(Clone, Debug)]
pub enum History {
    /// Git answered, over the window named.
    ///
    /// `tracked` is every file git knows about, which is not the same set as
    /// `files`. A tracked file absent from `files` genuinely had no commit in the
    /// window — git looked and found none. An *untracked* file is absent because
    /// git has never seen it, and reporting `0` for that asserts a settled file
    /// on the strength of a question nobody asked.
    Read {
        files: BTreeMap<String, FileHistory>,
        tracked: BTreeSet<String>,
        window_days: u32,
    },
    /// Git could not answer, and this is why.
    Unavailable { reason: String },
}

impl History {
    /// The file's history, or `None` when it has none *or* when none is known.
    ///
    /// Deliberately the same answer for both, so a caller cannot accidentally
    /// treat an unknown file as a quiet one. Callers that need the distinction
    /// ask [`History::notice`], which is the only place the difference is
    /// reportable.
    pub fn get(&self, path: &str) -> Option<&FileHistory> {
        match self {
            History::Read { files, .. } => files.get(path),
            History::Unavailable { .. } => None,
        }
    }

    /// Whether git knows this file at all.
    ///
    /// The distinction `get` cannot make. `get` returns `None` for a file with no
    /// commits in the window and for a file git has never heard of, and those are
    /// different facts: the first is a count of zero, the second is the absence of
    /// a count. Rendering both as `0` was the defect this exists to prevent —
    /// found by putting an untracked file in front of `sda hotspots` the day
    /// after the same distinction was drawn for an unreadable history.
    pub fn knows(&self, path: &str) -> bool {
        match self {
            History::Read { tracked, .. } => tracked.contains(path),
            History::Unavailable { .. } => false,
        }
    }

    /// What the report must say about this history, when anything.
    pub fn notice(&self) -> Option<Exclusion> {
        match self {
            History::Read { .. } => None,
            History::Unavailable { reason } => Some(Exclusion {
                provider: "sda.history".into(),
                reason: format!(
                    "{reason}, so no file was ranked by how often it changes. Every file is \
                     ordered as though it were equally settled, which is not a measurement \
                     and must not be read as one"
                ),
            }),
        }
    }
}

/// Read per-file churn under `root` over the last `window_days` days.
///
/// Asks git rather than reimplementing it, for the reasons `vcs::detect` gives.
/// Paths come back relative to `root`, not to the repository, so a scan of a
/// subdirectory joins against the findings it produced.
pub fn read(root: &Path, window_days: u32) -> History {
    if git(root, &["rev-parse", "HEAD"]).is_none() {
        return History::Unavailable { reason: "`{root}` is not a git checkout".replace(
            "{root}",
            &root.display().to_string(),
        ) };
    }

    // Depth first, and before any counting.
    //
    // `--is-shallow-repository` prints `true` or `false`. A shallow clone still
    // answers `git log` cheerfully with whatever it has, so asking afterwards is
    // asking too late: the counts would already be built and would already be
    // wrong in the direction that looks reassuring.
    if git(root, &["rev-parse", "--is-shallow-repository"]).as_deref() == Some("true") {
        return History::Unavailable {
            reason: "this checkout is shallow, so its history is a fragment of the project's"
                .into(),
        };
    }

    // Where the scan root sits inside the repository. `git log` reports paths
    // from the repository root; findings are relative to the scan root. Without
    // this every path fails to join whenever anyone scans a subdirectory, and a
    // silent total failure to match looks exactly like a tree nobody edits.
    let prefix = git(root, &["rev-parse", "--show-prefix"]).unwrap_or_default();

    let since = format!("--since={window_days} days ago");
    let Some(log) = git(
        root,
        &["log", &since, "--no-merges", "--date=short", "--format=%x00%ad%x00%an", "--name-only"],
    ) else {
        return History::Unavailable {
            reason: "`git log` failed in a checkout git otherwise recognises".into(),
        };
    };

    // Every path git tracks under the scan root, so an untracked file can be told
    // from one that simply did not change. `-C root` makes the listing relative
    // to the scan root, which is what the findings are relative to.
    let tracked: BTreeSet<String> = git(root, &["ls-files"])
        .map(|out| out.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default();

    let mut files: BTreeMap<String, FileHistory> = BTreeMap::new();
    let mut seen_authors: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    let mut date = String::new();
    let mut author = String::new();

    for line in log.lines() {
        if let Some(rest) = line.strip_prefix('\0') {
            // A commit header: date and author, separated by the same NUL.
            let mut parts = rest.splitn(2, '\0');
            date = parts.next().unwrap_or_default().to_string();
            author = parts.next().unwrap_or_default().to_string();
            continue;
        }
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        // Back to the scan root, and skipped when the file is outside it.
        let Some(rel) = path.strip_prefix(prefix.as_str()) else { continue };
        if rel.is_empty() {
            continue;
        }

        let e = files.entry(rel.to_string()).or_default();
        e.commits += 1;
        // `git log` walks newest first, so the first date seen for a file is its
        // most recent change.
        if e.last_change.is_empty() {
            e.last_change = date.clone();
        }
        seen_authors.entry(rel.to_string()).or_default().insert(author.clone());
    }

    for (path, authors) in seen_authors {
        if let Some(e) = files.get_mut(&path) {
            e.authors = authors.len() as u32;
        }
    }

    History::Read { files, tracked, window_days }
}

/// One git query, trimmed. `None` for any non-zero exit. Built by
/// `vcs::command`, so the repository's own configuration runs nothing.
fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = crate::vcs::command(root).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This repository is a checkout with real history, so reading it works.
    #[test]
    fn a_real_checkout_reports_files_that_changed() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("the workspace root");

        match read(root, 3650) {
            History::Read { files, window_days, .. } => {
                assert_eq!(window_days, 3650);
                assert!(!files.is_empty(), "this repository has a history to read");
                let handoff = files
                    .get("HANDOFF.md")
                    .expect("HANDOFF.md has been edited rather a lot");
                assert!(handoff.commits > 0);
                assert!(handoff.authors > 0);
                assert!(
                    handoff.last_change.len() == 10,
                    "a `YYYY-MM-DD` date: {}",
                    handoff.last_change
                );
            }
            History::Unavailable { reason } => {
                panic!("the workspace is a checkout with history: {reason}")
            }
        }
    }

    /// A file git has never seen is not a file that never changed.
    ///
    /// `get` returns `None` for both, and rendering both as `0` said a file was
    /// settled on the strength of a question nobody asked. Found by putting an
    /// untracked file in front of `sda hotspots` the day after the same
    /// distinction was drawn for an unreadable history — the row printed
    /// `0 commits` beside `—` for its date, contradicting itself.
    #[test]
    fn an_untracked_file_is_not_a_file_that_never_changed() {
        let dir = std::env::temp_dir().join("sda-history-tracked");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");

        let git_ = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(args)
                .output()
                .expect("git runs")
        };
        git_(&["init", "--quiet"]);
        git_(&["config", "user.email", "t@example.invalid"]);
        git_(&["config", "user.name", "T"]);

        std::fs::write(dir.join("tracked.c"), "int f(void) { return 0; }
").unwrap();
        git_(&["add", "tracked.c"]);
        git_(&["commit", "--quiet", "-m", "one"]);

        // Never added.
        std::fs::write(dir.join("untracked.c"), "int g(void) { return 1; }
").unwrap();

        let h = read(&dir, 3650);
        assert!(h.knows("tracked.c"), "git tracks this one");
        assert!(
            !h.knows("untracked.c"),
            "git has never seen this one, and `0 commits` for it would be a count of a              question nobody asked"
        );

        // And the one it knows about really did change.
        assert!(h.get("tracked.c").is_some_and(|f| f.commits == 1));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory that is not a checkout says so instead of returning nothing.
    #[test]
    fn a_directory_that_is_not_a_checkout_is_unavailable_rather_than_empty() {
        let dir = std::env::temp_dir().join("sda-history-not-a-repo");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");

        let h = read(&dir, 180);
        assert!(
            matches!(h, History::Unavailable { .. }),
            "an empty map here would read as a tree nobody has ever edited"
        );
        let notice = h.notice().expect("and it must reach the report");
        assert_eq!(notice.provider.as_str(), "sda.history");
        assert!(notice.reason.contains("not a git checkout"), "{}", notice.reason);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `get` answers `None` for an unknown file and for an unreadable history
    /// alike, so neither can be mistaken for a settled file.
    #[test]
    fn an_unavailable_history_answers_nothing_about_any_file() {
        let h = History::Unavailable { reason: "no checkout".into() };
        assert!(h.get("src/main.c").is_none());
        assert!(h.notice().is_some(), "the difference is reportable, not guessable");
    }
}
