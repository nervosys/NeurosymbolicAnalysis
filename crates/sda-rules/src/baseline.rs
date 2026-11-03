//! What the findings looked like last time somebody said "this is the line".
//!
//! Every commercial reviewer has some version of this — Coverity's snapshots,
//! SonarQube's new-code period — because the question a team actually asks is not
//! *how many findings are there* but *what did we just add*. A backlog of
//! fourteen thousand is not triaged; a diff of eleven is.
//!
//! Three decisions here, and each is the difference between a useful baseline and
//! a misleading one.
//!
//! **A baseline is set deliberately, never on every scan.** The obvious
//! implementation records the current findings each time it runs, and then
//! nothing is ever new: every finding was present in the baseline written
//! moments earlier by the scan you are looking at. That is a feature that reports
//! zero forever and looks like it is working.
//!
//! **No baseline means *unknown*, not *not new*.** [`Baseline::status`] returns
//! `None` when nothing was recorded, and callers are expected to render that
//! differently from `Some(false)`. Treating an absent baseline as "nothing is
//! new" would be the same confusion the correlation engine has a table about:
//! never measured, reported as measured and clean.
//!
//! **New means *not in the recorded set*, and nothing more.** It is not a claim
//! about authorship, a commit, or a release. A finding is new because the last
//! person to draw a line did not see it — which may be because the code changed,
//! or because a rule was added, or because a tool was enabled. The baseline
//! records what it recorded and the report says when.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// The recorded state of a previous run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    /// RFC 3339, so a report can say how old the comparison is. A baseline
    /// nobody has refreshed in a year is still a baseline, and the date is how a
    /// reader knows to distrust it.
    pub taken_at: String,
    /// What the project was when it was taken, for the same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Content-addressed finding ids. A set, because order carries nothing.
    #[serde(default)]
    pub ids: BTreeSet<String>,
}

impl Baseline {
    /// Record the findings of a run as the new line.
    pub fn of(ids: impl IntoIterator<Item = String>, taken_at: String, note: Option<String>) -> Self {
        Baseline { taken_at, note, ids: ids.into_iter().collect() }
    }

    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        // A malformed baseline is an error, not an absent one. "We could not read
        // the line" and "nobody has drawn a line" are different, and the second
        // is the one that makes every finding new.
        toml::from_str(&text).map(Some).map_err(|e| e.to_string())
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let header = concat!(
            "# The findings a previous run produced, recorded deliberately so this one\n",
            "# can say what is *new*. Set it when you accept the current state as the\n",
            "# line; it is never written automatically, because a baseline refreshed on\n",
            "# every scan reports zero new findings forever and looks like it is working.\n\n",
        );
        let body = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        // Through the symlink guard: the repository being scanned can commit `.sda`.
        sda_core::safe_write::write_refusing_symlinks(path, format!("{header}{body}"))
            .map_err(|e| e.to_string())
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Whether a finding is absent from the recorded set.
    pub fn is_new(&self, id: &str) -> bool {
        !self.ids.contains(id)
    }

    /// Ids in the baseline that this run did not produce.
    ///
    /// Worth reporting for the reason a stale triage record is: something the
    /// last line included is gone, and *fixed*, *moved*, *filtered out by a scope
    /// change* and *a rule that stopped firing* all look identical from here.
    pub fn resolved(&self, seen: &BTreeSet<String>) -> Vec<&str> {
        self.ids.iter().filter(|id| !seen.contains(*id)).map(|s| s.as_str()).collect()
    }
}

/// Whether a finding is new, when that is even askable.
///
/// `None` is the whole point of this type: with nothing recorded, "is this new"
/// has no answer, and a `bool` would have to invent one.
pub fn status(baseline: Option<&Baseline>, id: &str) -> Option<bool> {
    baseline.map(|b| b.is_new(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Baseline {
        Baseline::of(
            ["a".to_string(), "b".to_string()],
            "2026-09-07T00:00:00Z".into(),
            Some("before the refactor".into()),
        )
    }

    #[test]
    fn a_finding_the_baseline_did_not_hold_is_new() {
        let b = base();
        assert!(!b.is_new("a"));
        assert!(b.is_new("c"));
    }

    /// The distinction the whole module exists for. An absent baseline must not
    /// answer the question at all.
    #[test]
    fn with_no_baseline_newness_is_unknown_rather_than_false() {
        assert_eq!(status(None, "anything"), None);
        assert_eq!(status(Some(&base()), "a"), Some(false));
        assert_eq!(status(Some(&base()), "c"), Some(true));
    }

    #[test]
    fn findings_the_baseline_held_and_this_run_lost_are_reported() {
        let seen: BTreeSet<String> = ["a".to_string()].into_iter().collect();
        assert_eq!(base().resolved(&seen), vec!["b"]);
    }

    #[test]
    fn a_baseline_survives_a_round_trip() {
        let dir = std::env::temp_dir().join("sda-baseline-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("baseline.toml");
        base().save(&p).unwrap();
        let back = Baseline::load(&p).unwrap().unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.taken_at, "2026-09-07T00:00:00Z");
        assert_eq!(back.note.as_deref(), Some("before the refactor"));
    }

    #[test]
    fn an_absent_file_is_none_and_a_malformed_one_is_an_error() {
        let missing = std::env::temp_dir().join("sda-baseline-absent.toml");
        let _ = std::fs::remove_file(&missing);
        assert!(Baseline::load(&missing).unwrap().is_none());

        let bad = std::env::temp_dir().join("sda-baseline-bad.toml");
        std::fs::write(&bad, "ids = [[[").unwrap();
        assert!(Baseline::load(&bad).is_err(), "unreadable is not the same as unrecorded");
    }
}
