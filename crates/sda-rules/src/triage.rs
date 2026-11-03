//! Review state shared by every reader of a project — human or agent.
//!
//! A deviation says *this finding is permitted*. Triage says something weaker and
//! far more common: *someone has looked at this*. The two are deliberately
//! separate files and separate concepts. A deviation is a compliance artefact
//! with an approver and a rationale, validated against the catalogue and refused
//! outright for a Mandatory guideline. Triage is working state — the thing that
//! makes a backlog of fourteen thousand findings survivable — and it carries no
//! compliance weight at all.
//!
//! **Triage never hides a finding.** It annotates one. A tool that let a reviewer
//! make results disappear would be a tool for producing clean reports rather than
//! clean code, and the distinction between "nobody has looked at this" and "this
//! was examined and accepted" is exactly the kind this codebase exists to keep.
//! Filtering by state is a *view*, chosen in the moment and never persisted into
//! a report.
//!
//! **The state is a file in the project, not a row in a server.** That is what
//! makes it reviewable in a pull request, diffable, and — the point here —
//! writable by an agent and readable by a human in the same breath. An agent
//! working a backlog over MCP and an engineer scrolling the workbench are looking
//! at one file, so neither can silently diverge from the other.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// What a reviewer concluded about a finding.
///
/// Four states, because a fifth would be a workflow and workflows belong to the
/// team rather than the tool. `Fixed` is deliberately absent: whether a defect is
/// gone is decided by the next scan, not by someone ticking a box, and a state
/// the tool cannot verify is a state that goes stale in silence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TriageState {
    /// Nobody has looked at it. The default, and never written to the file.
    #[default]
    Open,
    /// Looked at, judged real, and queued. Claims nothing about who is doing it.
    Acknowledged,
    /// Looked at, judged real, accepted as it stands. **Not** a deviation: this
    /// makes no compliance claim and nothing validates it against a catalogue.
    Accepted,
    /// Looked at, judged wrong. The most valuable state in the set, because a
    /// false positive is a defect report about the analyzer.
    FalsePositive,
}

impl TriageState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TriageState::Open => "open",
            TriageState::Acknowledged => "acknowledged",
            TriageState::Accepted => "accepted",
            TriageState::FalsePositive => "false-positive",
        }
    }

    pub fn parse(s: &str) -> Option<TriageState> {
        match s {
            "open" => Some(TriageState::Open),
            "acknowledged" => Some(TriageState::Acknowledged),
            "accepted" => Some(TriageState::Accepted),
            "false-positive" | "false_positive" => Some(TriageState::FalsePositive),
            _ => None,
        }
    }

    /// Whether a person has actually reached a conclusion.
    pub fn is_reviewed(&self) -> bool {
        !matches!(self, TriageState::Open)
    }
}

/// One reviewed finding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TriageRecord {
    /// The finding's content-addressed id, stable across runs by construction —
    /// which is the whole reason this file is worth keeping.
    pub id: String,
    pub state: TriageState,
    /// Why. Optional for `acknowledged`, and the only thing that makes the other
    /// two states worth anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Who reached the conclusion — a person, or the agent acting for them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// Human-readable context, so the file can be reviewed without the tool.
    /// None of it is matched on: the id is the key, and these exist purely so a
    /// diff in a pull request means something to the person reading it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Who owns this finding now.
    ///
    /// A person or an agent — `a.erickson`, `agent:triage-bot` — because the
    /// interesting workflow here is a human handing a batch to an agent and
    /// reading back what it concluded, and that only works if both are the same
    /// kind of thing to the store. Assignment is a claim about *intent*, not
    /// about the code, and nothing validates it: there is no user directory to
    /// check a name against, and inventing one would put a server between a team
    /// and a file they can already review in a pull request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    /// The discussion, oldest first.
    ///
    /// Append-only by construction: `comment` pushes and nothing removes. A
    /// review whose history can be quietly edited is a review nobody can audit,
    /// and this file is meant to be read in a diff.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<TriageComment>,
}

/// One remark on a finding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TriageComment {
    /// A person or an agent. Same namespace as [`TriageRecord::assignee`].
    pub by: String,
    /// RFC 3339. Ordering a discussion by file position would be nonsense, and
    /// without a time a reader cannot tell a first impression from a conclusion.
    pub at: String,
    pub text: String,
}

/// Every triage record for a project.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TriageStore {
    #[serde(default, rename = "record")]
    records: Vec<TriageRecord>,
    #[serde(skip)]
    index: BTreeMap<String, usize>,
}

impl TriageStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a store, or report why it could not be read.
    ///
    /// A malformed file is an error rather than an empty store, for the reason
    /// the deviation register gives: a register that failed to load must not look
    /// like a project with nothing recorded.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut store: TriageStore = toml::from_str(text).map_err(|e| e.to_string())?;
        store.reindex();
        Ok(store)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::parse(&text)
    }

    pub fn to_toml(&self) -> Result<String, String> {
        let header = "# Review state for this project, written by the workbench and by agents\n\
                      # working over MCP. Both read and write this one file, so neither can\n\
                      # diverge from the other without it showing up in a diff.\n\
                      #\n\
                      # Triage annotates; it never hides. A finding recorded here still appears\n\
                      # in every report, with its state attached. Suppression is a deviation, in\n\
                      # `deviations.toml`, and that has an approver and a rationale for a reason.\n\n";
        let body = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        Ok(format!("{header}{body}"))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        // Through the symlink guard: the repository being scanned can commit `.sda`.
        sda_core::safe_write::write_refusing_symlinks(path, self.to_toml()?)
            .map_err(|e| e.to_string())
    }

    fn reindex(&mut self) {
        self.index =
            self.records.iter().enumerate().map(|(i, r)| (r.id.clone(), i)).collect();
    }

    pub fn get(&self, id: &str) -> Option<&TriageRecord> {
        self.index.get(id).map(|i| &self.records[*i])
    }

    pub fn state_of(&self, id: &str) -> TriageState {
        self.get(id).map(|r| r.state).unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn records(&self) -> &[TriageRecord] {
        &self.records
    }

    /// Record a conclusion, replacing any earlier one for the same finding.
    ///
    /// Setting `Open` *removes* the record rather than storing it: "nobody has
    /// looked at this" is the absence of a conclusion, and writing it down would
    /// make an untouched finding indistinguishable from one a reviewer opened and
    /// walked away from.
    pub fn set(&mut self, record: TriageRecord) {
        if record.state == TriageState::Open {
            // Clearing a verdict is not clearing the record. An assignment or a
            // discussion outlives someone changing their mind about the verdict,
            // and deleting them here would lose work nobody asked to discard.
            if let Some(i) = self.index.get(&record.id).copied() {
                let keep = self.records[i].assignee.is_some()
                    || !self.records[i].comments.is_empty();
                if keep {
                    self.records[i].state = TriageState::Open;
                    self.records[i].note = record.note;
                    return;
                }
            }
            self.records.retain(|r| r.id != record.id);
        } else if let Some(i) = self.index.get(&record.id).copied() {
            // A conclusion replaces the previous conclusion and nothing else.
            // Overwriting the record wholesale discarded the assignee and the
            // whole discussion the moment anybody pressed a verdict button.
            let mut merged = record;
            merged.assignee = merged.assignee.or_else(|| self.records[i].assignee.clone());
            if merged.comments.is_empty() {
                merged.comments = std::mem::take(&mut self.records[i].comments);
            }
            self.records[i] = merged;
        } else {
            self.records.push(record);
        }
        self.reindex();
    }

    /// Assign a finding, creating a record for it if there is none.
    ///
    /// Assigning does not conclude anything, so the state stays whatever it was —
    /// `Open` for a finding nobody has judged. Handing work to someone is not the
    /// same as agreeing with the tool about it, and collapsing the two would make
    /// a queue look reviewed because it had been distributed.
    pub fn assign(&mut self, id: &str, to: Option<String>, context: TriageRecord) {
        match self.index.get(id).copied() {
            Some(i) => self.records[i].assignee = to,
            None => {
                let mut r = context;
                r.id = id.to_string();
                r.state = TriageState::Open;
                r.assignee = to;
                // An assignment is a reason to keep a record even with no verdict,
                // which is the one case where `Open` is stored rather than absent.
                self.records.push(r);
                self.reindex();
            }
        }
    }

    /// Append a remark.
    ///
    /// Same reasoning as `assign`: commenting is not concluding.
    pub fn comment(&mut self, id: &str, by: &str, text: &str, context: TriageRecord) {
        let entry = TriageComment {
            by: by.to_string(),
            at: sda_core::now_rfc3339(),
            text: text.to_string(),
        };
        match self.index.get(id).copied() {
            Some(i) => self.records[i].comments.push(entry),
            None => {
                let mut r = context;
                r.id = id.to_string();
                r.state = TriageState::Open;
                r.comments = vec![entry];
                self.records.push(r);
                self.reindex();
            }
        }
    }

    /// Findings assigned to `who`.
    pub fn assigned_to<'a>(&'a self, who: &str) -> Vec<&'a TriageRecord> {
        self.records.iter().filter(|r| r.assignee.as_deref() == Some(who)).collect()
    }

    /// Every distinct assignee, with how many findings each holds.
    pub fn by_assignee(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for r in &self.records {
            if let Some(a) = &r.assignee {
                *m.entry(a.clone()).or_default() += 1;
            }
        }
        m
    }

    /// Records whose finding did not appear in this run.
    ///
    /// Reported, never silently dropped. A stale record means the code moved
    /// under a conclusion somebody reached, and the two honest readings — the
    /// defect was fixed, or it moved and is now unreviewed — cannot be told apart
    /// from here. Deleting them automatically would quietly discard the second.
    pub fn stale<'a>(&'a self, seen: &[String]) -> Vec<&'a TriageRecord> {
        let live: std::collections::BTreeSet<&str> = seen.iter().map(|s| s.as_str()).collect();
        self.records.iter().filter(|r| !live.contains(r.id.as_str())).collect()
    }

    /// How many findings sit in each state, for a progress readout.
    pub fn by_state(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for r in &self.records {
            *m.entry(r.state.as_str()).or_default() += 1;
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, state: TriageState) -> TriageRecord {
        TriageRecord {
            id: id.into(),
            state,
            note: Some("looked at it".into()),
            by: Some("a.erickson".into()),
            rule: Some("MISRA-C-2023-15.5".into()),
            location: Some("src/main.c:12".into()),
            title: Some("t".into()),
            assignee: None,
            comments: Vec::new(),
        }
    }

    #[test]
    fn a_conclusion_survives_a_round_trip() {
        let mut s = TriageStore::new();
        s.set(rec("abc", TriageState::FalsePositive));
        let text = s.to_toml().unwrap();
        let back = TriageStore::parse(&text).unwrap();
        assert_eq!(back.state_of("abc"), TriageState::FalsePositive);
        assert_eq!(back.get("abc").unwrap().by.as_deref(), Some("a.erickson"));
    }

    /// The default is not a stored value. A finding nobody has opened and one
    /// somebody opened and left alone must not look the same.
    #[test]
    fn setting_open_removes_the_record_rather_than_storing_it() {
        let mut s = TriageStore::new();
        s.set(rec("abc", TriageState::Accepted));
        assert_eq!(s.len(), 1);
        s.set(rec("abc", TriageState::Open));
        assert_eq!(s.len(), 0);
        assert_eq!(s.state_of("abc"), TriageState::Open);
    }

    #[test]
    fn a_second_conclusion_replaces_the_first() {
        let mut s = TriageStore::new();
        s.set(rec("abc", TriageState::Acknowledged));
        s.set(rec("abc", TriageState::FalsePositive));
        assert_eq!(s.len(), 1, "one finding, one conclusion");
        assert_eq!(s.state_of("abc"), TriageState::FalsePositive);
    }

    /// The code moved under a conclusion somebody reached. Both readings — fixed,
    /// or moved and now unreviewed — are live, so it is reported rather than
    /// resolved.
    #[test]
    fn a_record_whose_finding_vanished_is_reported_as_stale() {
        let mut s = TriageStore::new();
        s.set(rec("gone", TriageState::Accepted));
        s.set(rec("here", TriageState::Accepted));
        let stale = s.stale(&["here".to_string()]);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].id, "gone");
    }

    #[test]
    fn a_malformed_store_is_an_error_not_an_empty_one() {
        assert!(TriageStore::parse("record = [[[").is_err());
    }

    #[test]
    fn an_absent_file_is_an_empty_store_rather_than_an_error() {
        let p = std::env::temp_dir().join("sda-triage-does-not-exist.toml");
        let _ = std::fs::remove_file(&p);
        assert!(TriageStore::load(&p).unwrap().is_empty());
    }

    /// And a malformed one is an error rather than an empty store.
    ///
    /// `a_malformed_store_is_an_error_not_an_empty_one` already says this of
    /// `parse`. This says it of `load`, which is the level the callers use and
    /// the level the sibling test above covers for the absent case — so both
    /// branches of the same distinction are pinned where they are relied on.
    ///
    /// The distinction is the point: "nobody has reviewed these" and "the review
    /// state could not be read" are identical in an empty store, and the first
    /// is what gets a finding dismissed a second time by someone who already
    /// decided about it once. The workbench's scan path used
    /// `unwrap_or_default()` here, so a corrupt file showed every finding as
    /// untriaged and then errored the moment anyone tried to triage.
    #[test]
    fn a_malformed_file_is_an_error_rather_than_an_empty_store() {
        let p = std::env::temp_dir().join("sda-triage-malformed.toml");
        std::fs::write(&p, "not toml {{{").unwrap();

        let loaded = TriageStore::load(&p);
        assert!(
            loaded.is_err(),
            "a store that could not be read must not arrive as one that is empty"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn states_round_trip_through_their_wire_names() {
        for s in [
            TriageState::Open,
            TriageState::Acknowledged,
            TriageState::Accepted,
            TriageState::FalsePositive,
        ] {
            assert_eq!(TriageState::parse(s.as_str()), Some(s));
        }
        assert!(!TriageState::Open.is_reviewed());
        assert!(TriageState::FalsePositive.is_reviewed());
    }

    /// Assignment is a claim about intent, not about the code, so it must not
    /// look like somebody agreed with the finding.
    #[test]
    fn assigning_does_not_conclude_anything() {
        let mut s = TriageStore::new();
        s.assign("abc", Some("agent:triage-bot".into()), rec("abc", TriageState::Open));
        assert_eq!(s.state_of("abc"), TriageState::Open, "assigned is not reviewed");
        assert!(!s.state_of("abc").is_reviewed());
        assert_eq!(s.get("abc").unwrap().assignee.as_deref(), Some("agent:triage-bot"));
        assert_eq!(s.by_assignee().get("agent:triage-bot"), Some(&1));
    }

    /// A human hands work to an agent and reads back what it concluded. That is
    /// the whole point of one namespace for both.
    #[test]
    fn a_human_can_hand_a_finding_to_an_agent_and_read_back_its_conclusion() {
        let mut s = TriageStore::new();
        s.assign("abc", Some("agent:triage-bot".into()), rec("abc", TriageState::Open));
        s.comment("abc", "a.erickson", "is this reachable?", rec("abc", TriageState::Open));

        let mut concluded = rec("abc", TriageState::FalsePositive);
        concluded.by = Some("agent:triage-bot".into());
        s.set(concluded);

        let r = s.get("abc").unwrap();
        assert_eq!(r.state, TriageState::FalsePositive);
        assert_eq!(r.by.as_deref(), Some("agent:triage-bot"));
        assert_eq!(r.assignee.as_deref(), Some("agent:triage-bot"), "a verdict kept the owner");
        assert_eq!(r.comments.len(), 1, "and kept the question that was asked");
    }

    /// The easy bug: `set` replaced the record wholesale, so pressing a verdict
    /// button discarded the assignee and the entire discussion.
    #[test]
    fn recording_a_verdict_does_not_discard_the_discussion() {
        let mut s = TriageStore::new();
        s.comment("abc", "a.erickson", "first", rec("abc", TriageState::Open));
        s.comment("abc", "b.reviewer", "second", rec("abc", TriageState::Open));
        s.assign("abc", Some("b.reviewer".into()), rec("abc", TriageState::Open));

        s.set(rec("abc", TriageState::Accepted));

        let r = s.get("abc").unwrap();
        assert_eq!(r.comments.len(), 2, "the thread survived a verdict");
        assert_eq!(r.comments[0].text, "first", "and kept its order");
        assert_eq!(r.assignee.as_deref(), Some("b.reviewer"));
    }

    /// Clearing a verdict is not clearing the record. Someone changing their mind
    /// must not delete an assignment or a thread nobody asked to discard.
    #[test]
    fn clearing_a_verdict_keeps_an_assignment_and_a_thread() {
        let mut s = TriageStore::new();
        s.set(rec("abc", TriageState::Accepted));
        s.assign("abc", Some("a.erickson".into()), rec("abc", TriageState::Open));
        s.comment("abc", "a.erickson", "keep me", rec("abc", TriageState::Open));

        s.set(rec("abc", TriageState::Open));

        let r = s.get("abc").expect("the record survives losing its verdict");
        assert_eq!(r.state, TriageState::Open);
        assert_eq!(r.comments.len(), 1);
        assert_eq!(r.assignee.as_deref(), Some("a.erickson"));
    }

    /// But a record that holds nothing else still disappears, so an untouched
    /// finding and one somebody opened and walked away from stay distinguishable.
    #[test]
    fn clearing_a_verdict_on_a_bare_record_still_removes_it() {
        let mut s = TriageStore::new();
        s.set(rec("abc", TriageState::Accepted));
        s.set(rec("abc", TriageState::Open));
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn a_thread_is_append_only_and_ordered_by_time() {
        let mut s = TriageStore::new();
        s.comment("abc", "a", "one", rec("abc", TriageState::Open));
        s.comment("abc", "b", "two", rec("abc", TriageState::Open));
        let c = &s.get("abc").unwrap().comments;
        assert_eq!(c.len(), 2);
        assert_eq!((c[0].by.as_str(), c[1].by.as_str()), ("a", "b"));
        assert!(c[0].at.contains('T'), "a remark without a time cannot be read as a discussion");
    }

    #[test]
    fn assignment_and_comments_survive_a_round_trip() {
        let mut s = TriageStore::new();
        s.assign("abc", Some("agent:triage-bot".into()), rec("abc", TriageState::Open));
        s.comment("abc", "a.erickson", "why?", rec("abc", TriageState::Open));
        let back = TriageStore::parse(&s.to_toml().unwrap()).unwrap();
        let r = back.get("abc").unwrap();
        assert_eq!(r.assignee.as_deref(), Some("agent:triage-bot"));
        assert_eq!(r.comments[0].text, "why?");
        assert_eq!(back.assigned_to("agent:triage-bot").len(), 1);
    }
}
