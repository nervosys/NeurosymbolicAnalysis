//! Run output, and the correlation records that make it *stato*dynamic.

use crate::evidence::Evidence;
use crate::finding::{Confidence, Finding, Severity};
use crate::ids::FindingId;
use crate::provider::Exclusion;
use crate::target::Language;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What dynamic evidence had to say about a static finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorrelationVerdict {
    /// Execution reached the code and exhibited the predicted defect.
    /// The strongest signal the toolkit can produce.
    Confirmed,
    /// Execution reached the code repeatedly and the defect did not occur.
    /// Not a proof of correctness, but strong evidence of a false positive.
    Refuted,
    /// No execution ever reached the code. The static finding stands unchallenged,
    /// and the coverage gap is itself worth reporting.
    Unreached,
    /// Execution reached the code but the observation was ambiguous.
    Inconclusive,
    /// A defect was observed at runtime that no static finding predicted.
    /// These are the gaps in the static rule set.
    Unpredicted,
    /// A proof obligation covering the finding was discharged: the predicted
    /// defect cannot occur on any execution, given the assumptions recorded
    /// with the proof.
    ///
    /// Strictly stronger than [`CorrelationVerdict::Refuted`], and deliberately
    /// not merged with it. `Refuted` says the code ran many times without
    /// faulting, which the report itself calls "not proof of correctness — the
    /// executions may all have taken the same path". `Proved` says there is no
    /// such path. Collapsing the two would throw away the only distinction that
    /// makes deductive evidence worth collecting.
    Proved,
    /// The finding lies behind a boundary this run cannot adjudicate — most
    /// often inside a learned model, where no proof is available and a quiet
    /// probe suite is not a refutation.
    ///
    /// Severity and confidence are left exactly where the static provider put
    /// them, for the same reason [`CorrelationVerdict::Unreached`] leaves them:
    /// nothing was learned. The verdict exists so that "we could not judge this"
    /// is a reported category rather than an absence.
    Assumed,
}

impl CorrelationVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            CorrelationVerdict::Confirmed => "confirmed",
            CorrelationVerdict::Refuted => "refuted",
            CorrelationVerdict::Unreached => "unreached",
            CorrelationVerdict::Inconclusive => "inconclusive",
            CorrelationVerdict::Unpredicted => "unpredicted",
            CorrelationVerdict::Proved => "proved",
            CorrelationVerdict::Assumed => "assumed",
        }
    }

    /// How this verdict moves a finding's severity.
    pub fn adjust_severity(&self, s: Severity) -> Severity {
        match self {
            CorrelationVerdict::Confirmed | CorrelationVerdict::Unpredicted => s.escalate(),
            CorrelationVerdict::Refuted => s.deescalate(),
            // A discharged proof does not soften the finding, it removes it: the
            // predicted defect has no execution on which it occurs.
            CorrelationVerdict::Proved => Severity::Info,
            CorrelationVerdict::Unreached
            | CorrelationVerdict::Inconclusive
            | CorrelationVerdict::Assumed => s,
        }
    }

    /// How this verdict moves a finding's confidence.
    pub fn adjust_confidence(&self, c: Confidence) -> Confidence {
        match self {
            CorrelationVerdict::Confirmed | CorrelationVerdict::Unpredicted => Confidence::Certain,
            CorrelationVerdict::Refuted => Confidence::Low,
            // Certain, and about the opposite proposition: the finding is
            // certainly not a defect. `Refuted` can only manage `Low`, because
            // repeated clean executions leave the question open.
            CorrelationVerdict::Proved => Confidence::Certain,
            // Unreached code tells you nothing about whether the static claim is
            // true, so confidence is left exactly where the static provider put it.
            // The same applies behind an unadjudicable boundary.
            CorrelationVerdict::Unreached
            | CorrelationVerdict::Inconclusive
            | CorrelationVerdict::Assumed => c,
        }
    }
}

impl CorrelationVerdict {
    /// The kind of evidence this verdict rests on.
    ///
    /// `Unreached` and `Assumed` have none, and that is the point of both: they
    /// record that no evidence bore on the finding, rather than reporting weak
    /// evidence as if it were some.
    pub fn modality(&self) -> Option<crate::verification::Modality> {
        use crate::verification::Modality;
        match self {
            CorrelationVerdict::Proved => Some(Modality::Deductive),
            CorrelationVerdict::Confirmed
            | CorrelationVerdict::Refuted
            | CorrelationVerdict::Unpredicted
            | CorrelationVerdict::Inconclusive => Some(Modality::Inductive),
            CorrelationVerdict::Unreached | CorrelationVerdict::Assumed => None,
        }
    }

    /// True when some evidence actually bore on the finding.
    pub fn is_adjudicated(&self) -> bool {
        self.modality().is_some()
    }
}

/// A static finding adjudicated against dynamic evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Correlation {
    /// The static finding under review. `None` for `Unpredicted` verdicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_finding: Option<FindingId>,
    /// Dynamic findings that bear on it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_findings: Vec<FindingId>,
    pub verdict: CorrelationVerdict,
    /// Human-readable justification; shown verbatim in the GUI and reports.
    pub rationale: String,
    /// Evidence gathered specifically while correlating (coverage counts, replays).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl Correlation {
    pub fn new(verdict: CorrelationVerdict, rationale: impl Into<String>) -> Self {
        Correlation {
            static_finding: None,
            dynamic_findings: Vec::new(),
            verdict,
            rationale: rationale.into(),
            evidence: Vec::new(),
        }
    }
    pub fn about(mut self, id: FindingId) -> Self {
        self.static_finding = Some(id);
        self
    }
    pub fn witnessed_by(mut self, id: FindingId) -> Self {
        self.dynamic_findings.push(id);
        self
    }
    pub fn evidence(mut self, e: Evidence) -> Self {
        self.evidence.push(e);
        self
    }
}

/// Aggregate counts for dashboards and CI gates.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Summary {
    pub total: usize,
    pub suppressed: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub by_phase: BTreeMap<String, usize>,
    pub by_provider: BTreeMap<String, usize>,
    pub by_language: BTreeMap<String, usize>,
    pub by_verdict: BTreeMap<String, usize>,
}

impl Summary {
    pub fn count(&self, severity: Severity) -> usize {
        self.by_severity.get(severity.as_str()).copied().unwrap_or(0)
    }
    /// Findings at or above `threshold`; the usual CI gate.
    pub fn at_or_above(&self, threshold: Severity) -> usize {
        [Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical]
            .iter()
            .filter(|s| **s >= threshold)
            .map(|s| self.count(*s))
            .sum()
    }
}

/// Which revision of the source a report describes.
///
/// # Why `dirty` is not optional
///
/// A conformance report that cannot say what it looked at is weaker than one
/// that can, which is why this exists at all. But *"these findings describe
/// commit abc123"* becomes false the moment somebody edits a file, and a
/// consumer reading only `revision` has no way to know. So the revision is
/// recorded **and** whether the working tree matched it, together, and neither
/// is emitted without the other.
///
/// `dirty` counts untracked files as well as modifications: a new source file is
/// analysed and is not in the commit, so a tree carrying one does not describe
/// that commit either.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcsProvenance {
    /// The commit the working tree is based on.
    pub revision: String,
    /// Branch name, when the checkout has one. A detached HEAD has none, and
    /// inventing one would be a claim about where this work belongs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// The remote this checkout came from, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Whether the working tree differed from `revision` when the scan ran.
    pub dirty: bool,
}

impl VcsProvenance {
    /// One sentence for a human, stating the limit of the claim where there is
    /// one.
    pub fn summary(&self) -> String {
        let where_ = match (&self.branch, &self.repository) {
            (Some(b), Some(r)) => format!(" on `{b}` of {r}"),
            (Some(b), None) => format!(" on `{b}`"),
            (None, Some(r)) => format!(" of {r}"),
            (None, None) => String::new(),
        };
        if self.dirty {
            format!(
                "based on commit {}{where_}, but the working tree had uncommitted changes when \
                 this ran — these findings describe what was on disk, which is not that commit",
                self.revision
            )
        } else {
            format!("commit {}{where_}, with a clean working tree", self.revision)
        }
    }
}

/// The complete output of one analysis run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    /// RFC 3339 timestamp.
    pub generated_at: String,
    pub tool_version: String,
    /// Analyzed root, as given.
    pub target: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub languages: Vec<Language>,
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub correlations: Vec<Correlation>,
    /// What this report does not cover, and why. Never omitted: a report that
    /// hides its own gaps is worse than no report.
    ///
    /// Not only providers that failed to run, though it began that way. An entry
    /// here may be an external tool that was never invoked, a provider that ran
    /// and reached no conclusion, a vacuous result, or configuration the project
    /// asked for and did not get. Nothing about an `Exclusion` says whether code
    /// executed, so a consumer must not read one as if it did — the SARIF
    /// serializer used to, for every entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<Exclusion>,
    /// The revision this report describes, when the target is a checkout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcs: Option<VcsProvenance>,
    pub summary: Summary,
}

impl Report {
    pub fn new(target: impl Into<String>, findings: Vec<Finding>) -> Self {
        let mut r = Report {
            schema_version: crate::SCHEMA_VERSION.to_string(),
            generated_at: now_rfc3339(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            target: target.into(),
            languages: Vec::new(),
            findings,
            correlations: Vec::new(),
            exclusions: Vec::new(),
            vcs: None,
            summary: Summary::default(),
        };
        r.recompute_summary();
        r
    }

    pub fn with_correlations(mut self, c: Vec<Correlation>) -> Self {
        self.correlations = c;
        self.recompute_summary();
        self
    }

    pub fn with_exclusions(mut self, e: Vec<Exclusion>) -> Self {
        self.exclusions = e;
        self
    }

    pub fn with_vcs(mut self, v: Option<VcsProvenance>) -> Self {
        self.vcs = v;
        self
    }

    /// Sort findings most-actionable-first and rebuild [`Summary`].
    pub fn finalize(mut self) -> Self {
        self.findings.sort_by_key(|f| f.triage_key());
        self.recompute_summary();
        self
    }

    pub fn recompute_summary(&mut self) {
        let mut s = Summary { total: self.findings.len(), ..Default::default() };
        for f in &self.findings {
            if f.is_suppressed() {
                s.suppressed += 1;
                continue;
            }
            *s.by_severity.entry(f.severity.as_str().to_string()).or_default() += 1;
            *s.by_phase.entry(f.phase.as_str().to_string()).or_default() += 1;
            *s.by_provider.entry(f.provider.to_string()).or_default() += 1;
            let lang = crate::target::Language::from_path(&f.location.file);
            *s.by_language.entry(lang.to_string()).or_default() += 1;
        }
        for c in &self.correlations {
            *s.by_verdict.entry(c.verdict.as_str().to_string()).or_default() += 1;
        }
        self.summary = s;
    }

    /// Findings the correlation engine promoted to runtime-confirmed.
    pub fn confirmed(&self) -> Vec<&Finding> {
        let ids: Vec<&FindingId> = self
            .correlations
            .iter()
            .filter(|c| c.verdict == CorrelationVerdict::Confirmed)
            .filter_map(|c| c.static_finding.as_ref())
            .collect();
        self.findings.iter().filter(|f| ids.contains(&&f.id)).collect()
    }

    /// The notice saying no enabled provider read anything, if this run carries
    /// one.
    ///
    /// One predicate, three consumers: the CI gate, `Report::fails_gate`, and
    /// the SARIF emitter. They were about to be three copies of the string
    /// `"sda.discovery"` in three crates, which is the shape this codebase has
    /// spent the day removing — a duplicate is harmless only while something
    /// compares the copies, and nothing compares string literals.
    pub fn discovery_notice(&self) -> Option<&crate::provider::Exclusion> {
        self.exclusions.iter().find(|e| e.provider.as_str() == "sda.discovery")
    }

    /// True when no enabled provider read anything this run.
    pub fn scanned_nothing(&self) -> bool {
        self.discovery_notice().is_some()
    }

    /// True when the run should stop a CI gate set at `threshold`.
    ///
    /// Two reasons to stop, not one. Findings at or above the threshold is the
    /// obvious one. The other is that nothing was scanned: a run that read no
    /// file has no verdict to give, and answering `false` there means *passed*,
    /// which is how a mistyped path produced a green build.
    ///
    /// `run::gate` says which of the three it is and explains itself in a
    /// sentence; this returns only the stop/continue half, because a `bool`
    /// cannot carry the distinction and pretending otherwise is the defect.
    /// They are kept in step by `the_two_gates_agree_about_stopping`, since
    /// `sda-core` cannot call into `sda-engine` to share the predicate.
    pub fn fails_gate(&self, threshold: Severity) -> bool {
        if self.scanned_nothing() {
            return true;
        }
        self.summary.at_or_above(threshold) > 0
    }

    pub fn to_json_pretty(&self) -> crate::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// RFC 3339 timestamp for "now", or a fixed epoch string if the clock is unavailable.
pub fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{AnalysisPhase, Location};

    fn finding(sev: Severity, phase: AnalysisPhase) -> Finding {
        Finding::new("sda.static.c", "R1", format!("{sev:?}/{phase:?}"), sev, Location::file_only("a.c"))
            .phase(phase)
    }

    #[test]
    fn summary_counts_by_dimension_and_skips_suppressed() {
        let mut suppressed = finding(Severity::High, AnalysisPhase::Static);
        suppressed.suppressed_by = Some("deviation D-17".into());
        let r = Report::new(
            "/p",
            vec![
                finding(Severity::Critical, AnalysisPhase::Dynamic),
                finding(Severity::Low, AnalysisPhase::Static),
                suppressed,
            ],
        );
        assert_eq!(r.summary.total, 3);
        assert_eq!(r.summary.suppressed, 1);
        assert_eq!(r.summary.count(Severity::Critical), 1);
        assert_eq!(r.summary.count(Severity::High), 0, "suppressed findings must not count");
        assert_eq!(r.summary.by_phase.get("dynamic"), Some(&1));
    }

    #[test]
    fn gate_threshold_is_inclusive_and_upward() {
        let r = Report::new("/p", vec![finding(Severity::High, AnalysisPhase::Static)]);
        assert!(r.fails_gate(Severity::High));
        assert!(r.fails_gate(Severity::Low));
        assert!(!r.fails_gate(Severity::Critical));
    }

    #[test]
    fn confirmation_escalates_and_refutation_demotes() {
        assert_eq!(CorrelationVerdict::Confirmed.adjust_severity(Severity::Medium), Severity::High);
        assert_eq!(CorrelationVerdict::Refuted.adjust_severity(Severity::Medium), Severity::Low);
        assert_eq!(
            CorrelationVerdict::Confirmed.adjust_confidence(Confidence::Low),
            Confidence::Certain
        );
    }

    #[test]
    fn unreached_code_leaves_the_static_claim_untouched() {
        assert_eq!(CorrelationVerdict::Unreached.adjust_severity(Severity::High), Severity::High);
        assert_eq!(
            CorrelationVerdict::Unreached.adjust_confidence(Confidence::Medium),
            Confidence::Medium
        );
    }

    #[test]
    fn confirmed_findings_are_recoverable_from_correlations() {
        let f = finding(Severity::Medium, AnalysisPhase::Static);
        let id = f.id.clone();
        let r = Report::new("/p", vec![f]).with_correlations(vec![
            Correlation::new(CorrelationVerdict::Confirmed, "crash replayed").about(id),
        ]);
        assert_eq!(r.confirmed().len(), 1);
        assert_eq!(r.summary.by_verdict.get("confirmed"), Some(&1));
    }

    #[test]
    fn finalize_sorts_most_severe_first() {
        let r = Report::new(
            "/p",
            vec![
                finding(Severity::Low, AnalysisPhase::Static),
                finding(Severity::Critical, AnalysisPhase::Static),
            ],
        )
        .finalize();
        assert_eq!(r.findings[0].severity, Severity::Critical);
    }
}
