//! The central unit of analysis output.

use crate::evidence::Evidence;
use crate::ids::{FindingId, ProviderId, RuleId, fingerprint};
use crate::taxonomy::{Taxonomy, TaxonomyRef};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
    /// One step more severe, saturating at `Critical`.
    pub fn escalate(self) -> Severity {
        match self {
            Severity::Info => Severity::Low,
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High | Severity::Critical => Severity::Critical,
        }
    }
    /// One step less severe, saturating at `Info`.
    pub fn deescalate(self) -> Severity {
        match self {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low | Severity::Info => Severity::Info,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How much the emitting provider trusts this finding.
///
/// This is orthogonal to severity: a `Critical`/`Low` finding is a
/// catastrophic-if-true report worth a human's attention, while a
/// `Low`/`Certain` finding is a definite but minor defect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// Heuristic; expect false positives.
    Low,
    /// Pattern is reliable but context was not fully resolved.
    Medium,
    /// Provider resolved the relevant context.
    High,
    /// Observed at runtime, or otherwise not in doubt.
    Certain,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
            Confidence::Certain => "certain",
        }
    }
}

/// Which side of the statodynamic divide produced this finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisPhase {
    /// Derived from source alone.
    Static,
    /// Derived from observing execution.
    Dynamic,
    /// Produced by correlating static and dynamic evidence.
    Statodynamic,
}

impl AnalysisPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnalysisPhase::Static => "static",
            AnalysisPhase::Dynamic => "dynamic",
            AnalysisPhase::Statodynamic => "statodynamic",
        }
    }
}

/// A source position. Lines and columns are 1-based, matching every compiler
/// and editor a user will cross-reference against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: PathBuf,
    pub line: u32,
    #[serde(default = "one")]
    pub column: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
    /// Enclosing function, when the provider knows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Byte offset of the construct, for files that have no lines.
    ///
    /// A pickle opcode, a GGUF header field or a safetensors tensor entry has a
    /// position, but it is a byte offset — there is no line to report and no
    /// column to point at. Model findings used to be flattened to `path:1:1`,
    /// which says "the start of the file" when the truth was "byte 4128", and
    /// the offset was known one layer down: it is already carried in
    /// [`crate::Evidence::ModelArtifact`], purely as prose.
    ///
    /// Line/column and byte range are not alternatives to each other. A text
    /// finding has the first; an artifact finding has the second; nothing is
    /// required to invent the one it does not have.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_start: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_end: Option<u64>,
}

fn one() -> u32 {
    1
}

impl Location {
    pub fn new(file: impl Into<PathBuf>, line: u32, column: u32) -> Self {
        Location {
            file: file.into(),
            line,
            column,
            end_line: None,
            end_column: None,
            function: None,
            byte_start: None,
            byte_end: None,
        }
    }
    pub fn file_only(file: impl Into<PathBuf>) -> Self {
        Location::new(file, 1, 1)
    }
    pub fn spanning(mut self, end_line: u32, end_column: u32) -> Self {
        self.end_line = Some(end_line);
        self.end_column = Some(end_column);
        self
    }
    /// Locate a finding at a byte range, for a file with no line structure.
    ///
    /// An end at or before the start is no extent, and is recorded as a bare
    /// offset rather than a zero-width range — the same guard the line-based
    /// spans use, for the same reason.
    pub fn at_bytes(mut self, start: u64, end: Option<u64>) -> Self {
        self.byte_start = Some(start);
        self.byte_end = end.filter(|e| *e > start);
        self
    }
    /// True when this location is a byte offset rather than a line and column.
    pub fn is_byte_located(&self) -> bool {
        self.byte_start.is_some()
    }
    pub fn in_function(mut self, name: impl Into<String>) -> Self {
        self.function = Some(name.into());
        self
    }
    /// `path:line:col`, the form terminals and editors linkify.
    ///
    /// Separators are normalised to `/`, as they are for SARIF URIs, deviation
    /// scopes and probe correlation. This string is what an agent reads out of
    /// the MCP surface, and a location that changes shape with the host OS makes
    /// agent output unportable and stops it matching the same finding's SARIF.
    ///
    /// A byte-located finding renders as `path@0x1030` instead. Printing
    /// `model.pkl:1:1` for an opcode four kilobytes into a binary is not a
    /// position, it is the absence of one wearing a position's clothes — and it
    /// sends a reader to the top of a file that has no lines to look at.
    pub fn display(&self) -> String {
        let file = self.file.to_string_lossy().replace('\\', "/");
        match self.byte_start {
            Some(start) => format!("{file}@{start:#x}"),
            None => format!("{file}:{}:{}", self.line, self.column),
        }
    }
    /// True when both locations name the same file and overlap by line.
    pub fn overlaps(&self, other: &Location) -> bool {
        if self.file != other.file {
            return false;
        }
        let a = (self.line, self.end_line.unwrap_or(self.line));
        let b = (other.line, other.end_line.unwrap_or(other.line));
        a.0 <= b.1 && b.0 <= a.1
    }
}

/// A single reported issue.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    /// Content-addressed identity, stable across runs.
    pub id: FindingId,
    /// Provider that emitted it, e.g. `sda.static.c`.
    pub provider: ProviderId,
    /// Rule it violates, e.g. `MISRA-C-2023-15.5`.
    pub rule: RuleId,
    /// One-line headline suitable for a list view.
    pub title: String,
    /// Full explanation, including why it matters here.
    pub message: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub phase: AnalysisPhase,
    pub location: Location,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taxonomy: Vec<TaxonomyRef>,
    /// Concrete guidance on how to fix it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Set when a deviation record or suppression comment silences this finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed_by: Option<String>,
}

impl Finding {
    /// Build a finding, deriving its fingerprint from the identity-defining fields.
    ///
    /// The position is part of that identity. It is tempting to leave it out so
    /// that edits above a finding do not churn its id across runs, but two
    /// violations of the same rule in the same file are *different findings*:
    /// collapsing them means one correlation verdict silently applies to all of
    /// them, one deviation suppresses all of them, and a SARIF consumer shows
    /// one where there are several. Stability is worth less than distinctness.
    pub fn new(
        provider: impl Into<ProviderId>,
        rule: impl Into<RuleId>,
        title: impl Into<String>,
        severity: Severity,
        location: Location,
    ) -> Self {
        let provider = provider.into();
        let rule = rule.into();
        let title = title.into();
        let id = fingerprint(&[
            provider.as_str(),
            rule.as_str(),
            &location.file.to_string_lossy(),
            &location.line.to_string(),
            &location.column.to_string(),
            &title,
        ]);
        Finding {
            id,
            provider,
            rule,
            title: title.clone(),
            message: title,
            severity,
            confidence: Confidence::Medium,
            phase: AnalysisPhase::Static,
            location,
            evidence: Vec::new(),
            taxonomy: Vec::new(),
            remediation: None,
            suppressed_by: None,
        }
    }

    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }
    pub fn confidence(mut self, c: Confidence) -> Self {
        self.confidence = c;
        self
    }
    pub fn phase(mut self, p: AnalysisPhase) -> Self {
        self.phase = p;
        self
    }
    pub fn evidence(mut self, e: Evidence) -> Self {
        self.evidence.push(e);
        self
    }
    pub fn taxonomy(mut self, t: TaxonomyRef) -> Self {
        self.taxonomy.push(t);
        self
    }
    pub fn remediation(mut self, r: impl Into<String>) -> Self {
        self.remediation = Some(r.into());
        self
    }

    pub fn is_suppressed(&self) -> bool {
        self.suppressed_by.is_some()
    }

    /// First reference in `scheme`, if any.
    pub fn taxonomy_id(&self, scheme: Taxonomy) -> Option<&str> {
        self.taxonomy.iter().find(|t| t.scheme == scheme).map(|t| t.id.as_str())
    }

    /// True if this finding carries evidence observed at runtime.
    pub fn has_runtime_evidence(&self) -> bool {
        self.evidence.iter().any(|e| e.is_runtime())
    }

    /// Sort key placing the most actionable findings first: highest severity,
    /// then highest confidence, then file position for determinism.
    pub fn triage_key(&self) -> (std::cmp::Reverse<Severity>, std::cmp::Reverse<Confidence>, PathBuf, u32, u32) {
        (
            std::cmp::Reverse(self.severity),
            std::cmp::Reverse(self.confidence),
            self.location.file.clone(),
            self.location.line,
            self.location.column,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f() -> Finding {
        Finding::new(
            "sda.static.c",
            "MISRA-C-2023-15.5",
            "function has more than one point of exit",
            Severity::Low,
            Location::new("src/main.c", 42, 5),
        )
    }

    #[test]
    fn identity_is_stable_across_construction() {
        assert_eq!(f().id, f().id);
    }

    #[test]
    fn two_violations_of_one_rule_in_one_file_are_distinct_findings() {
        // The bug this guards: a shared id makes one correlation verdict apply
        // to every site, and one deviation suppress all of them.
        let a = Finding::new("p", "R", "same title", Severity::Medium, Location::new("a.c", 10, 1));
        let b = Finding::new("p", "R", "same title", Severity::Medium, Location::new("a.c", 40, 1));
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn identity_changes_with_file() {
        let other = Finding::new(
            "sda.static.c",
            "MISRA-C-2023-15.5",
            "function has more than one point of exit",
            Severity::Low,
            Location::new("src/other.c", 42, 5),
        );
        assert_ne!(f().id, other.id);
    }

    /// The MCP surface reports locations with this, and an agent that reads
    /// `src\main.c` on Windows and `src/main.c` elsewhere cannot compare its own
    /// output against the SARIF for the same finding, which is always `/`.
    #[test]
    fn a_displayed_location_uses_uri_separators_on_every_platform() {
        let loc = Location::new(std::path::Path::new("src").join("drivers").join("main.c"), 7, 3);
        assert_eq!(loc.display(), "src/drivers/main.c:7:3");
    }

    /// A pickle opcode has an offset, not a line. Rendering it as `:1:1` sends
    /// the reader to the top of a file with no lines in it, and claims a
    /// position the scanner never had.
    #[test]
    fn a_byte_located_finding_displays_its_offset_not_a_fictional_line() {
        let loc = Location::file_only("model.pkl").at_bytes(0x1030, Some(0x1048));
        assert_eq!(loc.display(), "model.pkl@0x1030");
        assert!(loc.is_byte_located());
        assert_eq!(loc.byte_end, Some(0x1048));

        // Text findings are untouched.
        let text = Location::new("src/main.c", 7, 3);
        assert_eq!(text.display(), "src/main.c:7:3");
        assert!(!text.is_byte_located());
    }

    /// A range that ends at or before it starts is no range, the same guard the
    /// line-based spans use — a zero-width highlight renders worse than none.
    #[test]
    fn a_degenerate_byte_range_keeps_the_offset_and_drops_the_end() {
        assert_eq!(Location::file_only("m.pkl").at_bytes(64, Some(64)).byte_end, None);
        assert_eq!(Location::file_only("m.pkl").at_bytes(64, Some(10)).byte_end, None);
        assert_eq!(Location::file_only("m.pkl").at_bytes(64, Some(96)).byte_end, Some(96));
        // The offset survives in every case; only the extent is in question.
        assert_eq!(Location::file_only("m.pkl").at_bytes(64, Some(10)).byte_start, Some(64));
    }

    #[test]
    fn severity_saturates_at_both_ends() {
        assert_eq!(Severity::Critical.escalate(), Severity::Critical);
        assert_eq!(Severity::Info.deescalate(), Severity::Info);
        assert_eq!(Severity::Medium.escalate(), Severity::High);
    }

    #[test]
    fn overlap_requires_same_file() {
        let a = Location::new("a.c", 10, 1).spanning(20, 1);
        let b = Location::new("a.c", 15, 1);
        let c = Location::new("b.c", 15, 1);
        let d = Location::new("a.c", 21, 1);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
        assert!(!a.overlaps(&d));
    }

    #[test]
    fn triage_orders_critical_before_info() {
        let mut v = [
            Finding::new("p", "r1", "t", Severity::Info, Location::file_only("a.c")),
            Finding::new("p", "r2", "t", Severity::Critical, Location::file_only("a.c")),
        ];
        v.sort_by_key(|f| f.triage_key());
        assert_eq!(v[0].severity, Severity::Critical);
    }
}
