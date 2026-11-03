//! The shell abstraction.
//!
//! Everything above this trait is analysis; everything below it is pixels. The
//! Tauri shell implements it over the webview IPC bridge; a Dewey shell would
//! implement it over Dewey's widget tree and get the agent protocol for free.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A document open in the workbench.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Document {
    pub path: PathBuf,
    pub text: String,
    pub language: String,
    pub version: u64,
}

/// A finding as the UI needs it: flattened, with the verdict resolved.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UiFinding {
    pub id: String,
    pub rule: String,
    pub severity: String,
    pub confidence: String,
    pub phase: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
    pub message: String,
    /// `confirmed`, `refuted`, `unreached`, ... when correlation reached one.
    pub verdict: Option<String>,
    pub suppressed_by: Option<String>,
    /// CSS class, decided in Rust so both shells agree.
    pub css_class: String,
    /// Runtime evidence, or a `confirmed` correlation verdict.
    ///
    /// Carried explicitly rather than inferred from `css_class`. The class is a
    /// *rendering* of this fact, and reading the fact back out of its own
    /// rendering is lossy the moment a second thing can produce the same class:
    /// a finding that is both confirmed and suppressed renders as suppressed,
    /// and the confirmation would have silently disappeared.
    pub confirmed: bool,
    /// Byte offset, for a finding in a file that has no lines.
    ///
    /// A model artifact finding carries an offset rather than a line, and its
    /// `line`/`column` are the `1`/`1` filler that every `Location` has. Without
    /// this the UI shows "line 1" for an opcode four kilobytes into a pickle,
    /// which is the same fiction the text and SARIF renderings were fixed to
    /// stop telling. `None` for ordinary source findings.
    pub byte_offset: Option<u64>,
    /// The short form, for a list row that cannot afford the full message.
    pub title: String,
    /// Weakness classes, as `CWE-787` and friends.
    pub taxonomy: Vec<String>,
    /// What to do about it, where the rule says.
    pub remediation: Option<String>,
    /// Why correlation reached the verdict it did.
    ///
    /// The strongest claim this toolkit makes is `confirmed`, and until now the
    /// workbench rendered it as a coloured chip and nothing else — a reader could
    /// see the conclusion and had no way to ask what produced it. The rationale
    /// is the sentence the engine already writes for exactly that question.
    pub rationale: Option<String>,
    /// The evidence behind the finding, flattened for display.
    ///
    /// Dataflow paths, runtime events, measured quantities and prover rulings all
    /// arrive here. The engine has always computed them; `UiFinding` simply did
    /// not carry them, so the product's own differentiator could not reach the
    /// screen.
    pub evidence: Vec<UiEvidence>,
    /// Review state, from `.sda/triage.toml`. Shared with agents over MCP.
    pub triage: Option<String>,
    pub triage_note: Option<String>,
    pub triage_by: Option<String>,
    /// Whether this finding is absent from the recorded baseline.
    ///
    /// `None` means no baseline exists, so the question has no answer — which the
    /// UI renders differently from `Some(false)`. Reporting "not new" when nothing
    /// was recorded would be the never-measured-reported-as-clean confusion again.
    pub is_new: Option<bool>,
    /// Who owns this now — a person or an agent, same namespace for both.
    pub assignee: Option<String>,
    /// The discussion, oldest first.
    pub comments: Vec<UiComment>,
}

/// One remark on a finding, as the UI needs it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UiComment {
    pub by: String,
    pub at: String,
    pub text: String,
}

/// One piece of evidence, rendered rather than typed.
///
/// A flat shape on purpose: the webview should not carry a copy of the evidence
/// taxonomy, because a second shell would then need one too and the two would
/// drift. `kind` is for grouping and iconography; everything else is text and
/// positions the UI can act on.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UiEvidence {
    /// `source`, `trace`, `runtime`, `metric`, `model-artifact`, `model-probe`,
    /// `proof`, `note`.
    pub kind: String,
    /// One line naming what this is.
    pub summary: String,
    /// The body, where there is one — source text, a probe response, a ruling.
    pub detail: Option<String>,
    /// Ordered steps, for a dataflow path. Empty for every other kind.
    pub steps: Vec<UiStep>,
}

/// One step of a dataflow path, clickable in the UI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UiStep {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub note: String,
}

/// One glyph-margin marker, as the webview needs it.
///
/// The *policy* — which finding owns a line that several share — is
/// [`sda_editor::line_markers`], not here. It is an analysis judgement (a
/// runtime-confirmed defect outranks a higher raw severity) and a second shell
/// has to reach the same answer, so it lives in the editor crate with the rest
/// of the decoration semantics. This struct is the same decision wearing CSS.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LineMarker {
    pub file: String,
    pub line: u32,
    /// The class of the finding that owns the line.
    pub css_class: String,
    /// How many findings share this line. `1` is the ordinary case.
    pub count: usize,
    /// Every finding on the line, so a hover can list them all rather than
    /// showing whichever one happened to be drawn.
    pub ids: Vec<String>,
}

/// The class for a finding, given the three facts that decide it.
///
/// Shared by [`to_ui`] and [`line_markers`] so a marker can never disagree with
/// the finding it stands for — they used to derive it separately, which is
/// exactly how two renderings of one report drift apart.
fn css_class_for(severity: sda_core::Severity, confirmed: bool, suppressed: bool) -> &'static str {
    if suppressed {
        "sda-suppressed"
    } else if confirmed {
        "sda-confirmed"
    } else {
        match severity {
            sda_core::Severity::Critical | sda_core::Severity::High => "sda-error",
            sda_core::Severity::Medium => "sda-warning",
            _ => "sda-info",
        }
    }
}

/// Collapse findings into one marker per line, then dress the result in CSS.
pub fn line_markers(findings: &[UiFinding]) -> Vec<LineMarker> {
    let inputs: Vec<sda_editor::MarkerInput> = findings
        .iter()
        .map(|f| sda_editor::MarkerInput {
            file: f.file.clone(),
            line: f.line,
            id: f.id.clone(),
            severity: severity_from_str(&f.severity),
            confirmed: f.confirmed,
            suppressed: f.suppressed_by.is_some(),
        })
        .collect();

    sda_editor::line_markers(&inputs)
        .into_iter()
        .map(|m| LineMarker {
            file: m.file,
            line: m.line,
            css_class: css_class_for(m.severity, m.confirmed, m.suppressed).to_string(),
            count: m.count,
            ids: m.ids,
        })
        .collect()
}

/// `UiFinding` carries severity as a string for the webview; this reads it back.
///
/// An unrecognised name becomes `Info` rather than panicking: a stale frontend
/// sending a severity this build does not know should render dimly, not take
/// the window down.
fn severity_from_str(s: &str) -> sda_core::Severity {
    match s {
        "critical" => sda_core::Severity::Critical,
        "high" => sda_core::Severity::High,
        "medium" => sda_core::Severity::Medium,
        "low" => sda_core::Severity::Low,
        _ => sda_core::Severity::Info,
    }
}

/// A line's coverage state, for the gutter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageLine {
    pub line: u32,
    pub hits: u64,
}

/// What a shell must be able to do.
///
/// Unused by the Tauri backend, which satisfies these responsibilities through
/// `#[tauri::command]` functions rather than a trait object. It is defined
/// anyway because it is the contract a Dewey shell implements, and writing it
/// down is what keeps the Tauri commands from quietly growing analysis logic
/// that a second shell could not reproduce.
#[allow(dead_code)]
pub trait Shell {
    fn open_document(&self, path: &std::path::Path) -> Result<Document, String>;
    fn show_findings(&self, findings: &[UiFinding]) -> Result<(), String>;
    fn show_coverage(&self, file: &str, lines: &[CoverageLine]) -> Result<(), String>;
    /// Write a line into the embedded terminal.
    fn terminal_write(&self, text: &str) -> Result<(), String>;
    /// A human-readable status line.
    fn set_status(&self, text: &str) -> Result<(), String>;
}

/// Flatten one piece of evidence for display.
///
/// Deliberately lossy and deliberately here rather than in the webview: this is
/// the only place that knows the evidence taxonomy, so a second shell gets the
/// same rendering by construction instead of by agreement.
fn to_ui_evidence(e: &sda_core::Evidence) -> UiEvidence {
    use sda_core::Evidence as E;
    let (kind, summary, detail, steps) = match e {
        E::Source { location, text, .. } => (
            "source",
            format!("source at {}", location.display()),
            Some(text.clone()),
            Vec::new(),
        ),
        E::Trace { frames } => (
            "trace",
            format!("dataflow path, {} step(s)", frames.len()),
            None,
            frames
                .iter()
                .map(|f| UiStep {
                    file: f.location.file.to_string_lossy().replace('\\', "/"),
                    line: f.location.line,
                    column: f.location.column,
                    note: f.note.clone(),
                })
                .collect(),
        ),
        E::Runtime { event } => (
            "runtime",
            format!("observed at runtime: {:?}", event.kind),
            Some(event.detail.clone()),
            Vec::new(),
        ),
        E::Metric { name, value, unit } => (
            "metric",
            match unit {
                Some(u) => format!("{name}: {value} {u}"),
                None => format!("{name}: {value}"),
            },
            None,
            Vec::new(),
        ),
        E::ModelArtifact { path, format, offset, detail } => (
            "model-artifact",
            match offset {
                Some(o) => format!("{path} ({format}) at offset {o:#x}"),
                None => format!("{path} ({format})"),
            },
            Some(detail.clone()),
            Vec::new(),
        ),
        E::ModelProbe { probe_id, prompt, response, verdict } => (
            "model-probe",
            format!("probe `{probe_id}`: {verdict}"),
            Some(format!("prompt: {prompt}

response: {response}")),
            Vec::new(),
        ),
        E::Proof { obligation, assumptions } => (
            "proof",
            format!("`{}`: {}", obligation.id, obligation.status.as_str()),
            Some(if assumptions.is_empty() {
                obligation.statement.clone()
            } else {
                // The assumptions are the load-bearing half. A ruling shown
                // without what it was granted is evidence for a different claim.
                format!(
                    "{}

granted: {}",
                    obligation.statement,
                    assumptions.join(", ")
                )
            }),
            Vec::new(),
        ),
        E::Note { text } => ("note", text.clone(), None, Vec::new()),
    };
    UiEvidence { kind: kind.to_string(), summary, detail, steps }
}

/// Convert a core finding into its UI form, resolving the verdict and the class.
pub fn to_ui(finding: &sda_core::Finding, report: &sda_core::Report) -> UiFinding {
    to_ui_with_triage(finding, report, None)
}

/// As [`to_ui`], with the project's review state folded in.
pub fn to_ui_with_triage(
    finding: &sda_core::Finding,
    report: &sda_core::Report,
    triage: Option<&sda_rules::TriageStore>,
) -> UiFinding {
    to_ui_full(finding, report, triage, None)
}

/// As [`to_ui`], with review state and the baseline comparison folded in.
pub fn to_ui_full(
    finding: &sda_core::Finding,
    report: &sda_core::Report,
    triage: Option<&sda_rules::TriageStore>,
    baseline: Option<&sda_rules::Baseline>,
) -> UiFinding {
    let correlation = report
        .correlations
        .iter()
        .find(|c| c.static_finding.as_ref() == Some(&finding.id));
    let verdict = correlation.map(|c| c.verdict.as_str().to_string());
    let rationale = correlation.map(|c| c.rationale.clone());

    let record = triage.and_then(|t| t.get(finding.id.as_str()));
    let confirmed = verdict.as_deref() == Some("confirmed") || finding.has_runtime_evidence();
    let css_class = css_class_for(finding.severity, confirmed, finding.is_suppressed());

    UiFinding {
        id: finding.id.to_string(),
        rule: finding.rule.to_string(),
        severity: finding.severity.as_str().to_string(),
        confidence: finding.confidence.as_str().to_string(),
        phase: finding.phase.as_str().to_string(),
        file: finding.location.file.to_string_lossy().replace('\\', "/"),
        line: finding.location.line,
        column: finding.location.column,
        end_line: finding.location.end_line,
        end_column: finding.location.end_column,
        message: finding.message.clone(),
        verdict,
        suppressed_by: finding.suppressed_by.clone(),
        css_class: css_class.to_string(),
        confirmed,
        byte_offset: finding.location.byte_start,
        title: finding.title.clone(),
        taxonomy: finding.taxonomy.iter().map(|t| t.id.clone()).collect(),
        remediation: finding.remediation.clone(),
        rationale,
        evidence: finding.evidence.iter().map(to_ui_evidence).collect(),
        triage: record.map(|r| r.state.as_str().to_string()),
        triage_note: record.and_then(|r| r.note.clone()),
        triage_by: record.and_then(|r| r.by.clone()),
        is_new: sda_rules::baseline::status(baseline, finding.id.as_str()),
        assignee: record.and_then(|r| r.assignee.clone()),
        comments: record
            .map(|r| {
                r.comments
                    .iter()
                    .map(|c| UiComment {
                        by: c.by.clone(),
                        at: c.at.clone(),
                        text: c.text.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::{
        Correlation, CorrelationVerdict, Finding, Location, Report, Severity,
    };

    fn finding(sev: Severity) -> Finding {
        Finding::new("sda.static.c", "MISRA-C-2023-15.6", "t", sev, Location::new("src\\a.c", 4, 2))
    }

    #[test]
    fn a_confirmed_finding_gets_the_confirmed_class_regardless_of_severity() {
        let f = finding(Severity::Low);
        let id = f.id.clone();
        let report = Report::new("/p", vec![f.clone()]).with_correlations(vec![
            Correlation::new(CorrelationVerdict::Confirmed, "seen at runtime").about(id),
        ]);
        let ui = to_ui(&f, &report);
        assert_eq!(ui.css_class, "sda-confirmed");
        assert_eq!(ui.verdict.as_deref(), Some("confirmed"));
    }

    #[test]
    fn severity_drives_the_class_when_there_is_no_verdict() {
        let report = Report::new("/p", vec![]);
        assert_eq!(to_ui(&finding(Severity::High), &report).css_class, "sda-error");
        assert_eq!(to_ui(&finding(Severity::Medium), &report).css_class, "sda-warning");
        assert_eq!(to_ui(&finding(Severity::Info), &report).css_class, "sda-info");
    }

    #[test]
    fn a_suppressed_finding_is_shown_but_de_emphasised() {
        let mut f = finding(Severity::High);
        f.suppressed_by = Some("deviation D-3".into());
        let ui = to_ui(&f, &Report::new("/p", vec![]));
        assert_eq!(ui.css_class, "sda-suppressed");
        assert!(ui.suppressed_by.is_some(), "the justification must reach the UI");
    }

    /// Monaco draws one glyph per line, so three findings on line 42 rendered as
    /// one marker with no indication that the other two existed — the editor
    /// disagreeing with the findings list beside it about how many there were.
    #[test]
    fn findings_sharing_a_line_collapse_into_one_marker_that_states_the_count() {
        let report = Report::new("/p", vec![]);
        let mut a = to_ui(&finding(Severity::Info), &report);
        let mut b = to_ui(&finding(Severity::High), &report);
        let mut c = to_ui(&finding(Severity::Medium), &report);
        a.id = "a".into();
        b.id = "b".into();
        c.id = "c".into();

        let markers = line_markers(&[a, b, c]);
        assert_eq!(markers.len(), 1, "one line, one glyph");
        assert_eq!(markers[0].count, 3, "and it must say there are three");
        assert_eq!(markers[0].ids.len(), 3, "a hover can then list all of them");
        assert_eq!(
            markers[0].css_class, "sda-error",
            "the loudest finding owns the glyph; a high must not hide behind an info"
        );
    }

    /// A defect witnessed at runtime is the strongest claim the toolkit makes,
    /// and must own the glyph even against a higher raw severity.
    #[test]
    fn a_confirmed_finding_owns_the_glyph_it_shares() {
        let f = finding(Severity::Low);
        let id = f.id.clone();
        let report = Report::new("/p", vec![f.clone()]).with_correlations(vec![
            Correlation::new(CorrelationVerdict::Confirmed, "seen at runtime").about(id),
        ]);
        let confirmed = to_ui(&f, &report);
        assert_eq!(confirmed.css_class, "sda-confirmed");

        let critical = to_ui(&finding(Severity::Critical), &Report::new("/p", vec![]));
        let markers = line_markers(&[critical, confirmed]);
        assert_eq!(markers[0].css_class, "sda-confirmed");
        assert_eq!(markers[0].count, 2);
    }

    /// A line holding one deviated finding and one live one shows the live one.
    /// A line where everything is suppressed still shows as suppressed, because
    /// that is then the truth about the line.
    #[test]
    fn suppression_only_owns_a_line_when_it_is_the_whole_story() {
        let report = Report::new("/p", vec![]);
        let mut dev = to_ui(&finding(Severity::High), &report);
        dev.suppressed_by = Some("deviation D-3".into());
        dev.css_class = "sda-suppressed".into();

        let live = to_ui(&finding(Severity::Medium), &report);
        assert_eq!(line_markers(&[dev.clone(), live])[0].css_class, "sda-warning");

        let all_suppressed = line_markers(&[dev.clone(), dev]);
        assert_eq!(all_suppressed[0].css_class, "sda-suppressed");
        assert_eq!(all_suppressed[0].count, 2);
    }

    /// Different lines and different files stay separate, in a stable order —
    /// an unstable decoration order makes `deltaDecorations` churn and makes a
    /// UI test flaky for reasons unrelated to the analysis.
    #[test]
    fn markers_are_per_line_per_file_and_stably_ordered() {
        let report = Report::new("/p", vec![]);
        let mk = |file: &str, line: u32| {
            let mut u = to_ui(&finding(Severity::Low), &report);
            u.file = file.into();
            u.line = line;
            u
        };
        let markers = line_markers(&[mk("b.c", 9), mk("a.c", 20), mk("a.c", 3)]);
        let seen: Vec<(String, u32)> =
            markers.iter().map(|m| (m.file.clone(), m.line)).collect();
        assert_eq!(
            seen,
            vec![("a.c".into(), 3), ("a.c".into(), 20), ("b.c".into(), 9)],
            "sorted by file then line"
        );
        assert!(markers.iter().all(|m| m.count == 1));
    }

    #[test]
    fn no_findings_means_no_markers() {
        assert!(line_markers(&[]).is_empty());
    }

    /// A model-artifact finding has an offset, not a line. Showing "line 1" for
    /// an opcode four kilobytes into a pickle is the fiction the text and SARIF
    /// renderings were already fixed to stop telling.
    #[test]
    fn a_byte_located_finding_carries_its_offset_to_the_ui() {
        let f = Finding::new(
            "sda.ai.artifact",
            "AI-UNSAFE-DESERIALIZATION",
            "t",
            Severity::Critical,
            Location::file_only("model.pkl").at_bytes(0x11a, None),
        );
        let ui = to_ui(&f, &Report::new("/p", vec![]));
        assert_eq!(ui.byte_offset, Some(0x11a));

        // And an ordinary source finding claims no offset.
        assert_eq!(to_ui(&finding(Severity::Low), &Report::new("/p", vec![])).byte_offset, None);
    }

    /// `confirmed` used to be recovered by reading `css_class == "sda-confirmed"`
    /// back out. That is lossy exactly when two facts produce one class: a
    /// finding that is both runtime-confirmed and covered by a deviation renders
    /// as suppressed, and its confirmation vanished. The fact now travels on its
    /// own, so a report can still say the deviated thing was witnessed happening.
    #[test]
    fn a_confirmed_finding_that_is_also_deviated_keeps_both_facts() {
        let mut f = finding(Severity::Low);
        f.suppressed_by = Some("deviation D-7".into());
        let f = f.evidence(sda_core::Evidence::Runtime {
            event: sda_core::RuntimeEvent::new(
                sda_core::RuntimeEventKind::MemoryError,
                "observed out-of-bounds write",
            ),
        });

        let ui = to_ui(&f, &Report::new("/p", vec![]));
        assert_eq!(ui.css_class, "sda-suppressed", "the deviation decides the rendering");
        assert!(ui.confirmed, "but the runtime witness is not thereby forgotten");
        assert!(ui.suppressed_by.is_some());
    }

    #[test]
    fn paths_are_normalised_for_the_frontend() {
        let ui = to_ui(&finding(Severity::Low), &Report::new("/p", vec![]));
        assert_eq!(ui.file, "src/a.c");
    }
}
