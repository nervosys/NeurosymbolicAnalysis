//! Collapsing findings into one gutter marker per line.
//!
//! Every editor worth the name draws **one glyph per line**: Monaco does, and a
//! native gutter has the same pixel budget. So a line with three findings on it
//! forces a choice, and the choice has to be made deliberately — Monaco's own
//! answer is to draw one of the three and discard the rest, with no rule about
//! which, so a `Critical` could sit invisibly behind an `Info` and the editor
//! silently disagreed with the findings list beside it about how many there
//! were.
//!
//! This module is that choice, made once. It lives here rather than in a shell
//! because *which finding owns a shared line* is an analysis judgement — a
//! defect witnessed at runtime outranks a higher raw severity — and two shells
//! that answered it differently would draw different pictures of the same
//! report. The shells decide how a marker **looks**; this decides what it
//! **says**.

use sda_core::Severity;
use std::collections::BTreeMap;

/// One finding, reduced to what deciding a line's marker actually needs.
///
/// Deliberately not [`sda_core::Finding`]: the correlation verdict that makes a
/// finding "confirmed" lives on the [`sda_core::Report`], not on the finding, so
/// a caller holding both has to resolve it anyway. Taking the resolved answer
/// keeps this function pure and keeps the report out of the editor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkerInput {
    pub file: String,
    pub line: u32,
    pub id: String,
    pub severity: Severity,
    /// Runtime evidence or a `confirmed` correlation verdict.
    pub confirmed: bool,
    /// Suppressed by an approved deviation.
    pub suppressed: bool,
}

/// The marker for one line that has findings on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineMarker {
    pub file: String,
    pub line: u32,
    /// The severity of the finding that owns the line.
    pub severity: Severity,
    /// Whether the owning finding is runtime-confirmed.
    pub confirmed: bool,
    /// True only when *every* finding on the line is suppressed. A line holding
    /// one deviated finding and one live one is not a suppressed line.
    pub suppressed: bool,
    /// How many findings share this line. `1` is the ordinary case.
    pub count: usize,
    /// Every finding on the line, so a hover can list them all rather than
    /// showing whichever one happened to be drawn.
    pub ids: Vec<String>,
}

impl LineMarker {
    /// True when this marker stands for more than the one finding it shows.
    pub fn is_collapsed(&self) -> bool {
        self.count > 1
    }
}

/// How loudly a finding speaks, for deciding which one owns a shared line.
///
/// Confirmed outranks every severity: a defect witnessed at runtime is the
/// strongest claim the toolkit makes, and burying it under an unconfirmed
/// `Critical` would invert the product's whole thesis. Suppressed ranks below
/// everything live, so an approved deviation never hides a real finding.
fn rank(input: &MarkerInput) -> (u8, Severity) {
    let band = if input.suppressed {
        0
    } else if input.confirmed {
        2
    } else {
        1
    };
    (band, input.severity)
}

/// Collapse findings into one marker per line, deliberately and countably.
///
/// Order is stable — by file, then line — because an unstable decoration order
/// makes Monaco's `deltaDecorations` churn, and makes a UI test flaky for
/// reasons that have nothing to do with the analysis.
pub fn line_markers(inputs: &[MarkerInput]) -> Vec<LineMarker> {
    let mut by_line: BTreeMap<(&str, u32), (LineMarker, &MarkerInput)> = BTreeMap::new();

    for input in inputs {
        let key = (input.file.as_str(), input.line);
        match by_line.get_mut(&key) {
            Some((marker, owner)) => {
                marker.count += 1;
                marker.ids.push(input.id.clone());
                // A line is suppressed only if everything on it is.
                marker.suppressed &= input.suppressed;
                if rank(input) > rank(owner) {
                    marker.severity = input.severity;
                    marker.confirmed = input.confirmed;
                    *owner = input;
                }
            }
            None => {
                by_line.insert(
                    key,
                    (
                        LineMarker {
                            file: input.file.clone(),
                            line: input.line,
                            severity: input.severity,
                            confirmed: input.confirmed,
                            suppressed: input.suppressed,
                            count: 1,
                            ids: vec![input.id.clone()],
                        },
                        input,
                    ),
                );
            }
        }
    }

    by_line.into_values().map(|(m, _)| m).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(line: u32, id: &str, severity: Severity) -> MarkerInput {
        MarkerInput {
            file: "a.c".into(),
            line,
            id: id.into(),
            severity,
            confirmed: false,
            suppressed: false,
        }
    }

    #[test]
    fn findings_sharing_a_line_collapse_into_one_marker_that_states_the_count() {
        let m = line_markers(&[
            at(42, "a", Severity::Info),
            at(42, "b", Severity::High),
            at(42, "c", Severity::Medium),
        ]);
        assert_eq!(m.len(), 1, "one line, one glyph");
        assert_eq!(m[0].count, 3, "and it must say there are three");
        assert_eq!(m[0].ids, vec!["a", "b", "c"], "so a hover can list them all");
        assert_eq!(
            m[0].severity,
            Severity::High,
            "the loudest owns the glyph; a high must not hide behind an info"
        );
        assert!(m[0].is_collapsed());
    }

    /// A defect witnessed at runtime is the strongest claim the toolkit makes,
    /// and must own the glyph even against a higher raw severity. Burying it
    /// under an unconfirmed critical inverts the product's thesis.
    #[test]
    fn a_confirmed_finding_owns_the_line_even_against_a_higher_severity() {
        let mut confirmed = at(7, "runtime", Severity::Low);
        confirmed.confirmed = true;
        let m = line_markers(&[at(7, "static", Severity::Critical), confirmed]);
        assert_eq!(m[0].count, 2);
        assert!(m[0].confirmed, "the witnessed defect owns the line");
        assert_eq!(m[0].severity, Severity::Low, "and brings its own severity with it");
    }

    /// A line holding one deviated finding and one live one shows the live one.
    #[test]
    fn an_approved_deviation_never_hides_a_live_finding() {
        let mut dev = at(3, "deviated", Severity::Critical);
        dev.suppressed = true;
        let m = line_markers(&[dev, at(3, "live", Severity::Info)]);
        assert!(!m[0].suppressed, "the line still has something live on it");
        assert_eq!(m[0].severity, Severity::Info, "and the live finding owns it");
    }

    /// But a line where everything is suppressed is a suppressed line, because
    /// that is then the truth about it.
    #[test]
    fn a_line_of_only_deviations_is_a_suppressed_line() {
        let mut a = at(3, "a", Severity::High);
        let mut b = at(3, "b", Severity::Low);
        a.suppressed = true;
        b.suppressed = true;
        let m = line_markers(&[a, b]);
        assert!(m[0].suppressed);
        assert_eq!(m[0].count, 2);
        assert_eq!(m[0].severity, Severity::High, "the worst of them still owns it");
    }

    /// An unstable decoration order makes `deltaDecorations` churn and makes a
    /// UI test flaky for reasons unrelated to the analysis.
    #[test]
    fn markers_are_per_line_per_file_and_stably_ordered() {
        let mut b9 = at(9, "x", Severity::Low);
        b9.file = "b.c".into();
        let m = line_markers(&[b9, at(20, "y", Severity::Low), at(3, "z", Severity::Low)]);
        let seen: Vec<(&str, u32)> = m.iter().map(|x| (x.file.as_str(), x.line)).collect();
        assert_eq!(seen, vec![("a.c", 3), ("a.c", 20), ("b.c", 9)]);
        assert!(m.iter().all(|x| !x.is_collapsed()));
    }

    #[test]
    fn no_findings_means_no_markers() {
        assert!(line_markers(&[]).is_empty());
    }
}
