//! Decorations, and how they survive edits.
//!
//! A decoration marks a range: a diagnostic squiggle, a coverage stripe, a
//! confirmed-defect highlight. Its hard problem is *stickiness* — what happens
//! to the range when the text around it changes. Monaco names four policies, and
//! choosing correctly is what stops a finding from drifting onto the wrong line
//! after an unrelated edit above it.

use crate::model::ChangeEvent;
use crate::position::{Position, Range};
use sda_core::Severity;
use serde::{Deserialize, Serialize};

/// How a decoration's range reacts to text inserted at its boundaries.
///
/// The variants carry Monaco's names, so they carry Monaco's meanings. Two of
/// these doc comments used to describe the opposite of what Monaco does, and the
/// code implemented a third thing again — `NeverGrowsWhenTypingAtEdges` and
/// `GrowsOnlyWhenTypingBefore` were indistinguishable, because stickiness was
/// only ever consulted at the end edge. Captured from Monaco's own
/// `nodeAcceptEdit` in `tests/fixtures/monaco-stickiness.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stickiness {
    /// Text typed at the **start** is absorbed; at the end it is not.
    ///
    /// The right default for a diagnostic: a squiggle keeps its anchor when
    /// someone types in front of it, and does not swallow what is typed after.
    GrowsOnlyWhenTypingBefore,
    /// Text typed at **either** edge is absorbed.
    AlwaysGrowsWhenTypingAtEdges,
    /// Text typed at **neither** edge is absorbed: the range is pushed along
    /// ahead of an insertion at its start, and stops short of one at its end.
    NeverGrowsWhenTypingAtEdges,
}

impl Stickiness {
    /// Whether an insertion exactly at the range's start is absorbed.
    fn grows_at_start(self) -> bool {
        matches!(
            self,
            Stickiness::AlwaysGrowsWhenTypingAtEdges | Stickiness::GrowsOnlyWhenTypingBefore
        )
    }

    /// Whether an insertion exactly at the range's end is absorbed.
    fn grows_at_end(self) -> bool {
        matches!(self, Stickiness::AlwaysGrowsWhenTypingAtEdges)
    }
}

/// What a decoration represents.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DecorationKind {
    /// An analysis finding.
    Diagnostic {
        severity: Severity,
        /// Whether runtime evidence confirmed it — rendered differently, because
        /// a confirmed defect and a suspicion warrant different attention.
        confirmed: bool,
    },
    /// A line the dynamic run executed, with its hit count.
    Covered { hits: u64 },
    /// A line no run reached. The visual counterpart of an `Unreached` verdict.
    Uncovered,
    /// A finding that an approved deviation silences, shown but de-emphasised.
    Suppressed,
    /// A generic highlight, e.g. a search match.
    Highlight,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Decoration {
    pub id: String,
    pub range: Range,
    pub kind: DecorationKind,
    pub message: String,
    pub stickiness: Stickiness,
    /// Provider that produced it, for filtering in the UI.
    pub source: String,
}

impl Decoration {
    /// CSS class the shell renders this with. Kept here rather than in the
    /// frontend so a native renderer and the webview agree.
    pub fn css_class(&self) -> &'static str {
        match &self.kind {
            DecorationKind::Diagnostic { confirmed: true, .. } => "sda-confirmed",
            DecorationKind::Diagnostic { severity, .. } => match severity {
                Severity::Critical | Severity::High => "sda-error",
                Severity::Medium => "sda-warning",
                _ => "sda-info",
            },
            DecorationKind::Covered { .. } => "sda-covered",
            DecorationKind::Uncovered => "sda-uncovered",
            DecorationKind::Suppressed => "sda-suppressed",
            DecorationKind::Highlight => "sda-highlight",
        }
    }

    /// Sort order for overlapping decorations: the most important renders on top.
    pub fn z_order(&self) -> u8 {
        match &self.kind {
            DecorationKind::Diagnostic { confirmed: true, .. } => 5,
            DecorationKind::Diagnostic { severity, .. } => match severity {
                Severity::Critical | Severity::High => 4,
                Severity::Medium => 3,
                _ => 2,
            },
            DecorationKind::Suppressed => 1,
            _ => 0,
        }
    }
}

/// Update a decoration's range for a change, or drop it if the change destroyed
/// the text it marked.
///
/// Returns `None` when the decoration should be removed — which is the honest
/// outcome when its text is gone. Keeping a stale diagnostic anchored to
/// whatever moved into that position is worse than losing it, because it points
/// a reviewer at code that has nothing to do with the finding.
pub fn adjust(decoration: &Decoration, change: &ChangeEvent) -> Option<Decoration> {
    let edit = change.range;
    let mut d = decoration.clone();

    // An edit that swallowed the decoration entirely destroys it.
    if edit.contains_range(&d.range) && !edit.is_empty() {
        return None;
    }

    let line_delta = change.line_delta();

    // An insertion exactly at the decoration's start. Whether the decoration
    // keeps its anchor or is pushed along is the whole of what stickiness means
    // at this edge, and it used to be unasked: this fell into the branch below,
    // which shifts everything, so a range that Monaco grows was moved instead —
    // and `GrowsOnlyWhenTypingBefore`, whose entire purpose is this case, behaved
    // exactly like `NeverGrowsWhenTypingAtEdges`.
    if edit.is_empty()
        && !change.inserted.is_empty()
        && edit.start == d.range.start
        && d.stickiness.grows_at_start()
    {
        d.range = Range::new(d.range.start, shift_end(d.range, change));
        return Some(d);
    }

    // Wholly after the edit: shift by the line delta, and adjust the column too
    // when the decoration is on the edit's last line.
    if d.range.start >= edit.end {
        let same_line = d.range.start.line == edit.end.line;
        let column_delta: i64 = if same_line {
            change.new_range.end.column as i64 - edit.end.column as i64
        } else {
            0
        };
        d.range = shift(d.range, line_delta, if same_line { column_delta } else { 0 }, same_line);
        return Some(d);
    }

    // Wholly before the edit: untouched, unless stickiness says otherwise.
    if d.range.end <= edit.start {
        if d.range.end == edit.start && d.stickiness.grows_at_end() && !change.inserted.is_empty()
        {
            d.range.end = change.new_range.end;
        }
        return Some(d);
    }

    // Overlapping: keep the anchor and clamp the far end to the edit's start.
    // The decoration is now approximate, so a consumer that cares can compare
    // versions and re-run analysis.
    if d.range.start < edit.start {
        d.range = Range::new(d.range.start, edit.start.max(d.range.start));
        return Some(d);
    }

    // The decoration starts inside the edit: it no longer marks what it meant.
    None
}

/// Where a range's end lands after an insertion at its start, when the start
/// itself stays put.
fn shift_end(range: Range, change: &ChangeEvent) -> Position {
    let edit = change.range;
    let line_delta = change.line_delta();
    let same_line = range.end.line == edit.end.line;
    let column_delta: i64 = if same_line {
        change.new_range.end.column as i64 - edit.end.column as i64
    } else {
        0
    };
    Position::new(
        (range.end.line as i64 + line_delta).max(1) as u32,
        if same_line { (range.end.column as i64 + column_delta).max(1) as u32 } else { range.end.column },
    )
}

fn shift(range: Range, line_delta: i64, column_delta: i64, same_line_only: bool) -> Range {
    let apply = |p: Position, adjust_column: bool| Position::new(
        (p.line as i64 + line_delta).max(1) as u32,
        if adjust_column { (p.column as i64 + column_delta).max(1) as u32 } else { p.column },
    );
    Range::new(
        apply(range.start, same_line_only),
        apply(range.end, same_line_only && range.is_single_line()),
    )
}

/// Adjust a whole set, dropping those the change invalidated.
pub fn adjust_all(decorations: &[Decoration], change: &ChangeEvent) -> Vec<Decoration> {
    decorations.iter().filter_map(|d| adjust(d, change)).collect()
}

/// Build coverage decorations from a dynamic run's observation.
pub fn coverage_decorations(
    file: &str,
    covered_lines: &[(u32, u64)],
    total_lines: u32,
) -> Vec<Decoration> {
    let mut out = Vec::new();
    for line in 1..=total_lines {
        let hits = covered_lines.iter().find(|(l, _)| *l == line).map(|(_, n)| *n);
        let (kind, message) = match hits {
            Some(n) => (
                DecorationKind::Covered { hits: n },
                format!("executed {n} time(s)"),
            ),
            None => (
                DecorationKind::Uncovered,
                "never executed: any static finding here is untested, not clean".to_string(),
            ),
        };
        out.push(Decoration {
            id: format!("cov:{file}:{line}"),
            range: Range::new(Position::new(line, 1), Position::new(line, 1)),
            kind,
            message,
            stickiness: Stickiness::NeverGrowsWhenTypingAtEdges,
            source: "sda.dynamic".into(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{TextEdit, TextModel};

    fn decoration(start: (u32, u32), end: (u32, u32)) -> Decoration {
        Decoration {
            id: "d1".into(),
            range: Range::new(Position::new(start.0, start.1), Position::new(end.0, end.1)),
            kind: DecorationKind::Diagnostic { severity: Severity::High, confirmed: false },
            message: "m".into(),
            stickiness: Stickiness::GrowsOnlyWhenTypingBefore,
            source: "sda.static.c".into(),
        }
    }

    fn model() -> TextModel {
        TextModel::new("line one\nline two\nline three\nline four\n")
    }

    #[test]
    fn a_decoration_after_an_inserted_line_moves_down() {
        let mut m = model();
        let d = decoration((3, 1), (3, 5));
        let change = m.apply(&TextEdit::insert(Position::new(1, 1), "new\n"));
        let moved = adjust(&d, &change).unwrap();
        assert_eq!(moved.range.start.line, 4);
        assert_eq!(moved.range.end.line, 4);
    }

    #[test]
    fn a_decoration_before_an_edit_is_untouched() {
        let mut m = model();
        let d = decoration((1, 1), (1, 5));
        let change = m.apply(&TextEdit::insert(Position::new(3, 1), "x"));
        assert_eq!(adjust(&d, &change).unwrap().range, d.range);
    }

    #[test]
    fn deleting_lines_moves_later_decorations_up() {
        let mut m = model();
        let d = decoration((4, 1), (4, 5));
        let change = m.apply(&TextEdit::delete(Range::new(
            Position::new(1, 1),
            Position::new(2, 1),
        )));
        assert_eq!(adjust(&d, &change).unwrap().range.start.line, 3);
    }

    #[test]
    fn a_decoration_whose_text_was_deleted_is_dropped_not_left_pointing_elsewhere() {
        let mut m = model();
        let d = decoration((2, 1), (2, 5));
        let change = m.apply(&TextEdit::delete(Range::new(
            Position::new(1, 1),
            Position::new(3, 1),
        )));
        assert!(
            adjust(&d, &change).is_none(),
            "a stale diagnostic pointing at unrelated code is worse than none"
        );
    }

    #[test]
    fn an_edit_overlapping_the_start_of_a_decoration_drops_it() {
        let mut m = model();
        let d = decoration((2, 3), (2, 8));
        let change = m.apply(&TextEdit::replace(
            Range::new(Position::new(2, 1), Position::new(2, 5)),
            "X",
        ));
        assert!(adjust(&d, &change).is_none());
    }

    #[test]
    fn an_edit_overlapping_the_end_truncates_rather_than_dropping() {
        let mut m = model();
        let d = decoration((2, 1), (2, 8));
        let change = m.apply(&TextEdit::replace(
            Range::new(Position::new(2, 5), Position::new(2, 9)),
            "Z",
        ));
        let kept = adjust(&d, &change).unwrap();
        assert_eq!(kept.range.start, Position::new(2, 1), "the anchor is preserved");
        assert!(kept.range.end.column <= 5);
    }

    #[test]
    fn typing_before_a_diagnostic_does_not_extend_it() {
        let mut m = model();
        let d = decoration((2, 5), (2, 9));
        let width = d.range.end.column - d.range.start.column;
        let change = m.apply(&TextEdit::insert(Position::new(2, 1), "ab"));
        let moved = adjust(&d, &change).unwrap();
        assert_eq!(moved.range.end.column - moved.range.start.column, width);
    }

    #[test]
    fn always_growing_stickiness_absorbs_text_typed_at_the_end() {
        let mut m = model();
        let mut d = decoration((2, 1), (2, 5));
        d.stickiness = Stickiness::AlwaysGrowsWhenTypingAtEdges;
        let change = m.apply(&TextEdit::insert(Position::new(2, 5), "XY"));
        assert!(adjust(&d, &change).unwrap().range.end.column > 5);
    }

    #[test]
    fn confirmed_findings_render_and_stack_above_suspicions() {
        let suspicion = decoration((1, 1), (1, 2));
        let mut confirmed = suspicion.clone();
        confirmed.kind = DecorationKind::Diagnostic { severity: Severity::High, confirmed: true };
        assert_eq!(suspicion.css_class(), "sda-error");
        assert_eq!(confirmed.css_class(), "sda-confirmed");
        assert!(confirmed.z_order() > suspicion.z_order());
    }

    #[test]
    fn suppressed_findings_render_below_everything_else() {
        let mut d = decoration((1, 1), (1, 2));
        d.kind = DecorationKind::Suppressed;
        assert!(d.z_order() < decoration((1, 1), (1, 2)).z_order());
    }

    #[test]
    fn coverage_decorations_mark_unexecuted_lines_with_what_that_means() {
        let d = coverage_decorations("a.c", &[(1, 5), (3, 2)], 4);
        assert_eq!(d.len(), 4);
        assert!(matches!(d[0].kind, DecorationKind::Covered { hits: 5 }));
        assert!(matches!(d[1].kind, DecorationKind::Uncovered));
        assert!(d[1].message.contains("untested, not clean"));
    }

    #[test]
    fn adjusting_a_set_drops_only_the_invalidated_members() {
        let mut m = model();
        let set = vec![decoration((1, 1), (1, 4)), decoration((3, 1), (3, 4))];
        let change = m.apply(&TextEdit::delete(Range::new(
            Position::new(3, 1),
            Position::new(4, 1),
        )));
        let after = adjust_all(&set, &change);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].range.start.line, 1);
    }
}
