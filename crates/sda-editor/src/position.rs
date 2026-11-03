//! Positions, ranges and selections, using Monaco's conventions.
//!
//! Monaco counts lines from 1 and columns from 1, where column 1 is *before* the
//! first character. Getting this wrong by one is the difference between
//! underlining the right token and the one next to it, so the convention is
//! stated here once and tested.

use crate::model::TextModel;
use serde::{Deserialize, Serialize};

/// A caret position. `column` is measured in UTF-16 code units, as Monaco and
/// the Language Server Protocol both do, so that positions round-trip through a
/// JavaScript host unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Position {
    pub line: u32,
    pub column: u32,
}

impl Position {
    /// A position as given, without validation.
    ///
    /// This used to clamp `0` up to `1` on both axes, which looks defensive and
    /// is not: it made line 0 unrepresentable, so [`Position::clamped`] could
    /// never see it, and a finding arriving at line 0 column 12 — what an
    /// off-by-one in an external tool produces — became line 1 column 12 instead
    /// of the start of the file. Monaco's own `Position` holds whatever it is
    /// given and leaves validation to the model, which is the only place that
    /// knows how long the lines are.
    pub fn new(line: u32, column: u32) -> Self {
        Position { line, column }
    }
    pub fn start() -> Self {
        Position { line: 1, column: 1 }
    }
    pub fn is_before(&self, other: &Position) -> bool {
        self < other
    }
    /// Clamp into a model's valid range.
    /// Monaco's `validatePosition`.
    ///
    /// Not a pair of independent clamps, which is what this used to be. A line
    /// number outside the document does not keep its column: Monaco sends a
    /// position above the document to the very start and one below it to the very
    /// end, discarding the column, because a caret that is off the document has
    /// no column to preserve. Clamping the two separately put a finding reported
    /// at line 0, column 12 — which is what an off-by-one in an external tool
    /// produces — at line 1, column 12 instead of the start of the file.
    ///
    /// The surrogate step is the other half: a column that lands between the two
    /// halves of an astral character is moved back before the pair, so no
    /// position ever splits one.
    pub fn clamped(&self, model: &TextModel) -> Position {
        let p = self.clamped_relaxed(model);
        if p.column > 1 {
            let before = model.utf16_unit_at(p.line, (p.column - 2) as usize);
            if before.is_some_and(is_high_surrogate) {
                return Position { line: p.line, column: p.column - 1 };
            }
        }
        p
    }

    /// The same, without the surrogate step — Monaco's `Relaxed` validation.
    ///
    /// `getOffsetAt` uses this and `validatePosition` does not, so the port needs
    /// both. Measuring an offset must not silently move the position it was asked
    /// about; placing a caret must not leave it inside a character.
    pub fn clamped_relaxed(&self, model: &TextModel) -> Position {
        let line_count = model.line_count();
        if self.line < 1 {
            return Position { line: 1, column: 1 };
        }
        if self.line > line_count {
            return Position { line: line_count, column: model.line_length(line_count) + 1 };
        }
        if self.column <= 1 {
            return Position { line: self.line, column: 1 };
        }
        let max_col = model.line_length(self.line) + 1;
        Position { line: self.line, column: self.column.min(max_col) }
    }
}

/// The leading half of a UTF-16 surrogate pair.
fn is_high_surrogate(unit: u16) -> bool {
    (0xD800..0xDC00).contains(&unit)
}

/// A half-open span between two positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

impl Range {
    /// Build a range, normalising a reversed pair so `start <= end` always holds.
    pub fn new(start: Position, end: Position) -> Self {
        if end < start { Range { start: end, end: start } } else { Range { start, end } }
    }
    pub fn empty(at: Position) -> Self {
        Range { start: at, end: at }
    }
    pub fn line(line: u32, model: &TextModel) -> Self {
        Range::new(Position::new(line, 1), Position::new(line, model.line_length(line) + 1))
    }
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
    pub fn is_single_line(&self) -> bool {
        self.start.line == self.end.line
    }
    pub fn contains(&self, p: Position) -> bool {
        p >= self.start && p < self.end
    }
    pub fn contains_range(&self, other: &Range) -> bool {
        other.start >= self.start && other.end <= self.end
    }
    pub fn intersects(&self, other: &Range) -> bool {
        self.start < other.end && other.start < self.end
    }
    /// The smallest range covering both.
    pub fn union(&self, other: &Range) -> Range {
        Range {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
    /// Monaco's `validateRange`.
    ///
    /// Both ends are validated *without* the surrogate step and then the range is
    /// **expanded** outward over any pair an end would have split — never pulled
    /// inward. Validating each end on its own, which is what this used to do,
    /// moves an end backwards into the middle of the range and can collapse it;
    /// on a line with an emoji before the finding, the workbench drew a
    /// highlight one code unit short and ending inside a character.
    ///
    /// An empty range is moved rather than expanded, because expanding it would
    /// turn a caret into a selection.
    pub fn clamped(&self, model: &TextModel) -> Range {
        let start = self.start.clamped_relaxed(model);
        let end = self.end.clamped_relaxed(model);

        let splits = |p: Position, cap: bool| -> bool {
            if p.column <= 1 || (cap && p.column > model.line_length(p.line)) {
                return false;
            }
            model.utf16_unit_at(p.line, (p.column - 2) as usize).is_some_and(is_high_surrogate)
        };
        let start_splits = splits(start, false);
        let end_splits = splits(end, true);

        if !start_splits && !end_splits {
            return Range::new(start, end);
        }
        if start == end {
            let back = Position { line: start.line, column: start.column - 1 };
            return Range::new(back, back);
        }
        let s = if start_splits {
            Position { line: start.line, column: start.column - 1 }
        } else {
            start
        };
        let e =
            if end_splits { Position { line: end.line, column: end.column + 1 } } else { end };
        Range::new(s, e)
    }
}

/// A selection: a range plus which end the caret is at, which determines what
/// happens when the user extends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    pub anchor: Position,
    pub active: Position,
}

impl Selection {
    pub fn new(anchor: Position, active: Position) -> Self {
        Selection { anchor, active }
    }
    pub fn caret(at: Position) -> Self {
        Selection { anchor: at, active: at }
    }
    pub fn range(&self) -> Range {
        Range::new(self.anchor, self.active)
    }
    pub fn is_empty(&self) -> bool {
        self.anchor == self.active
    }
    /// True when the caret is before the anchor, i.e. selected backwards.
    pub fn is_reversed(&self) -> bool {
        self.active < self.anchor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> TextModel {
        TextModel::new("hello\nworld wide\n\nlast\n")
    }

    /// Construction holds what it is given; validation is the model's job.
    ///
    /// This test used to assert the opposite — that `Position::new(0, 0)` *is*
    /// `(1, 1)` — which made line 0 unrepresentable and so unvalidatable. Monaco
    /// sends a position above the document to the very start, discarding the
    /// column; clamping in the constructor kept the column and put a finding
    /// reported at line 0 column 12 eleven columns into line 1. See
    /// `tests/model_layer_agrees_with_monaco.rs`.
    #[test]
    fn construction_does_not_validate_and_validation_is_monacos() {
        let p = Position::new(0, 0);
        assert_eq!((p.line, p.column), (0, 0), "held as given");
        assert_eq!(p.clamped(&model()), Position::start(), "and validated to the document start");
        assert_eq!(Position::start(), Position::new(1, 1));
    }

    #[test]
    fn ranges_normalise_a_reversed_pair() {
        let r = Range::new(Position::new(3, 1), Position::new(1, 1));
        assert_eq!(r.start, Position::new(1, 1));
        assert_eq!(r.end, Position::new(3, 1));
    }

    #[test]
    fn containment_is_half_open() {
        let r = Range::new(Position::new(1, 1), Position::new(1, 5));
        assert!(r.contains(Position::new(1, 1)));
        assert!(r.contains(Position::new(1, 4)));
        assert!(!r.contains(Position::new(1, 5)), "the end is exclusive");
    }

    #[test]
    fn intersection_and_containment_are_distinct() {
        let a = Range::new(Position::new(1, 1), Position::new(1, 10));
        let b = Range::new(Position::new(1, 5), Position::new(1, 20));
        let c = Range::new(Position::new(1, 3), Position::new(1, 6));
        assert!(a.intersects(&b));
        assert!(!a.contains_range(&b));
        assert!(a.contains_range(&c));
    }

    #[test]
    fn adjacent_ranges_do_not_intersect() {
        let a = Range::new(Position::new(1, 1), Position::new(1, 5));
        let b = Range::new(Position::new(1, 5), Position::new(1, 9));
        assert!(!a.intersects(&b));
    }

    #[test]
    fn a_line_range_spans_to_one_past_the_last_character() {
        let m = model();
        let r = Range::line(2, &m);
        assert_eq!(r.start, Position::new(2, 1));
        assert_eq!(r.end, Position::new(2, 11), "`world wide` is 10 columns wide");
    }

    #[test]
    fn an_empty_line_yields_an_empty_range() {
        let m = model();
        assert!(Range::line(3, &m).is_empty());
    }

    #[test]
    fn clamping_pulls_a_stale_position_into_the_buffer() {
        let m = model();
        // The last line is the empty one the trailing newline opens, as Monaco
        // counts it, so a runaway position lands at its only column.
        assert_eq!(Position::new(99, 99).clamped(&m), Position::new(5, 1));
        assert_eq!(Position::new(1, 99).clamped(&m), Position::new(1, 6));
    }

    #[test]
    fn selections_know_their_direction() {
        let forward = Selection::new(Position::new(1, 1), Position::new(2, 3));
        let backward = Selection::new(Position::new(2, 3), Position::new(1, 1));
        assert!(!forward.is_reversed());
        assert!(backward.is_reversed());
        assert_eq!(forward.range(), backward.range(), "the covered text is the same");
    }

    #[test]
    fn a_caret_is_an_empty_selection() {
        let s = Selection::caret(Position::new(2, 4));
        assert!(s.is_empty());
        assert!(s.range().is_empty());
    }

    #[test]
    fn union_covers_both_operands() {
        let a = Range::new(Position::new(1, 1), Position::new(1, 5));
        let b = Range::new(Position::new(3, 2), Position::new(3, 4));
        let u = a.union(&b);
        assert!(u.contains_range(&a) && u.contains_range(&b));
    }
}
