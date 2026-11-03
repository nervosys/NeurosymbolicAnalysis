//! The text model: a rope-backed buffer with versioned edits.

use crate::position::{Position, Range};
use ropey::Rope;
use serde::{Deserialize, Serialize};

/// A replacement of `range` with `text`. Deleting is an edit with empty text;
/// inserting is an edit with an empty range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextEdit {
    pub range: Range,
    pub text: String,
}

impl TextEdit {
    pub fn replace(range: Range, text: impl Into<String>) -> Self {
        TextEdit { range, text: text.into() }
    }
    pub fn insert(at: Position, text: impl Into<String>) -> Self {
        TextEdit { range: Range::empty(at), text: text.into() }
    }
    pub fn delete(range: Range) -> Self {
        TextEdit { range, text: String::new() }
    }
    pub fn is_insertion(&self) -> bool {
        self.range.is_empty()
    }
    pub fn is_deletion(&self) -> bool {
        self.text.is_empty() && !self.range.is_empty()
    }
}

/// What one applied edit did, emitted so views and decorations can react.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeEvent {
    pub range: Range,
    /// Text that was there before.
    pub removed: String,
    /// Text that is there now.
    pub inserted: String,
    /// Model version after the change.
    pub version: u64,
    /// Range covering the text after the edit, for the view to repaint.
    pub new_range: Range,
}

impl ChangeEvent {
    /// Net change in line count.
    pub fn line_delta(&self) -> i64 {
        let before = self.removed.matches('\n').count() as i64;
        let after = self.inserted.matches('\n').count() as i64;
        after - before
    }
}

/// A text buffer with the operations an editor and an analyzer both need.
#[derive(Clone, Debug)]
pub struct TextModel {
    rope: Rope,
    version: u64,
    /// Language id, used to pick a lexer.
    pub language: sda_core::Language,
    /// Set when the buffer differs from what was last read from or written to disk.
    pub dirty: bool,
}

impl TextModel {
    pub fn new(text: &str) -> Self {
        TextModel {
            rope: Rope::from_str(text),
            version: 1,
            language: sda_core::Language::Unknown,
            dirty: false,
        }
    }

    pub fn with_language(mut self, language: sda_core::Language) -> Self {
        self.language = language;
        self
    }

    /// Load a file, inferring the language from its extension.
    pub fn from_path(path: &std::path::Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(TextModel::new(&text).with_language(sda_core::Language::from_path(path)))
    }

    pub fn text(&self) -> String {
        self.rope.to_string()
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn len_chars(&self) -> usize {
        self.rope.len_chars()
    }
    pub fn is_empty(&self) -> bool {
        self.rope.len_chars() == 0
    }

    /// Number of lines, **counting the empty line a trailing newline opens**.
    ///
    /// This used to subtract that line, on the reasoning that "a trailing
    /// newline does not create a phantom line, as every editor presents it".
    /// Monaco — the editor this is a port of — presents it: "a\n" is two lines,
    /// and the second is where the cursor sits when you press End on a file
    /// that ends properly. Captured from Monaco 0.52.2 in
    /// `tests/fixtures/monaco-answers.json`, which disagreed with this on the
    /// most ordinary input there is: a three-line C file ending in a newline.
    ///
    /// An empty buffer is still one line, which is also what Monaco says.
    pub fn line_count(&self) -> u32 {
        (self.rope.len_lines() as u32).max(1)
    }

    /// Text of a 1-based line, without its terminator.
    pub fn line(&self, line: u32) -> String {
        if line == 0 || line > self.line_count() {
            return String::new();
        }
        self.rope
            .line((line - 1) as usize)
            .to_string()
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string()
    }

    /// Length of a 1-based line **in UTF-16 code units**, excluding its
    /// terminator.
    ///
    /// Not characters. `Position` documents its column as UTF-16 "so that
    /// positions round-trip through a JavaScript host unchanged", and this
    /// counted `chars()` — so on any line holding an astral character, an emoji
    /// or a rarer CJK glyph, every column past it was short by one per such
    /// character. The doc was right and the code was wrong: Monaco measures
    /// "a😀b" as 4 and this said 3.
    pub fn line_length(&self, line: u32) -> u32 {
        self.line(line).encode_utf16().count() as u32
    }

    /// The UTF-16 code unit at a zero-based index in a line, as Monaco's
    /// `getLineCharCode`. `None` past the end of the line.
    pub fn utf16_unit_at(&self, line: u32, index: usize) -> Option<u16> {
        self.line(line).encode_utf16().nth(index)
    }

    /// UTF-16 code-unit offset of a position, as Monaco's `getOffsetAt`.
    ///
    /// Validated the way `getOffsetAt` validates — `Relaxed`, without the
    /// surrogate step — because measuring where a position is must not move it.
    pub fn offset_of(&self, p: Position) -> usize {
        let p = p.clamped_relaxed(self);
        let line_start = self.rope.line_to_char((p.line - 1) as usize);
        self.rope.char_to_utf16_cu(line_start) + (p.column - 1) as usize
    }

    /// Position of a UTF-16 code-unit offset, as Monaco's `getPositionAt`.
    pub fn position_of(&self, offset: usize) -> Position {
        let offset = offset.min(self.rope.len_utf16_cu());
        let char_idx = self.rope.utf16_cu_to_char(offset);
        let line = self.rope.char_to_line(char_idx);
        let line_start = self.rope.line_to_char(line);
        let column = offset - self.rope.char_to_utf16_cu(line_start);
        Position::new(line as u32 + 1, column as u32 + 1)
    }

    /// Length of the whole document in UTF-16 code units, as Monaco's
    /// `getValueLength`.
    pub fn len_utf16(&self) -> usize {
        self.rope.len_utf16_cu()
    }

    /// A range's text.
    ///
    /// Offsets arrive in UTF-16 and the rope slices by character, so the
    /// conversion happens here rather than at each caller: slicing a rope with a
    /// UTF-16 index silently returns the wrong text whenever anything above the
    /// BMP precedes it.
    pub fn text_in(&self, range: Range) -> String {
        // Validated as a range, not as two positions: Monaco's `getValueInRange`
        // calls `validateRange`, which expands over a surrogate pair rather than
        // slicing through one.
        let range = range.clamped(self);
        let start = self.offset_of(range.start);
        let end = self.offset_of(range.end).max(start);
        let (start, end) = (self.rope.utf16_cu_to_char(start), self.rope.utf16_cu_to_char(end));
        self.rope.slice(start..end).to_string()
    }

    /// Apply one edit, returning what changed.
    pub fn apply(&mut self, edit: &TextEdit) -> ChangeEvent {
        let range = edit.range.clamped(self);
        // Positions and offsets are UTF-16; the rope indexes by character. Every
        // conversion happens here, once, because mixing the two silently edits
        // the wrong span as soon as anything above the BMP precedes the range.
        let start_cu = self.offset_of(range.start);
        let end_cu = self.offset_of(range.end).max(start_cu);
        let start = self.rope.utf16_cu_to_char(start_cu);
        let end = self.rope.utf16_cu_to_char(end_cu);
        let removed = self.rope.slice(start..end).to_string();

        if end > start {
            self.rope.remove(start..end);
        }
        if !edit.text.is_empty() {
            self.rope.insert(start, &edit.text);
        }

        self.version += 1;
        self.dirty = true;
        let new_end = self.position_of(start_cu + edit.text.encode_utf16().count());

        ChangeEvent {
            range,
            removed,
            inserted: edit.text.clone(),
            version: self.version,
            new_range: Range::new(range.start, new_end),
        }
    }

    /// Apply several edits as one atomic change.
    ///
    /// Edits are applied last-first so that each one's positions still refer to
    /// the text the caller was looking at. Applying them in the given order
    /// would invalidate every position after the first edit — the classic
    /// multi-cursor bug.
    pub fn apply_all(&mut self, edits: &[TextEdit]) -> Vec<ChangeEvent> {
        let mut sorted: Vec<&TextEdit> = edits.iter().collect();
        sorted.sort_by_key(|e| std::cmp::Reverse(e.range.start));

        // Overlapping edits have no well-defined joint meaning; refuse rather
        // than silently producing whichever result the ordering happens to give.
        for pair in sorted.windows(2) {
            if pair[0].range.start < pair[1].range.end && pair[1].range.start < pair[0].range.end {
                return Vec::new();
            }
        }

        sorted.into_iter().map(|e| self.apply(e)).collect()
    }

    /// Replace the whole buffer, e.g. after a reload from disk.
    ///
    /// Works on offsets rather than a position range: a range ending at the last
    /// line's last column stops *before* a trailing newline, which would leave
    /// one behind on every reload.
    pub fn set_text(&mut self, text: &str) -> ChangeEvent {
        let removed = self.rope.to_string();
        let old_end = self.position_of(self.rope.len_chars());

        self.rope = Rope::from_str(text);
        self.version += 1;
        self.dirty = false;

        ChangeEvent {
            range: Range::new(Position::start(), old_end),
            removed,
            inserted: text.to_string(),
            version: self.version,
            new_range: Range::new(Position::start(), self.position_of(self.rope.len_chars())),
        }
    }

    pub fn mark_saved(&mut self) {
        self.dirty = false;
    }

    /// Lex this buffer with the native front-end for its language, so the editor
    /// and the analyzer always agree about what a token is.
    pub fn tokens(&self) -> Vec<(usize, usize, &'static str)> {
        let text = self.text();
        match self.language {
            sda_core::Language::C | sda_core::Language::Cpp => {
                let dialect = if self.language == sda_core::Language::Cpp {
                    sda_syntax::Dialect::Cpp23
                } else {
                    sda_syntax::Dialect::C23
                };
                sda_syntax::lex(&text, dialect)
                    .tokens
                    .iter()
                    .map(|t| (t.span.start, t.span.end, c_token_class(t.kind)))
                    .collect()
            }
            sda_core::Language::Rust => sda_syntax::lex_rust(&text)
                .tokens
                .iter()
                .map(|t| (t.span.start, t.span.end, rust_token_class(t.kind)))
                .collect(),
            _ => Vec::new(),
        }
    }
}

fn c_token_class(k: sda_syntax::CTokenKind) -> &'static str {
    use sda_syntax::CTokenKind as K;
    match k {
        K::Keyword => "keyword",
        K::Identifier => "identifier",
        K::Number => "number",
        K::String | K::Char | K::RawString => "string",
        K::LineComment | K::BlockComment => "comment",
        K::Directive => "directive",
        K::Punct => "operator",
        K::Unknown => "invalid",
    }
}

fn rust_token_class(k: sda_syntax::RTokenKind) -> &'static str {
    use sda_syntax::RTokenKind as K;
    match k {
        K::Keyword => "keyword",
        K::Identifier => "identifier",
        K::Number => "number",
        K::String | K::RawString | K::ByteString | K::Char => "string",
        K::LineComment | K::BlockComment => "comment",
        K::DocComment => "doc",
        K::Attribute => "attribute",
        K::Lifetime => "lifetime",
        K::Punct => "operator",
        K::Unknown => "invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> TextModel {
        TextModel::new("first\nsecond\nthird\n")
    }

    /// **This assertion used to be the other way round.** It expected a trailing
    /// newline *not* to open a final line, on the reasoning that no editor shows
    /// one. Monaco shows one — it is where the cursor sits when you press End on
    /// a file that ends properly — and Monaco is what this crate is a port of.
    /// Captured in `tests/fixtures/monaco-answers.json` and asserted by
    /// `tests/agrees_with_monaco.rs`, which caught this on a three-line C file.
    #[test]
    fn a_trailing_newline_opens_a_final_empty_line_as_monaco_does() {
        assert_eq!(model().line_count(), 4, "first, second, third, and the empty one");
        assert_eq!(model().line(4), "");
        assert_eq!(TextModel::new("one").line_count(), 1, "no terminator, no extra line");
        assert_eq!(TextModel::new("").line_count(), 1, "an empty buffer has one line");
        assert_eq!(TextModel::new("a\nb").line_count(), 2);
        assert_eq!(TextModel::new("a\n").line_count(), 2);
    }

    #[test]
    fn positions_and_offsets_round_trip() {
        let m = model();
        for offset in 0..m.len_chars() {
            let p = m.position_of(offset);
            assert_eq!(m.offset_of(p), offset, "offset {offset} did not round-trip");
        }
    }

    #[test]
    fn line_text_excludes_terminators() {
        let m = TextModel::new("a\r\nb\n");
        assert_eq!(m.line(1), "a");
        assert_eq!(m.line(2), "b");
        assert_eq!(m.line(99), "", "an out-of-range line is empty, not a panic");
    }

    #[test]
    fn inserting_shifts_the_text_after_it() {
        let mut m = model();
        let ev = m.apply(&TextEdit::insert(Position::new(2, 1), "very "));
        assert_eq!(m.line(2), "very second");
        assert_eq!(ev.version, 2);
        assert_eq!(ev.removed, "");
        assert_eq!(ev.inserted, "very ");
        assert!(m.dirty);
    }

    #[test]
    fn deleting_a_range_returns_what_was_removed() {
        let mut m = model();
        let ev = m.apply(&TextEdit::delete(Range::new(
            Position::new(1, 1),
            Position::new(2, 1),
        )));
        assert_eq!(ev.removed, "first\n");
        assert_eq!(m.line(1), "second");
        // "second", "third", and the empty line the trailing newline opens.
        assert_eq!(m.line_count(), 3);
    }

    #[test]
    fn replacing_across_lines_updates_the_line_count() {
        let mut m = model();
        let ev = m.apply(&TextEdit::replace(
            Range::new(Position::new(1, 1), Position::new(3, 1)),
            "only\n",
        ));
        assert_eq!(ev.line_delta(), -1);
        assert_eq!(m.line_count(), 3, "only, third, and the empty final line");
        assert_eq!(m.line(1), "only");
    }

    #[test]
    fn multiple_edits_apply_against_the_positions_the_caller_saw() {
        // The multi-cursor case: two insertions given in document order. If they
        // were applied front-to-back, the second position would be stale.
        let mut m = TextModel::new("aaa\nbbb\nccc\n");
        let edits = vec![
            TextEdit::insert(Position::new(1, 1), "X"),
            TextEdit::insert(Position::new(3, 1), "Y"),
        ];
        m.apply_all(&edits);
        assert_eq!(m.line(1), "Xaaa");
        assert_eq!(m.line(3), "Yccc");
    }

    #[test]
    fn overlapping_edits_are_refused_rather_than_applied_arbitrarily() {
        let mut m = TextModel::new("abcdef\n");
        let before = m.text();
        let events = m.apply_all(&[
            TextEdit::replace(Range::new(Position::new(1, 1), Position::new(1, 4)), "X"),
            TextEdit::replace(Range::new(Position::new(1, 3), Position::new(1, 6)), "Y"),
        ]);
        assert!(events.is_empty());
        assert_eq!(m.text(), before, "the buffer must be untouched");
    }

    #[test]
    fn versions_increase_monotonically_with_every_edit() {
        let mut m = model();
        let v0 = m.version();
        m.apply(&TextEdit::insert(Position::start(), "x"));
        m.apply(&TextEdit::insert(Position::start(), "y"));
        assert_eq!(m.version(), v0 + 2);
    }

    #[test]
    fn an_edit_beyond_the_buffer_is_clamped_rather_than_panicking() {
        let mut m = TextModel::new("short\n");
        m.apply(&TextEdit::insert(Position::new(500, 500), "!"));
        assert!(m.text().contains('!'));
    }

    #[test]
    fn set_text_replaces_everything_and_clears_the_dirty_flag() {
        let mut m = model();
        m.apply(&TextEdit::insert(Position::start(), "x"));
        assert!(m.dirty);
        m.set_text("brand new\n");
        assert_eq!(m.text(), "brand new\n");
        assert!(!m.dirty);
    }

    #[test]
    fn text_in_a_range_reads_exactly_that_range() {
        let m = model();
        let r = Range::new(Position::new(1, 3), Position::new(2, 3));
        assert_eq!(m.text_in(r), "rst\nse");
    }

    #[test]
    fn tokens_come_from_the_same_lexer_the_analyzer_uses() {
        let m = TextModel::new("int main(void) { return 0; }\n")
            .with_language(sda_core::Language::C);
        let t = m.tokens();
        assert!(!t.is_empty());
        assert_eq!(t[0].2, "keyword");

        let r = TextModel::new("fn main() { let x = 1; }\n")
            .with_language(sda_core::Language::Rust);
        assert_eq!(r.tokens()[0].2, "keyword");
    }

    #[test]
    fn an_unknown_language_yields_no_tokens_rather_than_wrong_ones() {
        assert!(TextModel::new("anything").tokens().is_empty());
    }

    #[test]
    fn unicode_text_edits_by_character_not_by_byte() {
        let mut m = TextModel::new("café au lait\n");
        m.apply(&TextEdit::delete(Range::new(
            Position::new(1, 1),
            Position::new(1, 5),
        )));
        assert_eq!(m.line(1), " au lait");
    }
}
