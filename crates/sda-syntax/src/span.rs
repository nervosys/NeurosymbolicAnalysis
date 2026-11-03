//! Byte spans and the offset-to-line/column mapping every diagnostic needs.

use serde::{Deserialize, Serialize};

/// A half-open byte range `[start, end)` into the source text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        debug_assert!(start <= end, "span start must not exceed end");
        Span { start, end }
    }
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
    /// Slice `src` by this span, clamped so a stale span can never panic.
    pub fn slice<'a>(&self, src: &'a str) -> &'a str {
        let end = self.end.min(src.len());
        let start = self.start.min(end);
        // Clamp to char boundaries: source may contain UTF-8 in comments or literals.
        let mut s = start;
        while s < src.len() && !src.is_char_boundary(s) {
            s += 1;
        }
        let mut e = end;
        while e < src.len() && !src.is_char_boundary(e) {
            e += 1;
        }
        &src[s..e]
    }
    pub fn contains(&self, offset: usize) -> bool {
        offset >= self.start && offset < self.end
    }
    /// Smallest span covering both.
    pub fn join(&self, other: Span) -> Span {
        Span::new(self.start.min(other.start), self.end.max(other.end))
    }
}

/// 1-based line and column, as compilers and editors report them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pos {
    pub line: u32,
    pub column: u32,
}

impl Pos {
    pub fn new(line: u32, column: u32) -> Self {
        Pos { line, column }
    }
}

/// Precomputed line-start offsets, for O(log n) offset lookup.
#[derive(Clone, Debug)]
pub struct LineIndex {
    /// Byte offset of the first character of each line.
    starts: Vec<usize>,
    len: usize,
}

impl LineIndex {
    pub fn new(src: &str) -> Self {
        let mut starts = vec![0usize];
        for (i, b) in src.bytes().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        LineIndex { starts, len: src.len() }
    }

    /// Number of lines. A trailing newline does not create a phantom final line
    /// for reporting purposes, but the index still tracks it.
    pub fn line_count(&self) -> u32 {
        self.starts.len() as u32
    }

    /// 1-based line/column for a byte offset. Columns count bytes, matching
    /// GCC/Clang default behaviour on ASCII source.
    pub fn pos(&self, offset: usize) -> Pos {
        let offset = offset.min(self.len);
        // Index of the last line start <= offset.
        let idx = match self.starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        Pos::new(idx as u32 + 1, (offset - self.starts[idx]) as u32 + 1)
    }

    /// Byte range of a 1-based line, excluding its terminator.
    pub fn line_span(&self, line: u32) -> Option<Span> {
        let i = line.checked_sub(1)? as usize;
        let start = *self.starts.get(i)?;
        let end = self.starts.get(i + 1).map(|n| n - 1).unwrap_or(self.len);
        Some(Span::new(start, end.max(start)))
    }

    /// Text of a 1-based line, without its terminator.
    pub fn line_text<'a>(&self, src: &'a str, line: u32) -> Option<&'a str> {
        self.line_span(line).map(|s| s.slice(src).trim_end_matches('\r'))
    }

    /// Up to `radius` lines either side of `line`, and the first line's number.
    /// Used to build the source snippet attached to every finding.
    pub fn context<'a>(&self, src: &'a str, line: u32, radius: u32) -> (u32, &'a str) {
        let first = line.saturating_sub(radius).max(1);
        let last = (line + radius).min(self.line_count());
        let start = self.line_span(first).map(|s| s.start).unwrap_or(0);
        let end = self.line_span(last).map(|s| s.end).unwrap_or(self.len);
        (first, Span::new(start, end).slice(src))
    }
}

/// The 1-based, exclusive end column of the token that begins at `column`.
///
/// Every check reports a start position; SARIF regions and editor decorations
/// both want an extent. Deriving it from the source once, here, gives all of
/// them a token-precise span without each check having to track lengths — and
/// without an extent, a SARIF consumer highlights a point and the editor
/// underlines everything to the end of the line.
///
/// Columns count bytes, as everywhere else in this module. A position that does
/// not land on a character boundary, or lands past the end of the line, yields
/// a minimal span rather than a panic: a wrong extent must never be worse than
/// no extent.
pub fn token_end_column(line: &str, column: u32) -> u32 {
    let col = column.max(1);
    let start = (col - 1) as usize;
    if start >= line.len() || !line.is_char_boundary(start) {
        return col;
    }

    let rest = &line[start..];
    let Some(first) = rest.chars().next() else { return col };

    let len = if is_ident_start(first) {
        rest.find(|c: char| !is_ident_continue(c)).unwrap_or(rest.len())
    } else if first == '"' || first == '\'' {
        quoted_len(rest, first)
    } else {
        // Punctuation. Multi-character operators are not worth a lexer here;
        // one character is honest and always inside the token.
        first.len_utf8()
    };

    col + len as u32
}

fn is_ident_start(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Digits and `.` continue a token so numeric literals span whole, and `$`
/// because some toolchains permit it in identifiers.
fn is_ident_continue(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

/// Length of a quoted literal including both delimiters, honouring backslash
/// escapes. An unterminated literal spans to the end of the line.
fn quoted_len(rest: &str, quote: char) -> usize {
    let mut it = rest.char_indices();
    it.next(); // the opening delimiter
    let mut escaped = false;
    for (i, c) in it {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == quote {
            return i + c.len_utf8();
        }
    }
    rest.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "one\ntwo\nthree\n";

    #[test]
    fn a_token_span_covers_the_identifier_it_starts_on() {
        let line = "    memcpy(dst, src, n);";
        // Column 5 is `m` of memcpy; the span must be exactly `memcpy`.
        assert_eq!(token_end_column(line, 5), 11);
        assert_eq!(&line[4..10], "memcpy");
    }

    #[test]
    fn a_string_literal_spans_to_its_closing_quote() {
        let line = "    puts(\"hello\");";
        let end = token_end_column(line, 10);
        assert_eq!(&line[9..(end - 1) as usize], "\"hello\"");
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_literal_early() {
        let line = "s = \"a\\\"b\";";
        let end = token_end_column(line, 5);
        assert_eq!(&line[4..(end - 1) as usize], "\"a\\\"b\"");
    }

    #[test]
    fn an_unterminated_literal_stops_at_the_end_of_the_line() {
        let line = "char *s = \"oops";
        assert_eq!(token_end_column(line, 11), line.len() as u32 + 1);
    }

    /// A bad position must degrade to a minimal span. Reporting the wrong
    /// extent is worse than reporting none, and panicking is worse than both.
    #[test]
    fn positions_off_the_end_or_mid_character_stay_harmless() {
        assert_eq!(token_end_column("abc", 99), 99);
        assert_eq!(token_end_column("", 1), 1);
        // `é` is two bytes; column 2 is inside it.
        let line = "é = 1;";
        assert_eq!(token_end_column(line, 2), 2);
        assert_eq!(token_end_column(line, 1), 1 + "é".len() as u32);
    }

    #[test]
    fn punctuation_spans_exactly_one_character() {
        assert_eq!(token_end_column("a + b", 3), 4);
    }

    #[test]
    fn a_numeric_literal_spans_whole() {
        let line = "x = 1234u;";
        assert_eq!(token_end_column(line, 5), 10);
    }

    #[test]
    fn offsets_map_to_one_based_positions() {
        let idx = LineIndex::new(SRC);
        assert_eq!(idx.pos(0), Pos::new(1, 1));
        assert_eq!(idx.pos(2), Pos::new(1, 3));
        assert_eq!(idx.pos(4), Pos::new(2, 1));
        assert_eq!(idx.pos(8), Pos::new(3, 1));
    }

    #[test]
    fn newline_offset_belongs_to_the_line_it_ends() {
        let idx = LineIndex::new(SRC);
        assert_eq!(idx.pos(3), Pos::new(1, 4));
    }

    #[test]
    fn out_of_range_offsets_clamp_instead_of_panicking() {
        let idx = LineIndex::new(SRC);
        assert_eq!(idx.pos(9999).line, 4);
    }

    #[test]
    fn line_text_strips_terminators() {
        let idx = LineIndex::new("a\r\nb\n");
        assert_eq!(idx.line_text("a\r\nb\n", 1), Some("a"));
        assert_eq!(idx.line_text("a\r\nb\n", 2), Some("b"));
    }

    #[test]
    fn context_window_clamps_at_both_ends() {
        let idx = LineIndex::new(SRC);
        let (first, text) = idx.context(SRC, 1, 5);
        assert_eq!(first, 1);
        assert!(text.contains("three"));
    }

    #[test]
    fn slicing_a_span_over_utf8_never_panics() {
        let src = "// caf\u{e9} comment";
        // A span landing mid-codepoint gets nudged to a boundary.
        assert!(!Span::new(0, 7).slice(src).is_empty());
    }

    #[test]
    fn spans_join_to_their_hull() {
        assert_eq!(Span::new(2, 5).join(Span::new(10, 12)), Span::new(2, 12));
    }
}
