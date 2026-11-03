//! A native C23 / C++23 lexer.
//!
//! This is a *translation-phase 1-3* lexer: it handles trigraphs, line splices,
//! comments, and preprocessing-tokens, but deliberately does **not** expand
//! macros or evaluate conditionals. That is the right altitude for a compliance
//! checker — MISRA is written against the source as the programmer typed it, and
//! a great many of its rules (comment form, literal form, directive nesting,
//! character-set restrictions) are *lexical* by nature.
//!
//! Anything requiring semantic types (e.g. essential-type analysis) is delegated
//! to a real compiler through `sda-build`; this lexer's job is to be fast,
//! dependency-free, and never wrong about what it does claim.

use crate::span::{LineIndex, Pos, Span};
use serde::{Deserialize, Serialize};

/// Which language the source is being read as. Affects keywords, raw strings,
/// and whether trigraphs are merely obsolete or outright removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Dialect {
    C23,
    Cpp23,
}

impl Dialect {
    pub fn as_str(&self) -> &'static str {
        match self {
            Dialect::C23 => "c23",
            Dialect::Cpp23 => "c++23",
        }
    }
    pub fn is_cpp(&self) -> bool {
        matches!(self, Dialect::Cpp23)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CTokenKind {
    Identifier,
    Keyword,
    /// A preprocessing-number: `42`, `0x1p-3`, `1'000`, `.5f`.
    Number,
    /// A string literal including any prefix and quotes.
    String,
    /// A character-constant including any prefix and quotes.
    Char,
    /// A C++ raw string literal, `R"delim(...)delim"`.
    RawString,
    /// Any operator or separator.
    Punct,
    /// `// ...` through end of (logical) line.
    LineComment,
    /// `/* ... */`.
    BlockComment,
    /// A whole `#...` preprocessing directive, including its arguments.
    Directive,
    /// A byte that begins no valid token.
    Unknown,
}

impl CTokenKind {
    pub fn is_comment(&self) -> bool {
        matches!(self, CTokenKind::LineComment | CTokenKind::BlockComment)
    }
    /// Tokens that contribute to the program's meaning, as opposed to comments
    /// and directives. Most structural rules iterate only over these.
    pub fn is_code(&self) -> bool {
        !self.is_comment() && !matches!(self, CTokenKind::Directive)
    }
    pub fn is_literal(&self) -> bool {
        matches!(
            self,
            CTokenKind::Number | CTokenKind::String | CTokenKind::Char | CTokenKind::RawString
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CToken {
    pub kind: CTokenKind,
    pub span: Span,
    pub pos: Pos,
}

impl CToken {
    pub fn text<'a>(&self, src: &'a str) -> &'a str {
        self.span.slice(src)
    }
    pub fn is(&self, src: &str, s: &str) -> bool {
        self.text(src) == s
    }
}

/// A lexical anomaly worth reporting. These map directly onto MISRA's
/// character-set and comment rules, so the engine turns them into findings
/// without re-scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LexNoteKind {
    /// `/*` never closed before end of file.
    UnterminatedComment,
    /// A string or character constant ran to end of line.
    UnterminatedLiteral,
    /// `/*` appearing inside a block comment — almost always an accidentally
    /// commented-out comment, and a code block silently disabled with it.
    NestedBlockCommentOpen,
    /// A `//` comment continued onto the next line by a trailing backslash,
    /// silently swallowing the line beneath it.
    LineSplicedComment,
    /// A trigraph sequence (`??=` and friends).
    Trigraph,
    /// A digraph token (`<%`, `%>`, `<:`, `:>`, `%:`).
    Digraph,
    /// A non-ASCII byte outside a comment or string literal.
    NonAsciiIdentifier,
    /// A tab used for indentation, which makes MISRA's layout rules ambiguous.
    TabCharacter,
    /// File does not end with a newline.
    MissingFinalNewline,
    /// The file mixes `\r\n` and bare `\n` line endings.
    MixedLineEndings,
    /// A character constant holding more than one character, e.g. `'ab'`,
    /// whose value is implementation-defined.
    MultiCharacterConstant,
}

impl LexNoteKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            LexNoteKind::UnterminatedComment => "unterminated-comment",
            LexNoteKind::UnterminatedLiteral => "unterminated-literal",
            LexNoteKind::NestedBlockCommentOpen => "nested-block-comment-open",
            LexNoteKind::LineSplicedComment => "line-spliced-comment",
            LexNoteKind::Trigraph => "trigraph",
            LexNoteKind::Digraph => "digraph",
            LexNoteKind::NonAsciiIdentifier => "non-ascii-identifier",
            LexNoteKind::TabCharacter => "tab-character",
            LexNoteKind::MissingFinalNewline => "missing-final-newline",
            LexNoteKind::MixedLineEndings => "mixed-line-endings",
            LexNoteKind::MultiCharacterConstant => "multi-character-constant",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LexNote {
    pub kind: LexNoteKind,
    pub span: Span,
    pub pos: Pos,
    pub detail: String,
}

/// The result of lexing one translation unit's source text.
#[derive(Clone, Debug)]
pub struct Lexed {
    pub dialect: Dialect,
    pub tokens: Vec<CToken>,
    pub notes: Vec<LexNote>,
    pub lines: LineIndex,
}

impl Lexed {
    /// The token covering a byte offset, if any.
    ///
    /// Used to give a finding the extent of the construct it names. Asking the
    /// lexer beats re-scanning the text: a directive, a block comment and a
    /// prefixed string literal are each one token here, and each would be
    /// mis-measured by looking at characters alone.
    pub fn token_at_offset(&self, offset: usize) -> Option<&CToken> {
        let i = match self.tokens.binary_search_by(|t| t.span.start.cmp(&offset)) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        self.tokens.get(i).filter(|t| offset < t.span.end)
    }

    /// Tokens that carry program meaning, skipping comments and directives.
    pub fn code_tokens(&self) -> impl Iterator<Item = &CToken> {
        self.tokens.iter().filter(|t| t.kind.is_code())
    }
    pub fn comments(&self) -> impl Iterator<Item = &CToken> {
        self.tokens.iter().filter(|t| t.kind.is_comment())
    }
    pub fn directives(&self) -> impl Iterator<Item = &CToken> {
        self.tokens.iter().filter(|t| t.kind == CTokenKind::Directive)
    }
    pub fn notes_of(&self, kind: LexNoteKind) -> impl Iterator<Item = &LexNote> {
        self.notes.iter().filter(move |n| n.kind == kind)
    }
}

// --- keyword tables -------------------------------------------------------

/// C23 keywords, including the `_`-prefixed ones and the C23 additions
/// (`bool`, `true`, `false`, `nullptr`, `typeof`, `constexpr`, `static_assert`).
const C23_KEYWORDS: &[&str] = &[
    "alignas", "alignof", "auto", "bool", "break", "case", "char", "const", "constexpr",
    "continue", "default", "do", "double", "else", "enum", "extern", "false", "float", "for",
    "goto", "if", "inline", "int", "long", "nullptr", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "static_assert", "struct", "switch", "thread_local", "true",
    "typedef", "typeof", "typeof_unqual", "union", "unsigned", "void", "volatile", "while",
    "_Alignas", "_Alignof", "_Atomic", "_BitInt", "_Bool", "_Complex", "_Decimal128",
    "_Decimal32", "_Decimal64", "_Generic", "_Imaginary", "_Noreturn", "_Static_assert",
    "_Thread_local",
];

/// C++23 keywords.
const CPP23_KEYWORDS: &[&str] = &[
    "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor", "bool", "break",
    "case", "catch", "char", "char8_t", "char16_t", "char32_t", "class", "co_await", "co_return",
    "co_yield", "compl", "concept", "const", "const_cast", "consteval", "constexpr", "constinit",
    "continue", "decltype", "default", "delete", "do", "double", "dynamic_cast", "else", "enum",
    "explicit", "export", "extern", "false", "float", "for", "friend", "goto", "if", "inline",
    "int", "long", "mutable", "namespace", "new", "noexcept", "not", "not_eq", "nullptr",
    "operator", "or", "or_eq", "private", "protected", "public", "register",
    "reinterpret_cast", "requires", "return", "short", "signed", "sizeof", "static",
    "static_assert", "static_cast", "struct", "switch", "template", "this", "thread_local",
    "throw", "true", "try", "typedef", "typeid", "typename", "union", "unsigned", "using",
    "virtual", "void", "volatile", "wchar_t", "while", "xor", "xor_eq",
];

pub fn keywords(dialect: Dialect) -> &'static [&'static str] {
    match dialect {
        Dialect::C23 => C23_KEYWORDS,
        Dialect::Cpp23 => CPP23_KEYWORDS,
    }
}

/// Multi-character operators, longest first so maximal munch is a linear scan.
const PUNCTUATORS: &[&str] = &[
    "%:%:", "...", "<<=", ">>=", "->*", "<=>", "##", "<<", ">>", "<=", ">=", "==", "!=", "&&",
    "||", "++", "--", "->", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "::", ".*", "<%",
    "%>", "<:", ":>", "%:", "#", "{", "}", "[", "]", "(", ")", ";", ":", "?", ".", "+", "-", "*",
    "/", "%", "^", "&", "|", "~", "!", "=", "<", ">", ",",
];

/// The five digraph spellings, which MISRA discourages for legibility.
const DIGRAPHS: &[&str] = &["<%", "%>", "<:", ":>", "%:"];

// --- lexer ----------------------------------------------------------------

struct Lexer<'a> {
    src: &'a str,
    b: &'a [u8],
    i: usize,
    dialect: Dialect,
    tokens: Vec<CToken>,
    notes: Vec<LexNote>,
    lines: LineIndex,
}

/// Lex `src` as `dialect`.
pub fn lex(src: &str, dialect: Dialect) -> Lexed {
    let mut lx = Lexer {
        src,
        b: src.as_bytes(),
        i: 0,
        dialect,
        tokens: Vec::new(),
        notes: Vec::new(),
        lines: LineIndex::new(src),
    };
    lx.run();
    Lexed { dialect, tokens: lx.tokens, notes: lx.notes, lines: lx.lines }
}

impl<'a> Lexer<'a> {
    fn at(&self, i: usize) -> u8 {
        self.b.get(i).copied().unwrap_or(0)
    }
    fn cur(&self) -> u8 {
        self.at(self.i)
    }
    fn eof(&self) -> bool {
        self.i >= self.b.len()
    }

    fn note(&mut self, kind: LexNoteKind, span: Span, detail: impl Into<String>) {
        let pos = self.lines.pos(span.start);
        self.notes.push(LexNote { kind, span, pos, detail: detail.into() });
    }

    fn push(&mut self, kind: CTokenKind, start: usize, end: usize) {
        let span = Span::new(start, end);
        let pos = self.lines.pos(start);
        self.tokens.push(CToken { kind, span, pos });
    }

    /// Length of a line-splice (`\` + newline) at `i`, if there is one.
    fn splice_at(&self, i: usize) -> Option<usize> {
        if self.at(i) != b'\\' {
            return None;
        }
        match (self.at(i + 1), self.at(i + 2)) {
            (b'\n', _) => Some(2),
            (b'\r', b'\n') => Some(3),
            _ => None,
        }
    }

    /// Skip any run of line splices at the cursor.
    fn skip_splices(&mut self) -> bool {
        let mut skipped = false;
        while let Some(n) = self.splice_at(self.i) {
            self.i += n;
            skipped = true;
        }
        skipped
    }

    /// Trigraph length at `i` (always 3) if one starts there.
    fn trigraph_at(&self, i: usize) -> bool {
        self.at(i) == b'?'
            && self.at(i + 1) == b'?'
            && matches!(self.at(i + 2), b'=' | b'/' | b'\'' | b'(' | b')' | b'!' | b'<' | b'>' | b'-')
    }

    fn run(&mut self) {
        self.scan_line_ending_hygiene();
        // `#` only introduces a directive when it is the first token on a line.
        let mut at_line_start = true;

        while !self.eof() {
            if self.skip_splices() {
                continue;
            }
            let c = self.cur();
            let start = self.i;

            match c {
                b'\n' => {
                    self.i += 1;
                    at_line_start = true;
                }
                b' ' | b'\r' | b'\x0b' | b'\x0c' => {
                    self.i += 1;
                }
                b'\t' => {
                    // Only note the first tab per line; a whole tab-indented file
                    // would otherwise drown every other diagnostic.
                    if at_line_start || !self.last_note_is_tab_on_this_line(start) {
                        self.note(
                            LexNoteKind::TabCharacter,
                            Span::new(start, start + 1),
                            "tab character in source",
                        );
                    }
                    self.i += 1;
                }
                b'/' if self.at(start + 1) == b'/' => {
                    self.line_comment(start);
                    at_line_start = true;
                }
                b'/' if self.at(start + 1) == b'*' => {
                    self.block_comment(start);
                    at_line_start = false;
                }
                b'#' if at_line_start => {
                    self.directive(start);
                    at_line_start = true;
                }
                b'"' => {
                    self.string_literal(start, CTokenKind::String, b'"');
                    at_line_start = false;
                }
                b'\'' => {
                    self.string_literal(start, CTokenKind::Char, b'\'');
                    at_line_start = false;
                }
                b'0'..=b'9' => {
                    self.number(start);
                    at_line_start = false;
                }
                b'.' if self.at(start + 1).is_ascii_digit() => {
                    self.number(start);
                    at_line_start = false;
                }
                _ if is_ident_start(c) => {
                    self.identifier_or_literal_with_prefix(start);
                    at_line_start = false;
                }
                b'?' if self.trigraph_at(start) => {
                    self.note(
                        LexNoteKind::Trigraph,
                        Span::new(start, start + 3),
                        format!("trigraph `{}`", Span::new(start, start + 3).slice(self.src)),
                    );
                    // Trigraphs are removed in C23 and C++17; treat the bytes as
                    // punctuation so the rest of the scan stays in step.
                    self.push(CTokenKind::Punct, start, start + 3);
                    self.i = start + 3;
                    at_line_start = false;
                }
                _ if c >= 0x80 => {
                    // A non-ASCII byte outside a comment or literal. Consume the
                    // whole UTF-8 sequence so offsets stay on char boundaries.
                    let mut end = start + 1;
                    while end < self.b.len() && !self.src.is_char_boundary(end) {
                        end += 1;
                    }
                    self.note(
                        LexNoteKind::NonAsciiIdentifier,
                        Span::new(start, end),
                        "non-ASCII character outside a comment or string literal",
                    );
                    self.push(CTokenKind::Unknown, start, end);
                    self.i = end;
                    at_line_start = false;
                }
                _ => {
                    self.punctuator(start);
                    at_line_start = false;
                }
            }
        }
    }

    fn last_note_is_tab_on_this_line(&self, offset: usize) -> bool {
        let line = self.lines.pos(offset).line;
        self.notes
            .iter()
            .rev()
            .take(4)
            .any(|n| n.kind == LexNoteKind::TabCharacter && n.pos.line == line)
    }

    /// Report end-of-file and line-ending hygiene once, up front.
    fn scan_line_ending_hygiene(&mut self) {
        if self.b.is_empty() {
            return;
        }
        let crlf = self.src.matches("\r\n").count();
        let lf = self.b.iter().filter(|b| **b == b'\n').count();
        if crlf > 0 && lf > crlf {
            let span = Span::new(0, 0);
            self.note(
                LexNoteKind::MixedLineEndings,
                span,
                format!("{crlf} CRLF and {} bare LF line endings", lf - crlf),
            );
        }
        if self.b.last() != Some(&b'\n') {
            let end = self.b.len();
            self.note(
                LexNoteKind::MissingFinalNewline,
                Span::new(end.saturating_sub(1), end),
                "file does not end with a newline",
            );
        }
    }

    fn line_comment(&mut self, start: usize) {
        let mut i = start + 2;
        let mut spliced = false;
        while i < self.b.len() {
            if let Some(n) = self.splice_at(i) {
                spliced = true;
                i += n;
                continue;
            }
            if self.at(i) == b'\n' {
                break;
            }
            i += 1;
        }
        if spliced {
            self.note(
                LexNoteKind::LineSplicedComment,
                Span::new(start, i),
                "`//` comment continued by a trailing backslash, silently commenting out the following line",
            );
        }
        self.push(CTokenKind::LineComment, start, i);
        self.i = i;
    }

    fn block_comment(&mut self, start: usize) {
        let mut i = start + 2;
        let mut terminated = false;
        while i < self.b.len() {
            if self.at(i) == b'*' && self.at(i + 1) == b'/' {
                i += 2;
                terminated = true;
                break;
            }
            // `/*` inside a comment: the opener is inert, but it almost always
            // means a nested comment has swallowed live code.
            if self.at(i) == b'/' && self.at(i + 1) == b'*' {
                self.note(
                    LexNoteKind::NestedBlockCommentOpen,
                    Span::new(i, i + 2),
                    "`/*` inside a block comment",
                );
                i += 2;
                continue;
            }
            i += 1;
        }
        if !terminated {
            self.note(
                LexNoteKind::UnterminatedComment,
                Span::new(start, self.b.len()),
                "block comment is never closed",
            );
            i = self.b.len();
        }
        self.push(CTokenKind::BlockComment, start, i);
        self.i = i;
    }

    /// Consume a whole preprocessing directive, including continuation lines.
    fn directive(&mut self, start: usize) {
        let mut i = start + 1;
        while i < self.b.len() {
            if let Some(n) = self.splice_at(i) {
                i += n;
                continue;
            }
            // A block comment inside a directive may span lines; skip it whole.
            if self.at(i) == b'/' && self.at(i + 1) == b'*' {
                let mut j = i + 2;
                while j < self.b.len() && !(self.at(j) == b'*' && self.at(j + 1) == b'/') {
                    j += 1;
                }
                i = (j + 2).min(self.b.len());
                continue;
            }
            if self.at(i) == b'/' && self.at(i + 1) == b'/' {
                while i < self.b.len() && self.at(i) != b'\n' {
                    i += 1;
                }
                break;
            }
            if self.at(i) == b'\n' {
                break;
            }
            i += 1;
        }
        self.push(CTokenKind::Directive, start, i);
        self.i = i;
    }

    /// A string or character literal, `quote` being `"` or `'`.
    fn string_literal(&mut self, start: usize, kind: CTokenKind, quote: u8) {
        let body_start = self.i;
        let mut i = body_start + 1;
        let mut chars = 0usize;
        let mut terminated = false;
        while i < self.b.len() {
            if let Some(n) = self.splice_at(i) {
                i += n;
                continue;
            }
            let c = self.at(i);
            if c == b'\\' {
                // An escape consumes the next byte whatever it is.
                i += 2;
                chars += 1;
                continue;
            }
            if c == quote {
                i += 1;
                terminated = true;
                break;
            }
            if c == b'\n' {
                break;
            }
            // Trigraphs are replaced before literals exist, so a string is where
            // one does its damage: `"what??!"` holds a `|` on a compiler that
            // honours them.
            if c == b'?' && self.trigraph_at(i) {
                self.note(
                    LexNoteKind::Trigraph,
                    Span::new(i, i + 3),
                    format!("trigraph `{}`", Span::new(i, i + 3).slice(self.src)),
                );
                i += 3;
                chars += 1;
                continue;
            }
            i += 1;
            chars += 1;
        }
        if !terminated {
            self.note(
                LexNoteKind::UnterminatedLiteral,
                Span::new(start, i),
                "literal is not closed before end of line",
            );
        }
        if kind == CTokenKind::Char && chars > 1 {
            self.note(
                LexNoteKind::MultiCharacterConstant,
                Span::new(start, i),
                "character constant contains more than one character; its value is implementation-defined",
            );
        }
        self.push(kind, start, i);
        self.i = i;
    }

    /// A preprocessing-number, which is deliberately permissive: `1'000`,
    /// `0x1.8p3f`, `1e+9`, `0b1010`, and even nonsense like `1abc` all lex as
    /// one token, exactly as the standard specifies.
    fn number(&mut self, start: usize) {
        let mut i = self.i;
        if self.at(i) == b'.' {
            i += 1;
        }
        while i < self.b.len() {
            if let Some(n) = self.splice_at(i) {
                i += n;
                continue;
            }
            let c = self.at(i);
            // Exponent signs are part of the number only after e/E/p/P.
            if matches!(c, b'+' | b'-') {
                let prev = self.at(i - 1);
                if matches!(prev, b'e' | b'E' | b'p' | b'P') {
                    i += 1;
                    continue;
                }
                break;
            }
            // Digit separators: `'` in C++14 and C23.
            if c == b'\'' && self.at(i + 1).is_ascii_alphanumeric() {
                i += 1;
                continue;
            }
            if c == b'.' || c.is_ascii_alphanumeric() || c == b'_' {
                i += 1;
                continue;
            }
            break;
        }
        self.push(CTokenKind::Number, start, i);
        self.i = i;
    }

    /// An identifier, or a literal introduced by one of the encoding prefixes
    /// (`L"x"`, `u8'c'`, `R"(raw)"`, `u8R"(raw)"`).
    fn identifier_or_literal_with_prefix(&mut self, start: usize) {
        let mut i = self.i;
        while i < self.b.len() {
            if let Some(n) = self.splice_at(i) {
                i += n;
                continue;
            }
            if is_ident_continue(self.at(i)) {
                i += 1;
            } else {
                break;
            }
        }
        let word = Span::new(start, i).slice(self.src);
        let next = self.at(i);

        if matches!(next, b'"' | b'\'') && is_literal_prefix(word, self.dialect) {
            if self.dialect.is_cpp() && next == b'"' && word.ends_with('R') {
                self.i = i;
                self.raw_string(start, i);
                return;
            }
            self.i = i;
            let kind = if next == b'"' { CTokenKind::String } else { CTokenKind::Char };
            self.string_literal(start, kind, next);
            return;
        }

        let kind = if keywords(self.dialect).contains(&word) {
            CTokenKind::Keyword
        } else {
            CTokenKind::Identifier
        };
        self.push(kind, start, i);
        self.i = i;
    }

    /// `R"delim( ... )delim"`, whose body is uninterpreted — no escapes, and
    /// newlines are content. Getting this wrong desynchronizes the whole file.
    fn raw_string(&mut self, start: usize, quote_at: usize) {
        let mut i = quote_at + 1; // past the opening `"`
        let delim_start = i;
        while i < self.b.len() && self.at(i) != b'(' {
            i += 1;
        }
        if i >= self.b.len() {
            self.note(
                LexNoteKind::UnterminatedLiteral,
                Span::new(start, self.b.len()),
                "raw string literal has no opening delimiter",
            );
            self.push(CTokenKind::RawString, start, self.b.len());
            self.i = self.b.len();
            return;
        }
        let delim = Span::new(delim_start, i).slice(self.src).to_string();
        let closer = format!("){delim}\"");
        i += 1; // past `(`
        match self.src[i..].find(&closer) {
            Some(off) => {
                let end = i + off + closer.len();
                self.push(CTokenKind::RawString, start, end);
                self.i = end;
            }
            None => {
                self.note(
                    LexNoteKind::UnterminatedLiteral,
                    Span::new(start, self.b.len()),
                    format!("raw string literal is never closed with `){delim}\"`"),
                );
                self.push(CTokenKind::RawString, start, self.b.len());
                self.i = self.b.len();
            }
        }
    }

    /// `<::` is `<` followed by `::`, not the digraph `<:` followed by `:`.
    ///
    /// C++ [lex.pptoken]/3.2: where the next three characters are `<::` and the
    /// one after is neither `:` nor `>`, the `<` stands alone. The rule exists
    /// for `std::vector<::Foo>` — a template argument naming something at global
    /// scope — which without it lexes as `vector[:Foo>` and is not exotic C++.
    ///
    /// Found by comparing this lexer against clang's: we said `<:` `:`, clang
    /// said `<` `::`, and clang is right. Maximal munch is the rule everywhere
    /// else in the language, which is why the exception has to be written down.
    fn splits_before_scope_operator(&self, start: usize) -> bool {
        self.dialect.is_cpp()
            && self.at(start) == b'<'
            && self.at(start + 1) == b':'
            && self.at(start + 2) == b':'
            && !matches!(self.at(start + 3), b':' | b'>')
    }

    fn punctuator(&mut self, start: usize) {
        if self.splits_before_scope_operator(start) {
            self.push(CTokenKind::Punct, start, start + 1);
            self.i = start + 1;
            return;
        }
        let rest = &self.src[start..];
        for p in PUNCTUATORS {
            if rest.starts_with(p) {
                let end = start + p.len();
                if DIGRAPHS.contains(p) {
                    self.note(
                        LexNoteKind::Digraph,
                        Span::new(start, end),
                        format!("digraph `{p}`"),
                    );
                }
                self.push(CTokenKind::Punct, start, end);
                self.i = end;
                return;
            }
        }
        self.push(CTokenKind::Unknown, start, start + 1);
        self.i = start + 1;
    }
}

fn is_ident_start(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphabetic()
}
fn is_ident_continue(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

/// Encoding prefixes that may precede a quote.
fn is_literal_prefix(word: &str, dialect: Dialect) -> bool {
    match dialect {
        Dialect::C23 => matches!(word, "L" | "u" | "U" | "u8"),
        Dialect::Cpp23 => matches!(
            word,
            "L" | "u" | "U" | "u8" | "R" | "LR" | "uR" | "UR" | "u8R"
        ),
    }
}

// --- literal helpers used by the rule engine ------------------------------

/// True for an integer constant written in octal, i.e. a leading `0` followed
/// by another digit. `0` itself is not octal, and `0x`/`0b` are not either.
pub fn is_octal_constant(text: &str) -> bool {
    let t = text.trim_start_matches('+').trim_start_matches('-');
    let digits: &str = t.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    digits.len() > 1
        && digits.starts_with('0')
        && digits[1..].chars().all(|c| c.is_ascii_digit() || c == '\'')
}

/// True if a numeric literal's suffix uses a lowercase `l`, which is easily
/// misread as `1` (MISRA requires an uppercase `L`).
pub fn has_lowercase_l_suffix(text: &str) -> bool {
    text.chars().rev().take_while(|c| c.is_ascii_alphabetic()).any(|c| c == 'l')
}

/// True if an unsigned literal lacks the `U`/`u` suffix conventions —
/// specifically, reports a lowercase `u` suffix, which MISRA also asks be uppercase.
pub fn has_lowercase_u_suffix(text: &str) -> bool {
    text.chars().rev().take_while(|c| c.is_ascii_alphabetic()).any(|c| c == 'u')
}

/// Octal escape sequences inside a literal, e.g. `"\101"`, whose readability
/// MISRA restricts. Returns the number found.
pub fn count_octal_escapes(text: &str) -> usize {
    let b = text.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'\\' {
            // `\\` escapes the backslash itself; skip both so `"\\123"` is not a hit.
            if b[i + 1] == b'\\' {
                i += 2;
                continue;
            }
            if b[i + 1].is_ascii_digit() && b[i + 1] != b'8' && b[i + 1] != b'9' {
                n += 1;
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str, d: Dialect) -> Vec<CTokenKind> {
        lex(src, d).tokens.iter().map(|t| t.kind).collect()
    }
    fn texts(src: &str, d: Dialect) -> Vec<String> {
        lex(src, d).tokens.iter().map(|t| t.text(src).to_string()).collect()
    }
    fn has(src: &str, d: Dialect, k: LexNoteKind) -> bool {
        lex(src, d).notes.iter().any(|n| n.kind == k)
    }

    #[test]
    fn lexes_a_minimal_function() {
        let src = "int main(void) { return 0; }\n";
        let t = texts(src, Dialect::C23);
        assert_eq!(t, ["int", "main", "(", "void", ")", "{", "return", "0", ";", "}"]);
        assert_eq!(kinds(src, Dialect::C23)[0], CTokenKind::Keyword);
        assert_eq!(kinds(src, Dialect::C23)[1], CTokenKind::Identifier);
    }

    #[test]
    fn maximal_munch_prefers_longer_operators() {
        assert_eq!(texts("a >>= b;\n", Dialect::C23)[1], ">>=");
        assert_eq!(texts("a <=> b;\n", Dialect::Cpp23)[1], "<=>");
        assert_eq!(texts("a->*b;\n", Dialect::Cpp23)[1], "->*");
    }

    #[test]
    fn directives_are_single_tokens_including_continuations() {
        let src = "#define LONG(a) \\\n    do { a; } while (0)\nint x;\n";
        let lexed = lex(src, Dialect::C23);
        let d: Vec<&CToken> = lexed.directives().collect();
        assert_eq!(d.len(), 1);
        assert!(d[0].text(src).contains("while (0)"), "continuation line must be part of the directive");
        // Code after the directive still lexes.
        assert!(lexed.code_tokens().any(|t| t.text(src) == "x"));
    }

    #[test]
    fn hash_mid_line_is_an_operator_not_a_directive() {
        let src = "#define S(x) #x\n";
        let lexed = lex(src, Dialect::C23);
        assert_eq!(lexed.directives().count(), 1);
        let src2 = "int a = b # c;\n";
        assert_eq!(lex(src2, Dialect::C23).directives().count(), 0);
    }

    #[test]
    fn nested_block_comment_opener_is_flagged() {
        assert!(has("/* outer /* inner */\n", Dialect::C23, LexNoteKind::NestedBlockCommentOpen));
        assert!(!has("/* plain */\n", Dialect::C23, LexNoteKind::NestedBlockCommentOpen));
    }

    #[test]
    fn unterminated_block_comment_is_flagged_and_does_not_hang() {
        assert!(has("/* never closed\nint x;\n", Dialect::C23, LexNoteKind::UnterminatedComment));
    }

    #[test]
    fn spliced_line_comment_swallows_the_next_line_and_is_flagged() {
        let src = "// comment \\\nint dropped = 1;\nint kept = 2;\n";
        assert!(has(src, Dialect::C23, LexNoteKind::LineSplicedComment));
        let lexed = lex(src, Dialect::C23);
        let idents: Vec<String> =
            lexed.code_tokens().map(|t| t.text(src).to_string()).collect();
        assert!(idents.contains(&"kept".to_string()));
        assert!(!idents.contains(&"dropped".to_string()), "spliced line is inside the comment");
    }

    #[test]
    fn comment_markers_inside_strings_are_not_comments() {
        let src = "const char *s = \"/* not a comment */\";\n";
        assert_eq!(lex(src, Dialect::C23).comments().count(), 0);
    }

    #[test]
    fn string_markers_inside_comments_are_not_strings() {
        let src = "/* he said \"hi */ int x;\n";
        let lexed = lex(src, Dialect::C23);
        assert_eq!(lexed.comments().count(), 1);
        assert!(lexed.code_tokens().any(|t| t.text(src) == "x"));
    }

    #[test]
    fn escaped_quotes_do_not_end_a_string() {
        let src = "char *s = \"a\\\"b\"; int y;\n";
        let lexed = lex(src, Dialect::C23);
        let strings: Vec<String> = lexed
            .tokens
            .iter()
            .filter(|t| t.kind == CTokenKind::String)
            .map(|t| t.text(src).to_string())
            .collect();
        assert_eq!(strings, ["\"a\\\"b\""]);
        assert!(lexed.code_tokens().any(|t| t.text(src) == "y"));
    }

    #[test]
    fn raw_strings_swallow_quotes_and_newlines() {
        let src = "auto s = R\"json({\"k\": \"v\"}\n)json\"; int z;\n";
        let lexed = lex(src, Dialect::Cpp23);
        let raws: Vec<&CToken> =
            lexed.tokens.iter().filter(|t| t.kind == CTokenKind::RawString).collect();
        assert_eq!(raws.len(), 1);
        assert!(raws[0].text(src).contains("\"k\""));
        assert!(lexed.code_tokens().any(|t| t.text(src) == "z"), "lexer stays in step after a raw string");
    }

    #[test]
    fn raw_string_syntax_is_not_applied_to_c() {
        // In C, `R` is an ordinary identifier and the quote starts a normal string.
        let src = "R\"abc\";\n";
        let lexed = lex(src, Dialect::C23);
        assert_eq!(lexed.tokens[0].kind, CTokenKind::Identifier);
        assert_eq!(lexed.tokens[1].kind, CTokenKind::String);
    }

    #[test]
    fn encoding_prefixes_attach_to_their_literal() {
        let lexed = lex("u8\"x\" L'c' U\"y\";\n", Dialect::C23);
        let kinds: Vec<CTokenKind> = lexed.tokens.iter().map(|t| t.kind).take(3).collect();
        assert_eq!(kinds, [CTokenKind::String, CTokenKind::Char, CTokenKind::String]);
    }

    #[test]
    fn preprocessing_numbers_absorb_suffixes_separators_and_exponents() {
        for n in ["0x1.8p+3f", "1'000'000UL", "1e-9", "0b1010", ".5F", "42"] {
            let src = format!("x = {n};\n");
            let lexed = lex(&src, Dialect::Cpp23);
            let num = lexed.tokens.iter().find(|t| t.kind == CTokenKind::Number).unwrap();
            assert_eq!(num.text(&src), n, "number {n} did not lex as one token");
        }
    }

    #[test]
    fn minus_after_identifier_is_an_operator_not_an_exponent() {
        let t = texts("a-1;\n", Dialect::C23);
        assert_eq!(t, ["a", "-", "1", ";"]);
    }

    #[test]
    fn trigraphs_and_digraphs_are_reported() {
        assert!(has("??=define X 1\n", Dialect::C23, LexNoteKind::Trigraph));
        assert!(has("int a<:3:>;\n", Dialect::C23, LexNoteKind::Digraph));
    }

    #[test]
    fn multi_character_constants_are_reported() {
        assert!(has("int c = 'ab';\n", Dialect::C23, LexNoteKind::MultiCharacterConstant));
        assert!(!has("int c = 'a';\n", Dialect::C23, LexNoteKind::MultiCharacterConstant));
        assert!(
            !has("int c = '\\n';\n", Dialect::C23, LexNoteKind::MultiCharacterConstant),
            "an escape sequence is one character"
        );
    }

    #[test]
    fn file_hygiene_notes_fire_once() {
        assert!(has("int x;", Dialect::C23, LexNoteKind::MissingFinalNewline));
        assert!(!has("int x;\n", Dialect::C23, LexNoteKind::MissingFinalNewline));
        assert!(has("a\r\nb\nc\nd\n", Dialect::C23, LexNoteKind::MixedLineEndings));
    }

    #[test]
    fn positions_are_one_based_and_track_lines() {
        let src = "int a;\nint b;\n";
        let lexed = lex(src, Dialect::C23);
        let b = lexed.code_tokens().find(|t| t.text(src) == "b").unwrap();
        assert_eq!(b.pos, Pos::new(2, 5));
    }

    #[test]
    fn utf8_in_comments_is_fine_but_bare_in_code_is_noted() {
        assert!(!has("// caf\u{e9}\n", Dialect::C23, LexNoteKind::NonAsciiIdentifier));
        assert!(!has("char*s=\"caf\u{e9}\";\n", Dialect::C23, LexNoteKind::NonAsciiIdentifier));
        assert!(has("int caf\u{e9} = 1;\n", Dialect::C23, LexNoteKind::NonAsciiIdentifier));
    }

    #[test]
    fn empty_and_whitespace_only_input_is_handled() {
        assert!(lex("", Dialect::C23).tokens.is_empty());
        assert!(lex("   \n\t\n", Dialect::C23).code_tokens().count() == 0);
    }

    #[test]
    fn octal_detection_distinguishes_zero_hex_and_octal() {
        assert!(is_octal_constant("0777"));
        assert!(is_octal_constant("017U"));
        assert!(!is_octal_constant("0"));
        assert!(!is_octal_constant("0x1F"));
        assert!(!is_octal_constant("0b11"));
        assert!(!is_octal_constant("123"));
    }

    #[test]
    fn suffix_case_helpers_only_look_at_the_suffix() {
        assert!(has_lowercase_l_suffix("100l"));
        assert!(has_lowercase_l_suffix("100ul"));
        assert!(!has_lowercase_l_suffix("100UL"));
        assert!(!has_lowercase_l_suffix("0xl0"), "`l` inside the digits is not a suffix");
        assert!(has_lowercase_u_suffix("7u"));
        assert!(!has_lowercase_u_suffix("7U"));
    }

    #[test]
    fn octal_escapes_are_counted_but_escaped_backslashes_are_not() {
        assert_eq!(count_octal_escapes("\"\\101\\102\""), 2);
        assert_eq!(count_octal_escapes("\"\\\\123\""), 0);
        assert_eq!(count_octal_escapes("\"\\n\""), 0);
    }
}

