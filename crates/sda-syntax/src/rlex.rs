//! A native Rust 2024 lexer.
//!
//! Rust already has a borrow checker and a mature lint ecosystem, so this exists
//! for a narrower purpose than the C lexer: to find the constructs that *escape*
//! those guarantees — `unsafe`, FFI boundaries, panicking operations in code that
//! must not panic, and the edition-2024 migration hazards — in source that may
//! not build, without shelling out to `rustc`.

use crate::span::{LineIndex, Pos, Span};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RTokenKind {
    Identifier,
    Keyword,
    /// `'a` — a lifetime or loop label, not a character literal.
    Lifetime,
    Number,
    String,
    /// `r"..."`, `r#"..."#`.
    RawString,
    /// `b"..."` / `b'c'`.
    ByteString,
    Char,
    Punct,
    LineComment,
    BlockComment,
    /// `///` or `//!`.
    DocComment,
    /// `#[...]` or `#![...]`, captured whole.
    Attribute,
    Unknown,
}

impl RTokenKind {
    pub fn is_comment(&self) -> bool {
        matches!(self, RTokenKind::LineComment | RTokenKind::BlockComment | RTokenKind::DocComment)
    }
    pub fn is_code(&self) -> bool {
        !self.is_comment()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RToken {
    pub kind: RTokenKind,
    pub span: Span,
    pub pos: Pos,
}

impl RToken {
    pub fn text<'a>(&self, src: &'a str) -> &'a str {
        self.span.slice(src)
    }
    pub fn is(&self, src: &str, s: &str) -> bool {
        self.text(src) == s
    }
}

#[derive(Clone, Debug)]
pub struct RustLexed {
    pub tokens: Vec<RToken>,
    pub lines: LineIndex,
    /// `/*` blocks never closed.
    pub unterminated_block_comments: Vec<Pos>,
}

impl RustLexed {
    pub fn code_tokens(&self) -> impl Iterator<Item = &RToken> {
        self.tokens.iter().filter(|t| t.kind.is_code())
    }
    pub fn attributes(&self) -> impl Iterator<Item = &RToken> {
        self.tokens.iter().filter(|t| t.kind == RTokenKind::Attribute)
    }
}

/// Rust 2024 keywords, including reserved-for-future-use ones and the
/// edition-2024 additions (`gen`).
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
    "extern", "false", "fn", "for", "gen", "if", "impl", "in", "let", "loop", "match", "mod",
    "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super", "trait",
    "true", "type", "union", "unsafe", "use", "where", "while", "abstract", "become", "box",
    "do", "final", "macro", "override", "priv", "try", "typeof", "unsized", "virtual", "yield",
];

const RUST_PUNCT: &[&str] = &[
    "...", "..=", "<<=", ">>=", "->", "=>", "::", "..", "==", "!=", "<=", ">=", "&&", "||",
    "+=", "-=", "*=", "/=", "%=", "^=", "&=", "|=", "<<", ">>", "#", "{", "}", "[", "]", "(",
    ")", ";", ":", ",", ".", "@", "?", "+", "-", "*", "/", "%", "^", "&", "|", "!", "=", "<",
    ">", "~", "$",
];

pub fn lex_rust(src: &str) -> RustLexed {
    let b = src.as_bytes();
    let lines = LineIndex::new(src);
    let mut tokens = Vec::new();
    let mut unterminated = Vec::new();
    let mut i = 0usize;

    let at = |i: usize| -> u8 { b.get(i).copied().unwrap_or(0) };
    macro_rules! push {
        ($kind:expr, $start:expr, $end:expr) => {{
            let span = Span::new($start, $end);
            tokens.push(RToken { kind: $kind, span, pos: lines.pos($start) });
        }};
    }

    while i < b.len() {
        let start = i;
        let c = at(i);

        match c {
            b' ' | b'\t' | b'\n' | b'\r' => {
                i += 1;
            }

            b'/' if at(i + 1) == b'/' => {
                // `///` and `//!` are doc comments; `////` is an ordinary comment.
                let doc = (at(i + 2) == b'/' && at(i + 3) != b'/') || at(i + 2) == b'!';
                while i < b.len() && at(i) != b'\n' {
                    i += 1;
                }
                push!(if doc { RTokenKind::DocComment } else { RTokenKind::LineComment }, start, i);
            }

            b'/' if at(i + 1) == b'*' => {
                // Rust block comments nest, unlike C's.
                let doc = at(i + 2) == b'*' && at(i + 3) != b'/' || at(i + 2) == b'!';
                let mut depth = 1usize;
                i += 2;
                while i < b.len() && depth > 0 {
                    if at(i) == b'/' && at(i + 1) == b'*' {
                        depth += 1;
                        i += 2;
                    } else if at(i) == b'*' && at(i + 1) == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if depth > 0 {
                    unterminated.push(lines.pos(start));
                }
                push!(if doc { RTokenKind::DocComment } else { RTokenKind::BlockComment }, start, i);
            }

            // `#[...]` / `#![...]`, captured whole so attribute inspection is trivial.
            b'#' if at(i + 1) == b'[' || (at(i + 1) == b'!' && at(i + 2) == b'[') => {
                let bracket = if at(i + 1) == b'[' { i + 1 } else { i + 2 };
                let mut depth = 0i32;
                let mut j = bracket;
                while j < b.len() {
                    match at(j) {
                        b'[' => depth += 1,
                        b']' => {
                            depth -= 1;
                            if depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        // Don't let a `]` inside a string close the attribute.
                        b'"' => {
                            j += 1;
                            while j < b.len() && at(j) != b'"' {
                                if at(j) == b'\\' {
                                    j += 1;
                                }
                                j += 1;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                i = j.min(b.len());
                push!(RTokenKind::Attribute, start, i);
            }

            // Raw strings: r"...", r#"..."#, and the byte forms br#"..."#.
            b'r' | b'b'
                if matches!(
                    (c, at(i + 1), at(i + 2)),
                    (b'r', b'"', _) | (b'r', b'#', _) | (b'b', b'r', b'"') | (b'b', b'r', b'#')
                ) =>
            {
                let mut j = i + if c == b'b' { 2 } else { 1 };
                let hashes = {
                    let h = j;
                    while at(j) == b'#' {
                        j += 1;
                    }
                    j - h
                };
                if at(j) != b'"' {
                    // `r#ident` is a **raw identifier**, not `r`, `#`, `ident`.
                    // It exists so a keyword can be used as a name, so lexing it
                    // apart produced a stray `#` and then classified `r#fn`'s
                    // `fn` as the keyword — the one reading the syntax exists to
                    // rule out. `r#type` and friends are ordinary in generated
                    // bindings. Found against rustc's own lexer.
                    if c == b'r' && hashes == 1 && is_ident_start(at(j)) {
                        i = j;
                        while i < b.len() && is_ident_continue(at(i)) {
                            i += 1;
                        }
                        push!(RTokenKind::Identifier, start, i);
                        continue;
                    }
                    // Not a raw string and not a raw identifier: just the prefix
                    // letter as an identifier.
                    while i < b.len() && is_ident_continue(at(i)) {
                        i += 1;
                    }
                    push!(RTokenKind::Identifier, start, i);
                    continue;
                }
                j += 1;
                let closer: String = std::iter::once('"').chain(std::iter::repeat_n('#', hashes)).collect();
                match src[j..].find(&closer) {
                    Some(off) => i = j + off + closer.len(),
                    None => i = b.len(),
                }
                push!(RTokenKind::RawString, start, i);
            }

            // `b"..." `, `b'x'` and `c"..."`. A C string has no character
            // form: `c'x'` is not a literal, and lexing it as one would invent a
            // token rustc does not produce.
            b'b' | b'c'
                if at(i + 1) == b'"' || (c == b'b' && at(i + 1) == b'\'') =>
            {
                let quote = at(i + 1);
                i += 2;
                while i < b.len() && at(i) != quote {
                    if at(i) == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i = (i + 1).min(b.len());
                push!(RTokenKind::ByteString, start, i);
            }

            b'"' => {
                i += 1;
                while i < b.len() && at(i) != b'"' {
                    if at(i) == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i = (i + 1).min(b.len());
                push!(RTokenKind::String, start, i);
            }

            // `'` is a lifetime unless it encloses exactly one char.
            b'\'' => {
                if is_char_literal(b, i) {
                    i += 1;
                    while i < b.len() && at(i) != b'\'' {
                        if at(i) == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    i = (i + 1).min(b.len());
                    push!(RTokenKind::Char, start, i);
                } else {
                    i += 1;
                    while i < b.len() && is_ident_continue(at(i)) {
                        i += 1;
                    }
                    push!(RTokenKind::Lifetime, start, i);
                }
            }

            b'0'..=b'9' => {
                while i < b.len()
                    && (at(i).is_ascii_alphanumeric() || at(i) == b'_' || at(i) == b'.')
                {
                    // `1..2` is a range, not a float.
                    if at(i) == b'.' && at(i + 1) == b'.' {
                        break;
                    }
                    // A signed exponent is part of the literal. `1.0e-3f64` is
                    // one token; this used to stop at the `e` and hand back
                    // `1.0e`, `-`, `3f64` — three tokens, one of them an
                    // operator that is not there. Found against rustc's own
                    // lexer, and `1e-9` is ordinary in numeric code.
                    //
                    // Only after an exponent marker, and only for a base that
                    // has one: `0xE-1` is hex `0xE` minus one, and treating its
                    // `E` as an exponent would swallow the operator.
                    let exponent_sign = matches!(at(i), b'e' | b'E')
                        && matches!(at(i + 1), b'+' | b'-')
                        && at(i + 2).is_ascii_digit()
                        && !src[start..i].starts_with("0x")
                        && !src[start..i].starts_with("0X")
                        && !src[start..i].starts_with("0b")
                        && !src[start..i].starts_with("0o");
                    if exponent_sign {
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
                push!(RTokenKind::Number, start, i);
            }

            _ if is_ident_start(c) => {
                while i < b.len() && is_ident_continue(at(i)) {
                    i += 1;
                }
                let word = Span::new(start, i).slice(src);
                let kind = if RUST_KEYWORDS.contains(&word) {
                    RTokenKind::Keyword
                } else {
                    RTokenKind::Identifier
                };
                push!(kind, start, i);
            }

            _ => {
                let rest = &src[i..];
                match RUST_PUNCT.iter().find(|p| rest.starts_with(**p)) {
                    Some(p) => {
                        i += p.len();
                        push!(RTokenKind::Punct, start, i);
                    }
                    None => {
                        // Consume a whole UTF-8 sequence to stay on boundaries.
                        i += 1;
                        while i < b.len() && !src.is_char_boundary(i) {
                            i += 1;
                        }
                        push!(RTokenKind::Unknown, start, i);
                    }
                }
            }
        }
    }

    RustLexed { tokens, lines, unterminated_block_comments: unterminated }
}

/// Distinguish `'a` (lifetime) from `'a'` (char) and `'\n'` (escaped char).
fn is_char_literal(b: &[u8], i: usize) -> bool {
    let at = |k: usize| b.get(k).copied().unwrap_or(0);
    if at(i + 1) == b'\\' {
        return true; // every escape form is a char literal
    }
    // `'x'` — one byte then a closing quote.
    if at(i + 2) == b'\'' {
        return true;
    }
    // A multi-byte UTF-8 char followed by a quote.
    if at(i + 1) >= 0x80 {
        let mut j = i + 1;
        j += 1;
        while j < b.len() && (at(j) & 0xC0) == 0x80 {
            j += 1;
        }
        return at(j) == b'\'';
    }
    false
}

/// Rust identifiers are Unicode, and these used to be ASCII-only.
///
/// `café` lexed as `caf` and an unknown byte; `naïve` as three tokens. Non-ASCII
/// identifiers have been legal since Rust 1.53, and the fragments then reached
/// every rule that counts or matches identifiers. Found against rustc's own
/// lexer.
///
/// **The limit, stated rather than hidden.** rustc uses the Unicode XID
/// properties; this accepts any byte outside ASCII, because carrying an XID
/// table into a lexer that only needs to find token boundaries is not worth the
/// weight. The two agree on every identifier that is *valid*, and differ on
/// input that is not: rustc calls an emoji `InvalidIdent`, and this lexes it as
/// part of an identifier. That direction is the safe one — an unparseable name
/// stays one token rather than shattering the tokens around it — and the
/// comparison corpus stays inside valid identifiers, because that is the claim
/// being made.
fn is_ident_start(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphabetic() || c >= 0x80
}
fn is_ident_continue(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric() || c >= 0x80
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<RTokenKind> {
        lex_rust(src).code_tokens().map(|t| t.kind).collect()
    }
    fn texts(src: &str) -> Vec<String> {
        lex_rust(src).code_tokens().map(|t| t.text(src).to_string()).collect()
    }

    #[test]
    fn lexes_a_simple_function() {
        assert_eq!(
            texts("fn main() { let x = 1; }\n"),
            ["fn", "main", "(", ")", "{", "let", "x", "=", "1", ";", "}"]
        );
        assert_eq!(kinds("fn main() {}")[0], RTokenKind::Keyword);
    }

    #[test]
    fn lifetimes_are_not_char_literals() {
        let k = kinds("fn f<'a>(x: &'a str) {}\n");
        assert!(k.contains(&RTokenKind::Lifetime));
        assert!(!k.contains(&RTokenKind::Char));
    }

    #[test]
    fn char_literals_are_not_lifetimes() {
        assert!(kinds("let c = 'x';").contains(&RTokenKind::Char));
        assert!(kinds("let c = '\\n';").contains(&RTokenKind::Char));
        assert!(kinds("let c = '\u{e9}';").contains(&RTokenKind::Char));
    }

    #[test]
    fn loop_labels_lex_as_lifetimes_not_broken_chars() {
        let lexed = lex_rust("'outer: loop { break 'outer; }\n");
        let labels: Vec<String> = lexed
            .code_tokens()
            .filter(|t| t.kind == RTokenKind::Lifetime)
            .map(|t| t.text("'outer: loop { break 'outer; }\n").to_string())
            .collect();
        assert_eq!(labels, ["'outer", "'outer"]);
    }

    #[test]
    fn block_comments_nest() {
        let src = "/* a /* b */ still comment */ fn f() {}\n";
        let lexed = lex_rust(src);
        assert!(lexed.unterminated_block_comments.is_empty());
        assert_eq!(lexed.code_tokens().next().unwrap().text(src), "fn");
    }

    #[test]
    fn unterminated_nested_comment_is_reported() {
        assert_eq!(lex_rust("/* a /* b */\n").unterminated_block_comments.len(), 1);
    }

    #[test]
    fn doc_comments_are_distinguished_from_ordinary_ones() {
        let lexed = lex_rust("/// doc\n//! inner\n// plain\n////  also plain\n");
        let docs = lexed.tokens.iter().filter(|t| t.kind == RTokenKind::DocComment).count();
        assert_eq!(docs, 2);
    }

    #[test]
    fn raw_strings_absorb_quotes_and_hashes() {
        let src = "let s = r#\"a \" b\"#; let t = 1;\n";
        let lexed = lex_rust(src);
        let raws: Vec<&RToken> =
            lexed.tokens.iter().filter(|t| t.kind == RTokenKind::RawString).collect();
        assert_eq!(raws.len(), 1);
        assert_eq!(raws[0].text(src), "r#\"a \" b\"#");
        assert!(lexed.code_tokens().any(|t| t.text(src) == "t"), "lexer stays in step");
    }

    #[test]
    fn byte_and_raw_byte_strings_lex() {
        assert!(kinds("let b = b\"bytes\";").contains(&RTokenKind::ByteString));
        assert!(kinds("let b = br#\"bytes\"#;").contains(&RTokenKind::RawString));
    }

    #[test]
    fn attributes_are_captured_whole_including_nested_brackets() {
        let src = "#[derive(Debug)]\n#[cfg(all(feature = \"a\", not(test)))]\nstruct S;\n";
        let lexed = lex_rust(src);
        let attrs: Vec<String> = lexed.attributes().map(|t| t.text(src).to_string()).collect();
        assert_eq!(attrs.len(), 2);
        assert!(attrs[1].ends_with(')') || attrs[1].ends_with(']'));
        assert!(attrs[1].contains("not(test)"));
    }

    #[test]
    fn inner_attributes_are_captured() {
        let src = "#![forbid(unsafe_code)]\nfn main() {}\n";
        let lexed = lex_rust(src);
        assert_eq!(lexed.attributes().next().unwrap().text(src), "#![forbid(unsafe_code)]");
    }

    #[test]
    fn attribute_containing_a_bracket_in_a_string_does_not_end_early() {
        let src = "#[doc = \"see ]here\"]\nfn f() {}\n";
        let lexed = lex_rust(src);
        assert_eq!(lexed.attributes().next().unwrap().text(src), "#[doc = \"see ]here\"]");
    }

    #[test]
    fn range_syntax_does_not_swallow_the_second_operand() {
        assert_eq!(texts("for i in 0..10 {}"), ["for", "i", "in", "0", "..", "10", "{", "}"]);
    }

    #[test]
    fn float_and_suffixed_numbers_lex_whole() {
        assert_eq!(texts("let x = 1.5f64;"), ["let", "x", "=", "1.5f64", ";"]);
        assert_eq!(texts("let x = 1_000u32;"), ["let", "x", "=", "1_000u32", ";"]);
    }

    #[test]
    fn gen_is_a_keyword_in_edition_2024() {
        assert_eq!(kinds("gen fn g() {}")[0], RTokenKind::Keyword);
    }

    #[test]
    fn empty_input_is_handled() {
        assert!(lex_rust("").tokens.is_empty());
    }
}
