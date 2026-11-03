//! The C and C++ lexer, compared against clang's.
//!
//! Token boundaries and columns are the foundation under every native C and C++
//! finding: a rule that fires on the wrong token underlines the wrong code, and
//! the 14,284-finding PX4 run could only check locations for *plausibility* —
//! that no line ran past end of file. Nothing had ever checked them against a
//! compiler.
//!
//! `clang -cc1 -dump-raw-tokens` is clang's own lexer with the preprocessor
//! switched off, which is the right layer to compare: it reports every token,
//! its spelling and its 1-based line and column, and it treats a comment as one
//! token exactly as this crate does. The answers are captured by
//! `tools/clang-lex-oracle.py` so this test is hermetic.
//!
//! The corpus carries no preprocessing directives on purpose. This crate emits a
//! whole `#...` line as a single token and clang tokenizes inside it; that is a
//! deliberate difference of layer, not of lexing, and mixing it in would bury
//! the comparison that matters under a known disagreement.

use sda_syntax::{CTokenKind, Dialect, lex};

const FIXTURE: &str = include_str!("fixtures/clang-lex.json");

#[derive(serde::Deserialize)]
struct Fixture {
    clang: String,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    dialect: String,
    text: String,
    tokens: Vec<ClangToken>,
}

#[derive(serde::Deserialize)]
struct ClangToken {
    kind: String,
    text: String,
    line: u32,
    column: u32,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("the captured clang answers")
}

/// The categories both lexers genuinely have an opinion about. Clang's kinds are
/// far finer — every operator has its own name — so comparing them directly
/// would compare vocabularies. What matters is that a number is a number and a
/// comment is a comment.
#[derive(Debug, PartialEq, Eq)]
enum Category {
    Word,
    Number,
    String,
    Char,
    Comment,
    Punct,
    Other,
}

fn clang_category(kind: &str) -> Category {
    match kind {
        "raw_identifier" | "identifier" => Category::Word,
        "numeric_constant" => Category::Number,
        "string_literal" | "wide_string_literal" | "utf8_string_literal"
        | "utf16_string_literal" | "utf32_string_literal" => Category::String,
        "char_constant" | "wide_char_constant" | "utf8_char_constant"
        | "utf16_char_constant" | "utf32_char_constant" => Category::Char,
        "comment" => Category::Comment,
        "unknown" | "eof" => Category::Other,
        _ => Category::Punct,
    }
}

fn our_category(kind: CTokenKind) -> Category {
    match kind {
        CTokenKind::Identifier | CTokenKind::Keyword => Category::Word,
        CTokenKind::Number => Category::Number,
        CTokenKind::String | CTokenKind::RawString => Category::String,
        CTokenKind::Char => Category::Char,
        CTokenKind::LineComment | CTokenKind::BlockComment => Category::Comment,
        CTokenKind::Punct => Category::Punct,
        CTokenKind::Directive | CTokenKind::Unknown => Category::Other,
    }
}

fn dialect_of(name: &str) -> Dialect {
    if name == "cpp" { Dialect::Cpp23 } else { Dialect::C23 }
}

#[test]
fn the_oracle_is_a_real_clang_and_covers_the_corners() {
    let f = fixture();
    assert!(f.clang.contains("clang version"), "captured from: {}", f.clang);
    assert!(f.cases.iter().any(|c| c.text.contains("R\"delim(")), "a raw string");
    assert!(f.cases.iter().any(|c| c.text.contains('\t')), "tabs, where a column is not a glyph");
    assert!(f.cases.iter().any(|c| c.text.contains("caf\u{e9}")), "and text above ASCII");
    assert!(
        f.cases.iter().any(|c| c.text.contains("\\n")),
        "and a line splice, which joins one token across two lines"
    );
}

/// Every token clang reports is at the same place here, is the same kind of
/// thing, and spells the same.
///
/// Aligned by position rather than by index, for one reason worth stating:
/// clang's raw dump **omits a `//` comment that a line splice continued**, while
/// this crate reports it. Comparing index-for-index would desynchronise
/// everything after such a comment and turn one difference into a wall of them.
/// What is asserted instead is precise — every clang token has a counterpart
/// here, and anything extra on this side is a comment.
#[test]
fn every_token_clang_reports_is_here_in_the_same_place() {
    for c in fixture().cases {
        let ours = lex(&c.text, dialect_of(&c.dialect));
        let mut ours_by_pos: std::collections::BTreeMap<(u32, u32), &sda_syntax::CToken> =
            Default::default();
        for t in &ours.tokens {
            ours_by_pos.insert((t.pos.line, t.pos.column), t);
        }

        for theirs in &c.tokens {
            let t = ours_by_pos.remove(&(theirs.line, theirs.column)).unwrap_or_else(|| {
                panic!(
                    "case `{}`: clang has `{}` {:?} at {}:{} and this lexer has no token there",
                    c.name, theirs.kind, theirs.text, theirs.line, theirs.column
                )
            });

            assert_eq!(
                our_category(t.kind),
                clang_category(&theirs.kind),
                "case `{}`: {:?} at {}:{} — clang calls it `{}`",
                c.name,
                t.text(&c.text),
                theirs.line,
                theirs.column,
                theirs.kind
            );

            // Spelling, after undoing line splices.
            //
            // Clang reports a token's *spliced* spelling — `spl\<newline>it` is
            // `split` — while this crate reports the bytes it actually covers,
            // because a linter has to be able to point at the source. Comparing
            // the despliced text asserts the real claim, that both saw the same
            // token, rather than skipping the case.
            let ours_text = t.text(&c.text).replace("\\\r\n", "").replace("\\\n", "");
            assert_eq!(
                ours_text, theirs.text,
                "case `{}`: spelling at {}:{}",
                c.name, theirs.line, theirs.column
            );
        }

        // Anything this lexer reports that clang did not. Only ever a comment,
        // and only ever one a splice continued — clang's raw dump drops those.
        for ((line, column), t) in ours_by_pos {
            assert!(
                t.kind.is_comment(),
                "case `{}`: this lexer has a {:?} at {}:{} that clang does not report: {:?}",
                c.name,
                t.kind,
                line,
                column,
                t.text(&c.text)
            );
        }
    }
}

/// `<::` is `<` then `::`, not the digraph `<:` then `:`.
///
/// C++ makes this one exception to maximal munch so that
/// `std::vector<::Foo>` — a template argument naming something at global scope —
/// lexes as anybody would read it. Without the exception it lexes as
/// `vector[:Foo>`, which is not exotic C++ and was what this crate did until
/// clang disagreed.
#[test]
fn the_scope_operator_wins_over_the_digraph() {
    let text = "int x = a<::b;\n";
    let toks = lex(text, Dialect::Cpp23);
    let spellings: Vec<&str> = toks.tokens.iter().map(|t| t.text(text)).collect();
    assert!(spellings.contains(&"::"), "got {spellings:?}");
    assert!(!spellings.contains(&"<:"), "the digraph must not win here: {spellings:?}");

    // And the exception is exactly that narrow: `<:` is still a digraph where
    // C++ says it is, and C has no such rule at all.
    let arr = "int a<:3:>;\n";
    let c_toks = lex(arr, Dialect::Cpp23);
    assert!(
        c_toks.tokens.iter().any(|t| t.text(arr) == "<:"),
        "`a<:3:>` is still `a[3]`"
    );
    let plain_c = lex(text, Dialect::C23);
    assert!(
        plain_c.tokens.iter().any(|t| t.text(text) == "<:"),
        "C has no `<::` exception, because C has no `::`"
    );
}
