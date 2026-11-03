//! The Rust lexer, compared against rustc's.
//!
//! The C lexer met clang and lost on `<::`; this is the same question asked of
//! the Rust side, which fed every `RUST-2024` finding and had no oracle at all.
//!
//! The oracle is `ra-ap-rustc_lexer`, the rust-analyzer team's automatically
//! published mirror of the compiler's own `rustc_lexer` — the same code rustc
//! runs, not a description of it.
//!
//! # Why there is no fixture here, and there is one for clang
//!
//! clang is an external program that may not be installed, so its answers are
//! captured to a file and the test replays them. A Rust crate is fetched by
//! cargo like any other dependency, so the oracle can simply be called: the
//! comparison is then always against the version in `Cargo.lock` rather than
//! against a capture that can quietly age.
//!
//! # What is deliberately not compared
//!
//! Attributes. This crate captures `#[...]` whole, as it captures a C
//! preprocessing directive whole; rustc's lexer emits `#`, `[`, tokens, `]`.
//! That is a difference of layer rather than of lexing, and mixing it in would
//! bury the comparison under a known disagreement.

use ra_ap_rustc_lexer::{FrontmatterAllowed, LiteralKind, TokenKind as RustcKind, tokenize};
use sda_syntax::{RTokenKind, lex_rust};

const CORPUS: &str = include_str!("fixtures/rust-lex-corpus.json");

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    text: String,
}

fn corpus() -> Vec<Case> {
    serde_json::from_str(CORPUS).expect("the lexical corpus")
}

/// The categories both lexers have an opinion about. rustc names every operator
/// separately and this crate calls them all punctuation, so comparing kinds
/// directly would compare vocabularies rather than behaviour.
#[derive(Debug, PartialEq, Eq)]
enum Category {
    Word,
    Lifetime,
    Number,
    String,
    ByteString,
    Char,
    Comment,
    DocComment,
    Punct,
    Unknown,
}

fn rustc_category(k: &RustcKind) -> Category {
    match k {
        RustcKind::Ident | RustcKind::RawIdent => Category::Word,
        RustcKind::Lifetime { .. } | RustcKind::RawLifetime => Category::Lifetime,
        RustcKind::LineComment { doc_style } | RustcKind::BlockComment { doc_style, .. } => {
            if doc_style.is_some() { Category::DocComment } else { Category::Comment }
        }
        RustcKind::Literal { kind, .. } => match kind {
            LiteralKind::Int { .. } | LiteralKind::Float { .. } => Category::Number,
            LiteralKind::Char { .. } => Category::Char,
            LiteralKind::Str { .. } | LiteralKind::RawStr { .. } => Category::String,
            LiteralKind::Byte { .. }
            | LiteralKind::ByteStr { .. }
            | LiteralKind::RawByteStr { .. }
            | LiteralKind::CStr { .. }
            | LiteralKind::RawCStr { .. } => Category::ByteString,
        },
        RustcKind::Unknown | RustcKind::InvalidIdent => {
            Category::Unknown
        }
        _ => Category::Punct,
    }
}

fn our_category(k: RTokenKind) -> Category {
    match k {
        RTokenKind::Identifier | RTokenKind::Keyword => Category::Word,
        RTokenKind::Lifetime => Category::Lifetime,
        RTokenKind::Number => Category::Number,
        RTokenKind::String | RTokenKind::RawString => Category::String,
        RTokenKind::ByteString => Category::ByteString,
        RTokenKind::Char => Category::Char,
        RTokenKind::LineComment | RTokenKind::BlockComment => Category::Comment,
        RTokenKind::DocComment => Category::DocComment,
        RTokenKind::Punct => Category::Punct,
        RTokenKind::Attribute | RTokenKind::Unknown => Category::Unknown,
    }
}

/// A comparable view of a token stream.
///
/// Punctuation is **collapsed into runs**, and that is not a convenience.
/// `rustc_lexer` is a raw lexer: it emits `-` and `>` and leaves gluing them
/// into `->` to the parser, while this crate produces the compound punctuator
/// directly. Comparing punctuation token-for-token would compare layers rather
/// than lexing, and would report a disagreement on every arrow, shift and range
/// operator in the language.
///
/// What survives collapsing is the claim that matters: every identifier,
/// literal, lifetime and comment is at the same offset with the same text and
/// the same kind, and the punctuation between any two of them spells the same.
/// A punctuator that swallowed part of a literal — the failure this could
/// plausibly have — still shows up, because the literal's offset moves.
#[derive(Debug, PartialEq, Eq)]
enum Item {
    Token(usize, String, Category),
    /// A maximal run of punctuation, and where it starts.
    Punctuation(usize, String),
}

fn collapse(tokens: impl IntoIterator<Item = (usize, String, Category)>) -> Vec<Item> {
    let mut out: Vec<Item> = Vec::new();
    for (offset, text, category) in tokens {
        if category == Category::Punct {
            match out.last_mut() {
                Some(Item::Punctuation(_, run)) => run.push_str(&text),
                _ => out.push(Item::Punctuation(offset, text)),
            }
        } else {
            out.push(Item::Token(offset, text, category));
        }
    }
    out
}

fn rustc_items(src: &str) -> Vec<Item> {
    let mut raw = Vec::new();
    let mut at = 0usize;
    for t in tokenize(src, FrontmatterAllowed::No) {
        let end = (at + t.len as usize).min(src.len());
        if !matches!(t.kind, RustcKind::Whitespace) {
            raw.push((at, src[at..end].to_string(), rustc_category(&t.kind)));
        }
        at = end;
    }
    collapse(raw)
}

#[test]
fn the_corpus_covers_the_corners_that_separate_the_two() {
    let c = corpus();
    let has = |needle: &str| c.iter().any(|x| x.text.contains(needle));
    assert!(has("'a>"), "a lifetime, which is spelled like an unterminated char literal");
    assert!(has("/* outer /*"), "a nested block comment, which C does not have");
    assert!(has("r##\""), "a raw string with more than one hash");
    assert!(has("c\"cstr\""), "and a C string literal");
    assert!(has("r#fn"), "and a raw identifier");
}

#[test]
fn every_token_is_where_rustc_puts_it() {
    for c in corpus() {
        let ours = lex_rust(&c.text);
        // Attributes are captured whole here and tokenized by rustc; the corpus
        // has none, and this asserts that rather than trusting it.
        assert!(
            !ours.tokens.iter().any(|t| t.kind == RTokenKind::Attribute),
            "case `{}` has an attribute, which the two lex at different layers",
            c.name
        );

        let mine = collapse(
            ours.tokens
                .iter()
                .map(|t| (t.span.start, t.text(&c.text).to_string(), our_category(t.kind))),
        );

        assert_eq!(mine, rustc_items(&c.text), "case `{}`: {:?}", c.name, c.text);
    }
}
