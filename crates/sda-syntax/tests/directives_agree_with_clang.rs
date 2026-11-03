//! How far a preprocessing directive reaches, according to clang.
//!
//! Item 25. Neither lexer oracle covered directives, because this crate emits a
//! whole `#...` line as a single token while clang tokenizes inside it — a
//! difference of layer. That left `parse_directives` unchecked, and the
//! interesting part of it is exactly where a hand-written rule goes wrong: a
//! directive continued by a trailing backslash, where getting the extent wrong
//! silently swallows the line beneath or stops short of the body.
//!
//! # The oracle, and why it is clang's answer rather than a rule restated here
//!
//! `-dump-raw-tokens` marks a token with `[StartOfLine]` when it begins a
//! *logical* line, and a line splice does not begin one: in a continued
//! `#define`, the tokens on the second physical line do not carry the flag.
//! Checked against clang before it was relied on. So a directive runs from a
//! `hash` carrying `[StartOfLine]` up to, and not including, the next token that
//! carries it — which is clang's own account of the extent, not a reimplementation
//! of the splice rule this crate is being tested on.

use sda_syntax::{CTokenKind, Dialect, lex};

const FIXTURE: &str = include_str!("fixtures/c-directives.json");

#[derive(serde::Deserialize)]
struct Fixture {
    clang: String,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    text: String,
    tokens: Vec<ClangToken>,
}

#[derive(serde::Deserialize)]
struct ClangToken {
    kind: String,
    text: String,
    line: u32,
    column: u32,
    #[serde(rename = "startOfLine")]
    start_of_line: bool,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("the captured clang answers")
}

/// Where a directive starts and where it ends, both 1-based, end exclusive.
type Extent = (Position, Position);

/// `(line, column)`.
type Position = (u32, u32);

/// Every directive's extent, as clang's `[StartOfLine]` flags imply.
fn clang_directives(tokens: &[ClangToken]) -> Vec<Extent> {
    let mut out = Vec::new();
    let mut current: Option<(bool, Position, Position)> = None;
    for t in tokens {
        if t.start_of_line {
            if let Some((is_directive, start, end)) = current.take()
                && is_directive {
                    out.push((start, end));
                }
            current = Some((t.kind == "hash", (t.line, t.column), (t.line, t.column)));
        }
        if let Some((_, _, end)) = current.as_mut() {
            *end = (t.line, t.column + t.text.chars().count() as u32);
        }
    }
    if let Some((is_directive, start, end)) = current
        && is_directive {
            out.push((start, end));
        }
    out
}

#[test]
fn the_corpus_covers_the_ways_a_directive_can_run_on() {
    let f = fixture();
    assert!(f.clang.contains("clang version"), "captured from: {}", f.clang);
    let has = |n: &str| f.cases.iter().any(|c| c.text.contains(n));
    // Written by scanning characters rather than as a string literal: a
    // backslash before a newline is exactly the thing this corpus is about,
    // and spelling it in an escape is how it gets lost between here and the
    // file on disk.
    let splices = |t: &str| {
        t.as_bytes()
            .windows(2)
            .filter(|w| w[0] == b'\\' && w[1] == b'\n')
            .count()
    };
    assert!(
        f.cases.iter().any(|c| splices(&c.text) >= 1),
        "a directive continued by a trailing backslash"
    );
    assert!(
        f.cases.iter().any(|c| splices(&c.text) >= 2),
        "and one continued twice, where an off-by-one line shows up"
    );
    assert!(has("#  define"), "a hash separated from its directive name");
    assert!(has("/* why */"), "and a directive with a trailing comment");
}

#[test]
fn a_directive_reaches_exactly_as_far_as_clang_says() {
    for c in fixture().cases {
        let lexed = lex(&c.text, Dialect::C23);
        let ours: Vec<Extent> = lexed
            .tokens
            .iter()
            .filter(|t| t.kind == CTokenKind::Directive)
            .map(|t| {
                let end = lexed.lines.pos(t.span.end);
                ((t.pos.line, t.pos.column), (end.line, end.column))
            })
            .collect();

        assert_eq!(ours, clang_directives(&c.tokens), "case `{}`: {:?}", c.name, c.text);
    }
}
