//! The port, compared against the thing it is a port of.
//!
//! `sda-editor` says it is "a Rust-native port of Monaco's text model", and
//! until this file existed that claim rested on the porter's own expectations —
//! forty-nine tests, every one asserting what the author believed Monaco does.
//! The fixture here is what Monaco 0.52.2 actually answers, captured from its
//! own `createTextBuffer` by `gui/tools/monaco-oracle.mjs`.
//!
//! Hermetic on purpose: the answers are committed, so this runs without node or
//! a checkout of Monaco. Re-run the oracle to refresh them when Monaco moves.

use sda_editor::TextModel;

const CORPUS: &str = include_str!("fixtures/monaco-answers.json");

#[derive(serde::Deserialize)]
struct Answers {
    monaco: String,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    text: String,
    #[serde(rename = "lineCount")]
    line_count: u32,
    length: usize,
    lines: Vec<Line>,
    /// `[offset, line, column]`, for every offset in the document.
    offsets: Vec<(usize, u32, u32)>,
}

#[derive(serde::Deserialize)]
struct Line {
    line: u32,
    content: String,
    length: u32,
}

fn answers() -> Answers {
    serde_json::from_str(CORPUS).expect("the captured Monaco answers")
}

/// The fixture has to be Monaco's, not ours.
#[test]
fn the_oracle_is_a_real_monaco() {
    let a = answers();
    assert!(!a.monaco.is_empty(), "the capture records which Monaco answered");
    assert!(a.cases.len() >= 10, "and covers more than a happy path");
    assert!(
        a.cases.iter().any(|c| c.text.contains('\u{1F600}')),
        "including text where a UTF-16 column and a character column differ, which is the \
         disagreement a port is most likely to have"
    );
    assert!(
        a.cases.iter().any(|c| c.text.contains("\r\n")),
        "and CRLF, where a line terminator is two code units"
    );
}

#[test]
fn line_content_agrees() {
    for c in answers().cases {
        let m = TextModel::new(&c.text);
        for l in &c.lines {
            assert_eq!(
                m.line(l.line),
                l.content,
                "case `{}` line {}: Monaco says {:?}",
                c.name,
                l.line,
                l.content
            );
        }
    }
}

#[test]
fn line_count_agrees() {
    for c in answers().cases {
        let m = TextModel::new(&c.text);
        assert_eq!(
            m.line_count(),
            c.line_count,
            "case `{}` ({:?}): Monaco counts {} line(s)",
            c.name,
            c.text,
            c.line_count
        );
    }
}

/// Columns are documented as UTF-16 code units, "so that positions round-trip
/// through a JavaScript host unchanged" — which is what the workbench does on
/// every finding it draws.
#[test]
fn line_length_agrees() {
    for c in answers().cases {
        let m = TextModel::new(&c.text);
        for l in &c.lines {
            assert_eq!(
                m.line_length(l.line),
                l.length,
                "case `{}` line {} ({:?}): Monaco measures {}",
                c.name,
                l.line,
                l.content,
                l.length
            );
        }
    }
}

/// Every offset in every case, because the disagreements live at the seams —
/// the code unit after an astral character, the last offset in the document —
/// and a sample chosen by whoever wrote the port would miss exactly those.
#[test]
fn offset_and_position_round_trip_the_way_monaco_does() {
    for c in answers().cases {
        let m = TextModel::new(&c.text);
        assert_eq!(
            m.len_utf16(),
            c.length,
            "case `{}`: Monaco measures the whole document at {} code unit(s)",
            c.name,
            c.length
        );
        for (offset, line, column) in &c.offsets {
            let p = m.position_of(*offset);
            assert_eq!(
                (p.line, p.column),
                (*line, *column),
                "case `{}` offset {}: Monaco says ({}, {})",
                c.name,
                offset,
                line,
                column
            );
            // The round trip, everywhere a position is reachable.
            //
            // Skipped between the halves of a CRLF, and the reason is a real
            // difference worth stating rather than hiding. Monaco's *buffer* is
            // raw arithmetic — getOffsetAt(1, 20) on a three-character line
            // cheerfully returns 19, past the end of the document — while
            // TextModel.getOffsetAt validates the position first. offset_of
            // here is the model-level operation and validates, so it clamps a
            // column that has run into a line terminator; position_of matches
            // the raw buffer and can produce such a column. Every position a
            // cursor can occupy round-trips; an offset that splits a CRLF pair
            // is not one, and asserting on it would compare our model against
            // Monaco's buffer, which are different layers.
            let units: Vec<u16> = c.text.encode_utf16().collect();
            let inside_crlf = *offset > 0
                && units.get(*offset) == Some(&u16::from(b'\n'))
                && units.get(offset - 1) == Some(&u16::from(b'\r'));
            if !inside_crlf {
                assert_eq!(
                    m.offset_of(p),
                    *offset,
                    "case `{}`: position ({}, {}) must map back to offset {}",
                    c.name,
                    line,
                    column,
                    offset
                );
            }
        }
    }
}
