//! The layer that makes it a model rather than a buffer.
//!
//! `agrees_with_monaco.rs` compares this port against Monaco's *buffer*: raw
//! arithmetic over lines and offsets. Above that sits the model, and what
//! separates them is validation. `TextModel.getOffsetAt` validates its argument
//! first, so a column past the end of a line comes back clamped, while the
//! buffer cheerfully returns an offset past the end of the document.
//!
//! `sda-editor` is a port of the *model* — `Position::clamped` exists for exactly
//! this — and until this file existed that layer had never been compared with
//! anything. The other test even says so, in the comment explaining why it skips
//! offsets that split a CRLF pair: "asserting on it would compare our model
//! against Monaco's buffer, which are different layers". This compares the layer
//! it could not.
//!
//! The fixture is what Monaco 0.52.2's real `TextModel` answers, captured by
//! `gui/tools/monaco-model-oracle.mjs`. Hermetic: the answers are committed, so
//! this runs without node or a checkout of Monaco.

use sda_editor::{Position, Range, TextModel};

const CORPUS: &str = include_str!("fixtures/monaco-model.json");

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
    probes: Vec<Probe>,
    ranges: Vec<RangeCase>,
}

/// One position handed to the model, valid or not.
#[derive(serde::Deserialize)]
struct Probe {
    line: u32,
    column: u32,
    /// What `validatePosition` returned, as `[line, column]`.
    valid: (u32, u32),
    /// What `getOffsetAt` returned for the *unvalidated* position.
    offset: usize,
}

#[derive(serde::Deserialize)]
struct RangeCase {
    asked: (u32, u32, u32, u32),
    valid: (u32, u32, u32, u32),
    text: String,
}

fn answers() -> Answers {
    serde_json::from_str(CORPUS).expect("the captured Monaco answers")
}

/// The fixture has to come from the model, and has to contain the positions a
/// buffer comparison could not reach.
#[test]
fn the_oracle_is_a_real_text_model_asked_hard_questions() {
    let a = answers();
    assert!(a.monaco.contains("TextModel"), "captured from: {}", a.monaco);
    assert!(a.cases.len() >= 10);

    let out_of_range = a
        .cases
        .iter()
        .flat_map(|c| c.probes.iter().map(move |p| (c, p)))
        .filter(|(c, p)| p.line == 0 || p.line > c.line_count || p.column == 0)
        .count();
    assert!(
        out_of_range >= 40,
        "the corpus must ask about positions that do not exist: {out_of_range}"
    );
    assert!(
        a.cases.iter().any(|c| c.text.contains("\r\n")),
        "including CRLF, where a position can land between the two halves of a line terminator"
    );
}

/// `Position::clamped` is this port's `validatePosition`.
#[test]
fn a_position_is_validated_the_way_monaco_validates_it() {
    for c in answers().cases {
        let m = TextModel::new(&c.text);
        for p in &c.probes {
            let got = Position::new(p.line, p.column).clamped(&m);
            assert_eq!(
                (got.line, got.column),
                p.valid,
                "case `{}` ({:?}): Monaco validates ({}, {}) to ({}, {})",
                c.name,
                c.text,
                p.line,
                p.column,
                p.valid.0,
                p.valid.1
            );
        }
    }
}

/// And `offset_of` validates before it measures, as `getOffsetAt` does.
///
/// This is the assertion the buffer comparison had to skip.
#[test]
fn an_offset_is_taken_from_the_validated_position() {
    for c in answers().cases {
        let m = TextModel::new(&c.text);
        for p in &c.probes {
            assert_eq!(
                m.offset_of(Position::new(p.line, p.column)),
                p.offset,
                "case `{}` ({:?}): Monaco's getOffsetAt({}, {}) is {}",
                c.name,
                c.text,
                p.line,
                p.column,
                p.offset
            );
        }
    }
}

/// A range is validated end by end, and its text taken from the result — which
/// is what the workbench calls to draw a finding's snippet.
#[test]
fn a_range_is_validated_and_sliced_the_way_monaco_does_it() {
    for c in answers().cases {
        let m = TextModel::new(&c.text);
        for r in &c.ranges {
            let (sl, sc, el, ec) = r.asked;
            let asked = Range::new(Position::new(sl, sc), Position::new(el, ec));
            let valid = asked.clamped(&m);
            assert_eq!(
                (valid.start.line, valid.start.column, valid.end.line, valid.end.column),
                r.valid,
                "case `{}`: Monaco validates {:?} to {:?}",
                c.name,
                r.asked,
                r.valid
            );
            assert_eq!(
                m.text_in(asked),
                r.text,
                "case `{}`: Monaco's getValueInRange{:?} is {:?}",
                c.name,
                r.asked,
                r.text
            );
        }
    }
}
