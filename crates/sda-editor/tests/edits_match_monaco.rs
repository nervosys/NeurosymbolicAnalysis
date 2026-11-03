//! Applying several edits at once, compared against Monaco.
//!
//! This is the multi-cursor contract: every range is stated against the text as
//! the caller last saw it, and they are applied together. `apply_all` claims
//! exactly that, and until this file existed the claim was checked only against
//! the author's own expectation of it — the same gap the position and stickiness
//! oracles closed.
//!
//! The fixture is what Monaco 0.52.2's own `applyEdits` produces, captured by
//! `gui/tools/monaco-edits.mjs`. What is compared is the resulting text: it is
//! the observable both sides must agree on, and the change records Monaco
//! returns are a different shape from `ChangeEvent` by design.

use sda_editor::model::{TextEdit, TextModel};
use sda_editor::{Position, Range};

const FIXTURE: &str = include_str!("fixtures/monaco-edits.json");

#[derive(serde::Deserialize)]
struct Fixture {
    monaco: String,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    text: String,
    edits: Vec<Edit>,
    #[serde(rename = "resultLines")]
    result_lines: Vec<String>,
}

#[derive(serde::Deserialize)]
struct Edit {
    sl: u32,
    sc: u32,
    el: u32,
    ec: u32,
    text: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("the captured Monaco answers")
}

/// Lines as Monaco reports them, so the comparison is about edit application
/// rather than about which terminator a buffer chose to keep.
fn lines_of(m: &TextModel) -> Vec<String> {
    (1..=m.line_count()).map(|l| m.line(l)).collect()
}

#[test]
fn the_oracle_covers_more_than_the_easy_cases() {
    let f = fixture();
    assert!(!f.monaco.is_empty());
    assert!(
        f.cases.iter().any(|c| c.edits.len() >= 3),
        "several cursors at once is the case this contract exists for"
    );
    assert!(
        f.cases.iter().any(|c| c.text.contains('\u{1F600}')),
        "and one where a column is not a character"
    );
    assert!(
        f.cases.iter().any(|c| {
            let mut sorted = c.edits.iter().map(|e| (e.sl, e.sc)).collect::<Vec<_>>();
            let given = sorted.clone();
            sorted.sort();
            given != sorted
        }),
        "and one given out of document order, which is what makes ordering a question"
    );
}

#[test]
fn several_edits_land_where_monaco_puts_them() {
    for c in fixture().cases {
        let mut m = TextModel::new(&c.text);
        let edits: Vec<TextEdit> = c
            .edits
            .iter()
            .map(|e| {
                TextEdit::replace(
                    Range::new(Position::new(e.sl, e.sc), Position::new(e.el, e.ec)),
                    e.text.clone(),
                )
            })
            .collect();
        m.apply_all(&edits);

        assert_eq!(
            lines_of(&m),
            c.result_lines,
            "case `{}`: {:?} with {} edit(s)",
            c.name,
            c.text,
            c.edits.len()
        );
    }
}

/// Overlapping ranges have no joint meaning, and both refuse them — Monaco by
/// throwing, this crate by returning no events. The mechanisms differ because
/// the languages do; what a caller depends on is the same, and it is the part
/// worth pinning: **neither applies half of it**.
///
/// Read from the capture rather than from memory of what Monaco does.
#[test]
fn overlapping_edits_are_refused_by_both_and_change_nothing() {
    #[derive(serde::Deserialize)]
    struct Overlap {
        refused: bool,
        #[serde(rename = "resultLines")]
        result_lines: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct WithOverlap {
        overlapping: Overlap,
    }

    let o: WithOverlap = serde_json::from_str(FIXTURE).expect("the capture records the overlap case");
    assert!(o.overlapping.refused, "Monaco refuses overlapping ranges");

    // The same two ranges the oracle used: [1,2)-(1,5) and (1,3)-(1,6).
    let mut m = TextModel::new("abcdef\n");
    let before = lines_of(&m);
    let events = m.apply_all(&[
        TextEdit::replace(Range::new(Position::new(1, 2), Position::new(1, 5)), "X"),
        TextEdit::replace(Range::new(Position::new(1, 3), Position::new(1, 6)), "Y"),
    ]);

    assert!(events.is_empty(), "no edit is reported, because none was applied");
    assert_eq!(lines_of(&m), before, "and the buffer is untouched");
    assert_eq!(
        lines_of(&m),
        o.overlapping.result_lines,
        "which is where Monaco's buffer is left too"
    );
}
