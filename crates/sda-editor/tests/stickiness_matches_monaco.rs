//! What stickiness means at an edge, checked against Monaco rather than against
//! its own name.
//!
//! `Stickiness`'s variants carry Monaco's names, so a reader is entitled to
//! Monaco's meanings. Two of the three doc comments used to describe the
//! opposite, and the code implemented a third thing again: stickiness was only
//! ever consulted at the *end* edge, which made `GrowsOnlyWhenTypingBefore` —
//! whose entire purpose is the start edge — behave identically to
//! `NeverGrowsWhenTypingAtEdges`.
//!
//! The fixture is Monaco's own `nodeAcceptEdit`, captured by
//! `gui/tools/monaco-stickiness.mjs`.
//!
//! # What this does and does not compare
//!
//! The **edge** semantics, which is where the names make a promise. Monaco keeps
//! a decoration whose text was destroyed, collapsed to a point; this crate drops
//! it, deliberately and with a stated reason — an anchor left on whatever moved
//! into that position points a reviewer at unrelated code. That divergence is a
//! decision, not a defect, so the destructive cases are read from the fixture and
//! asserted to be exactly the ones that differ.

use sda_editor::model::{ChangeEvent, TextEdit, TextModel};
use sda_editor::{Decoration, DecorationKind, Position, Range, Stickiness};

const FIXTURE: &str = include_str!("fixtures/monaco-stickiness.json");

#[derive(serde::Deserialize)]
struct Fixture {
    cases: Vec<MonacoCase>,
}

#[derive(serde::Deserialize)]
struct MonacoCase {
    stickiness: String,
    edit: String,
    start: usize,
    end: usize,
}

fn monaco(edit: &str, stickiness: &str) -> (usize, usize) {
    let f: Fixture = serde_json::from_str(FIXTURE).expect("the captured Monaco answers");
    let c = f
        .cases
        .iter()
        .find(|c| c.edit == edit && c.stickiness == stickiness)
        .unwrap_or_else(|| panic!("no captured case for {stickiness} / {edit}"));
    (c.start, c.end)
}

/// One line of text so that offsets and columns coincide, which keeps the
/// comparison about stickiness rather than about position arithmetic — that is
/// what `agrees_with_monaco.rs` is for.
fn decorated(stickiness: Stickiness) -> (TextModel, Decoration) {
    let m = TextModel::new("0123456789abcdefghij");
    let d = Decoration {
        id: "d1".to_string(),
        range: Range::new(Position::new(1, 6), Position::new(1, 11)), // offsets 5..10
        kind: DecorationKind::Suppressed,
        message: "under test".to_string(),
        stickiness,
        source: "test".to_string(),
    };
    (m, d)
}

fn insert_at(m: &mut TextModel, column: u32, text: &str) -> ChangeEvent {
    m.apply(&TextEdit::insert(Position::new(1, column), text))
}

/// Columns are 1-based and offsets 0-based, on a single line.
fn offsets(d: &Decoration) -> (usize, usize) {
    ((d.range.start.column - 1) as usize, (d.range.end.column - 1) as usize)
}

fn check(stickiness: Stickiness, name: &str, edit_name: &str, at_column: u32) {
    let (mut m, d) = decorated(stickiness);
    let change = insert_at(&mut m, at_column, "xyz");
    let adjusted = sda_editor::decorations::adjust(&d, &change)
        .unwrap_or_else(|| panic!("{name}: {edit_name} must not destroy the decoration"));
    assert_eq!(
        offsets(&adjusted),
        monaco(edit_name, name),
        "{name}: {edit_name}"
    );
}

#[test]
fn an_insertion_at_the_start_edge_follows_monaco() {
    check(
        Stickiness::AlwaysGrowsWhenTypingAtEdges,
        "always-grows-when-typing-at-edges",
        "insert at the range start",
        6,
    );
    check(
        Stickiness::GrowsOnlyWhenTypingBefore,
        "grows-only-when-typing-before",
        "insert at the range start",
        6,
    );
    check(
        Stickiness::NeverGrowsWhenTypingAtEdges,
        "never-grows-when-typing-at-edges",
        "insert at the range start",
        6,
    );
}

#[test]
fn an_insertion_at_the_end_edge_follows_monaco() {
    for (s, name) in [
        (Stickiness::AlwaysGrowsWhenTypingAtEdges, "always-grows-when-typing-at-edges"),
        (Stickiness::GrowsOnlyWhenTypingBefore, "grows-only-when-typing-before"),
        (Stickiness::NeverGrowsWhenTypingAtEdges, "never-grows-when-typing-at-edges"),
    ] {
        check(s, name, "insert at the range end", 11);
    }
}

#[test]
fn insertions_away_from_the_edges_follow_monaco() {
    for (s, name) in [
        (Stickiness::AlwaysGrowsWhenTypingAtEdges, "always-grows-when-typing-at-edges"),
        (Stickiness::GrowsOnlyWhenTypingBefore, "grows-only-when-typing-before"),
        (Stickiness::NeverGrowsWhenTypingAtEdges, "never-grows-when-typing-at-edges"),
    ] {
        check(s, name, "insert strictly before", 3);
        check(s, name, "insert strictly after", 13);
    }
}

/// The two edges must be distinguishable, or the enum is decoration.
///
/// This is the assertion that would have caught the original defect on its own:
/// `GrowsOnlyWhenTypingBefore` and `NeverGrowsWhenTypingAtEdges` behaved
/// identically for every input, so one of the three names was a lie.
#[test]
fn the_three_stickinesses_are_actually_distinguishable() {
    let at_start = |s| {
        let (mut m, d) = decorated(s);
        let c = insert_at(&mut m, 6, "xyz");
        offsets(&sda_editor::decorations::adjust(&d, &c).unwrap())
    };
    let at_end = |s| {
        let (mut m, d) = decorated(s);
        let c = insert_at(&mut m, 11, "xyz");
        offsets(&sda_editor::decorations::adjust(&d, &c).unwrap())
    };

    let always = (at_start(Stickiness::AlwaysGrowsWhenTypingAtEdges), at_end(Stickiness::AlwaysGrowsWhenTypingAtEdges));
    let before = (at_start(Stickiness::GrowsOnlyWhenTypingBefore), at_end(Stickiness::GrowsOnlyWhenTypingBefore));
    let never = (at_start(Stickiness::NeverGrowsWhenTypingAtEdges), at_end(Stickiness::NeverGrowsWhenTypingAtEdges));

    assert_ne!(always, before, "`always` must absorb at the end where `before` does not");
    assert_ne!(before, never, "`before` must absorb at the start where `never` does not");
    assert_ne!(always, never);
}

/// The deliberate divergence, asserted so it stays deliberate. Monaco keeps a
/// decoration whose text was deleted, collapsed to a point; this crate drops it,
/// because an anchor on whatever moved into that position points a reviewer at
/// code that has nothing to do with the finding.
#[test]
fn a_decoration_whose_text_was_destroyed_is_dropped_where_monaco_keeps_it() {
    let (kept_start, kept_end) = monaco("delete the whole range", "never-grows-when-typing-at-edges");
    assert_eq!(kept_start, kept_end, "Monaco collapses it to a point rather than dropping it");

    let (mut m, d) = decorated(Stickiness::NeverGrowsWhenTypingAtEdges);
    let change = m.apply(&TextEdit::delete(Range::new(
        Position::new(1, 6),
        Position::new(1, 11),
    )));
    assert!(
        sda_editor::decorations::adjust(&d, &change).is_none(),
        "this crate drops it, on purpose"
    );
}
