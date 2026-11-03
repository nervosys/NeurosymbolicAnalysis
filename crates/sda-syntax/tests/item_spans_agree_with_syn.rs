//! Where an item begins and ends, according to a real Rust parser.
//!
//! `RustItem::span` and `RustItem::end_line` are the two extents the structure
//! analyser records for an item. HANDOFF named them as the part of `rstruct`
//! that no oracle had compared: kinds and `unsafe` regions were checked, the
//! item extents were not.
//!
//! The oracle is `syn`, called rather than captured, so the comparison always
//! runs against the version in `Cargo.lock`.
//!
//! # What is compared
//!
//! **Top-level items only**, the same set `agrees_with_syn.rs` compares kinds
//! over: syn nests an impl's methods inside the impl and this crate lists them
//! flat, so comparing everything would compare shapes rather than extents.
//!
//! For each item, three things:
//!
//! - **kind**, spelled as `RustItemKind::as_str` spells it;
//! - **start line**, the line of `RustItem::span.start`. The field has no doc
//!   comment of its own. What it covers is read from `collect_items`: it is the
//!   first keyword of the item's header (`pub`, `unsafe`, `const`, `extern`, or
//!   the item keyword itself, whichever comes first). It therefore excludes outer
//!   attributes and doc comments. syn's item span includes them, so the syn side
//!   is translated: the start is the first token after the item's last outer
//!   attribute, skipping whitespace and comments between that attribute and the
//!   item. The `attributes` field documents that attributes sit *above* the item,
//!   which is the same split.
//! - **end line**, `RustItem::end_line`, documented as the last line of the
//!   brace body, and `None` for anything that ends at a semicolon. syn's span
//!   ends just past the item's last token. If that token is `}` the expected
//!   value is that line; if it is `;` the expected value is `None`.
//!
//! Start is compared by line, not column: a keyword and its item share a line
//! in every corpus case, and a column comparison would test the formatting of
//! the corpus rather than where the item begins.

use sda_syntax::analyze_rust;
use syn::spanned::Spanned;

const CORPUS: &str = include_str!("fixtures/rust-struct-corpus.json");

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    text: String,
}

fn corpus() -> Vec<Case> {
    serde_json::from_str(CORPUS).expect("the corpus")
}

/// The character at a one-based line and zero-based column, or `None`.
fn char_at(src: &str, line: usize, column: usize) -> Option<char> {
    src.lines().nth(line.checked_sub(1)?)?.chars().nth(column)
}

/// Byte offset of a one-based line and zero-based character column.
fn offset_of(src: &str, line: usize, column: usize) -> usize {
    let line_start: usize = src.split_inclusive('\n').take(line - 1).map(str::len).sum();
    let rest = &src[line_start..];
    line_start + rest.char_indices().nth(column).map_or(rest.len(), |(i, _)| i)
}

/// One-based line of a byte offset.
fn line_of(src: &str, offset: usize) -> u32 {
    src[..offset].matches('\n').count() as u32 + 1
}

/// Steps over whitespace and comments, which belong to no item.
fn skip_trivia(src: &str, mut at: usize) -> usize {
    loop {
        let rest = &src[at..];
        if let Some(c) = rest.chars().next().filter(|c| c.is_whitespace()) {
            at += c.len_utf8();
        } else if rest.starts_with("//") {
            at += rest.find('\n').map_or(rest.len(), |n| n + 1);
        } else if rest.starts_with("/*") {
            at += rest.find("*/").map_or(rest.len(), |n| n + 2);
        } else {
            return at;
        }
    }
}

/// The kind syn gives a top-level item, with the attributes it carries.
///
/// The same mapping `agrees_with_syn.rs` uses, so the two tests select the same
/// items. Items this crate does not model (`macro_rules!`, `extern crate`,
/// trait aliases, verbatim) are `None`.
fn syn_item(i: &syn::Item) -> Option<(&'static str, &[syn::Attribute])> {
    use syn::Item;
    Some(match i {
        Item::Fn(x) => ("fn", &x.attrs),
        Item::Struct(x) => ("struct", &x.attrs),
        Item::Enum(x) => ("enum", &x.attrs),
        Item::Union(x) => ("union", &x.attrs),
        Item::Trait(x) => ("trait", &x.attrs),
        Item::Mod(x) => ("mod", &x.attrs),
        Item::Const(x) => ("const", &x.attrs),
        Item::Static(x) => (
            match x.mutability {
                syn::StaticMutability::Mut(_) => "static mut",
                _ => "static",
            },
            &x.attrs,
        ),
        Item::Type(x) => ("type", &x.attrs),
        Item::Impl(x) => ("impl", &x.attrs),
        Item::Use(x) => ("use", &x.attrs),
        Item::ForeignMod(x) => ("extern block", &x.attrs),
        _ => return None,
    })
}

/// `(kind, start line, end line)` for each top-level item, as syn sees it and
/// as `RustItem` documents its extents.
fn syn_items(src: &str) -> Vec<(&'static str, u32, Option<u32>)> {
    let file: syn::File = syn::parse_str(src).expect("the corpus is valid Rust");
    file.items
        .iter()
        .filter_map(|item| {
            let (kind, attrs) = syn_item(item)?;
            let span = item.span();

            // START. syn's span begins at the first outer attribute, and a doc
            // comment is one. RustItem's begins at the header keyword, after
            // them. So start after the last outer attribute, past any trivia.
            let item_start = offset_of(src, span.start().line, span.start().column);
            let after_attrs = attrs
                .iter()
                .filter(|a| matches!(a.style, syn::AttrStyle::Outer))
                .map(|a| {
                    let e = a.span().end();
                    offset_of(src, e.line, e.column)
                })
                .max()
                .unwrap_or(item_start);
            let start = skip_trivia(src, after_attrs);

            // END. syn's span ends just past the last token. RustItem records the
            // closing brace of a body, and nothing for an item that ends at `;`.
            let end = span.end();
            let end_line = match char_at(src, end.line, end.column - 1) {
                Some('}') => Some(end.line as u32),
                Some(';') => None,
                other => panic!("item `{kind}` ends in {other:?}, not `}}` or `;`"),
            };

            Some((kind, line_of(src, start), end_line))
        })
        .collect()
}

/// `(kind, start line, end line)` for each top-level item this crate found.
fn our_items(src: &str) -> Vec<(&'static str, u32, Option<u32>)> {
    analyze_rust(src)
        .items
        .iter()
        // Top level only, as `agrees_with_syn.rs` selects them.
        .filter(|i| i.pos.column == 1)
        .map(|i| (i.kind.as_str(), line_of(src, i.span.start), i.end_line))
        .collect()
}

/// The corpus has to contain the ways an item's extent can go wrong, or this
/// passes by never being asked a hard question.
#[test]
fn the_corpus_covers_where_an_item_begins_and_ends() {
    let c = corpus();
    let has = |n: &str| c.iter().any(|x| x.text.contains(n));
    assert!(has("#[derive(Debug, Clone)]\n#[repr(C)]"), "an attribute run above an item");
    assert!(has("#[test]\n// why"), "a comment between an attribute and its item");
    assert!(has("#[cfg(all(\n"), "an attribute spanning several lines");
    assert!(has("/// What this does.\n#[inline]"), "a doc comment above an attribute");
    assert!(has("#![allow(dead_code)]\n#[derive"), "an inner attribute that belongs to no item");
    assert!(has("pub struct Frame"), "a visible item, so the start is the `pub`");
    assert!(has("unsafe fn g()"), "a function whose header begins with a modifier");
    assert!(has("unsafe extern"), "an extern block whose header begins with a modifier");
    assert!(has("struct S;\n"), "an item that ends at a semicolon");
    assert!(has("fn f() { unsafe { let _ = 1; } }"), "an item that ends on the line it starts");
}

/// The claim the two fields make, per item.
#[test]
fn every_top_level_item_starts_and_ends_where_syn_says() {
    for c in corpus() {
        assert_eq!(our_items(&c.text), syn_items(&c.text), "case `{}`: {:?}", c.name, c.text);
    }
}

/// The comparison is not satisfied by having no items to compare.
#[test]
fn the_comparison_is_over_enough_items_to_mean_something() {
    let n: usize = corpus().iter().map(|c| syn_items(&c.text).len()).sum();
    assert!(n >= 40, "only {n} top-level item(s) compared across the whole corpus");
}
