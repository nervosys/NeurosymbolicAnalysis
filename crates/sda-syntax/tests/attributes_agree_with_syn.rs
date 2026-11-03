//! Which attributes belong to which item, according to a real Rust parser.
//!
//! `RustItem::attributes` is a public field documented as "attributes written
//! immediately above this item". Nothing ever wrote to it: every item carried an
//! empty list, so a consumer asking whether a function is `#[test]` or
//! `#[no_mangle]` was told "no" for all of them. That is this repository's own
//! failure shape in a struct field — an absence of knowledge presented as
//! knowledge of an absence — and it is why this file exists rather than a test of
//! the porter's expectations.
//!
//! The oracle is `syn`, called rather than captured, so the comparison always
//! runs against the version in `Cargo.lock`.
//!
//! # What is compared, and what is not
//!
//! **Attribute paths, per item, in source order.** `#[derive(Debug)]` and
//! `#[cfg(all(feature = "a", not(test)))]` both reduce to their path — `derive`,
//! `cfg` — because the argument text is formatting, and syn's is normalised
//! while this crate's is verbatim. Comparing the text would compare whitespace.
//! What has teeth is *which attribute is attached to which item*.
//!
//! **Doc comments are excluded, and the reason is a real difference.** syn turns
//! `/// text` into a synthesised `#[doc = " text"]` attribute; this crate lexes
//! it as a comment, because it is one. Neither reading is wrong. The filter
//! below keeps only attributes whose source actually begins with `#`, so the
//! comparison is over attributes somebody wrote as attributes.

use sda_syntax::{RustItemKind, analyze_rust};
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

/// `#[cfg(all(...))]` becomes `cfg`; `#[clippy::x]` becomes `clippy::x`.
fn path_of(attr_text: &str) -> String {
    let inner = attr_text
        .trim_start_matches("#!")
        .trim_start_matches('#')
        .trim_start_matches('[')
        .trim_end_matches(']');
    let head: String = inner
        .chars()
        .take_while(|c| *c != '(' && *c != '=' && *c != '[')
        .collect();
    head.split_whitespace().collect()
}

/// The character at a one-based line and zero-based column, or `None`.
fn char_at(src: &str, line: usize, column: usize) -> Option<char> {
    src.lines().nth(line.checked_sub(1)?)?.chars().nth(column)
}

/// A path as written, without pulling in `quote` for one string.
fn path_text(p: &syn::Path) -> String {
    p.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::")
}

/// Items syn recognises, as `(kind, attribute paths)`, in source order.
///
/// Walked rather than read off `File::items`, because `rstruct` has a *flat*
/// model: a method in a trait or an `impl`, and a declaration in an
/// `extern` block, are all items to it. Comparing against syn's top level only
/// would compare two different questions and fail on a corpus with no
/// attributes in it at all.
fn syn_items(src: &str) -> Vec<(&'static str, Vec<String>)> {
    fn kept(src: &str, attrs: &[syn::Attribute]) -> Vec<String> {
        attrs
            .iter()
            .filter(|a| matches!(a.style, syn::AttrStyle::Outer))
            // A doc comment is a synthesised attribute; its source does not
            // start with `#`, and this crate calls it a comment.
            .filter(|a| {
                let s = a.span().start();
                char_at(src, s.line, s.column) == Some('#')
            })
            .map(|a| path_of(&path_text(a.path())))
            .collect()
    }

    struct V<'a> {
        src: &'a str,
        out: Vec<(&'static str, Vec<String>)>,
    }
    impl<'a> V<'a> {
        fn push(&mut self, kind: &'static str, attrs: &[syn::Attribute]) {
            let a = kept(self.src, attrs);
            self.out.push((kind, a));
        }
    }
    impl<'ast> syn::visit::Visit<'ast> for V<'_> {
        fn visit_item(&mut self, i: &'ast syn::Item) {
            use syn::Item;
            match i {
                Item::Fn(x) => self.push("fn", &x.attrs),
                Item::Struct(x) => self.push("struct", &x.attrs),
                Item::Enum(x) => self.push("enum", &x.attrs),
                Item::Union(x) => self.push("union", &x.attrs),
                Item::Trait(x) => self.push("trait", &x.attrs),
                Item::Mod(x) => self.push("mod", &x.attrs),
                Item::Const(x) => self.push("const", &x.attrs),
                Item::Static(x) => self.push(
                    match x.mutability {
                        syn::StaticMutability::Mut(_) => "static mut",
                        _ => "static",
                    },
                    &x.attrs,
                ),
                Item::Type(x) => self.push("type", &x.attrs),
                Item::Impl(x) => self.push("impl", &x.attrs),
                Item::Use(x) => self.push("use", &x.attrs),
                Item::ForeignMod(x) => self.push("extern block", &x.attrs),
                _ => {}
            }
            syn::visit::visit_item(self, i);
        }
        fn visit_trait_item_fn(&mut self, i: &'ast syn::TraitItemFn) {
            self.push("fn", &i.attrs);
            syn::visit::visit_trait_item_fn(self, i);
        }
        fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
            self.push("fn", &i.attrs);
            syn::visit::visit_impl_item_fn(self, i);
        }
        fn visit_foreign_item_fn(&mut self, i: &'ast syn::ForeignItemFn) {
            self.push("fn", &i.attrs);
            syn::visit::visit_foreign_item_fn(self, i);
        }
    }

    let file: syn::File = syn::parse_str(src).expect("the corpus is valid Rust");
    let mut v = V { src, out: Vec::new() };
    syn::visit::Visit::visit_file(&mut v, &file);
    v.out
}

fn our_items(src: &str) -> Vec<(&'static str, Vec<String>)> {
    let st = analyze_rust(src);
    st.items
        .iter()
        .filter_map(|i| {
            let k = match i.kind {
                RustItemKind::Function => "fn",
                RustItemKind::Struct => "struct",
                RustItemKind::Enum => "enum",
                RustItemKind::Union => "union",
                RustItemKind::Trait => "trait",
                RustItemKind::Module => "mod",
                RustItemKind::Const => "const",
                RustItemKind::Static => "static",
                RustItemKind::StaticMut => "static mut",
                RustItemKind::TypeAlias => "type",
                RustItemKind::Impl => "impl",
                RustItemKind::Use => "use",
                RustItemKind::ExternBlock => "extern block",
                _ => return None,
            };
            Some((k, i.attributes.iter().map(|a| path_of(a)).collect()))
        })
        .collect()
}

/// The corpus has to contain the ways attachment goes wrong, or this passes by
/// never being asked a hard question.
#[test]
fn the_corpus_covers_the_ways_an_attribute_can_be_misattached() {
    let c = corpus();
    let has = |n: &str| c.iter().any(|x| x.text.contains(n));
    assert!(has("bracket\"]"), "a `]` inside a string inside an attribute");
    assert!(has("#![allow(dead_code)]"), "an inner attribute above an item");
    assert!(has("// why this is a test"), "a comment between an attribute and its item");
    assert!(has("#[cfg(all("), "an attribute spanning several lines");
    assert!(
        c.iter().any(|x| x.text.contains("struct A;\nstruct B;")),
        "an item with no attributes directly after one that has them"
    );
    assert!(has("/// What this does."), "a doc comment, which syn calls an attribute");
}

/// The claim the field makes.
#[test]
fn every_item_carries_the_attributes_syn_gives_it() {
    for c in corpus() {
        assert_eq!(our_items(&c.text), syn_items(&c.text), "case `{}`: {:?}", c.name, c.text);
    }
}

/// And the field is actually populated — an empty list everywhere would satisfy
/// the comparison above on any corpus whose items have no attributes, which is
/// precisely the state this file was written to end.
#[test]
fn the_comparison_is_not_satisfied_by_emptiness() {
    let attached: usize = corpus()
        .iter()
        .map(|c| our_items(&c.text).iter().map(|(_, a)| a.len()).sum::<usize>())
        .sum();
    assert!(attached >= 12, "only {attached} attribute(s) attached across the whole corpus");
}
