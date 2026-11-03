//! The Rust structure analyser, compared against a real Rust parser.
//!
//! `cstruct`'s return-finding is checked against clang's AST; this is the same
//! question asked of `rstruct`, which was checked only against its own
//! expectations — and the lexer directly beneath it turned out to have four
//! defects, which is a reason to look here.
//!
//! The oracle is `syn`, the parser every procedural macro in the ecosystem is
//! built on. Called rather than captured, for the same reason `rustc_lexer` is:
//! a crate is fetched by cargo, so the comparison is always against the version
//! in `Cargo.lock`.
//!
//! # What is compared
//!
//! **`unsafe { }` regions**, start and end line. That is the claim with teeth.
//! `UnsafeRegion::end_line` exists so `correlate::near` can decide that a runtime
//! defect reported below an `unsafe` keyword is *inside the region the finding is
//! about* — and it is found by walking braces by hand. A matcher that miscounts
//! inside a string or a comment attributes a Miri violation to the wrong block,
//! or to none.
//!
//! **Item kinds**, because that is what every `RUST-2024` rule selects on.

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

/// Every `unsafe { }` block syn can see, as `(start line, end line)`.
///
/// `unsafe fn`, `unsafe impl` and `unsafe extern` are not blocks and are
/// excluded: this crate reports no `end_line` for them, deliberately, because
/// the region is the function's body rather than a brace pair of its own.
fn syn_unsafe_blocks(src: &str) -> Vec<(u32, u32)> {
    struct V(Vec<(u32, u32)>);
    impl<'ast> syn::visit::Visit<'ast> for V {
        fn visit_expr_unsafe(&mut self, e: &'ast syn::ExprUnsafe) {
            let s = e.span();
            self.0.push((s.start().line as u32, s.end().line as u32));
            syn::visit::visit_expr_unsafe(self, e);
        }
    }
    let file: syn::File = syn::parse_str(src).expect("the corpus is valid Rust");
    let mut v = V(Vec::new());
    syn::visit::Visit::visit_file(&mut v, &file);
    v.0.sort_unstable();
    v.0
}

fn our_unsafe_blocks(src: &str) -> Vec<(u32, u32)> {
    let st = analyze_rust(src);
    let mut v: Vec<(u32, u32)> = st
        .unsafe_regions
        .iter()
        .filter_map(|r| r.end_line.map(|e| (r.pos.line, e)))
        .collect();
    v.sort_unstable();
    v
}

#[test]
fn the_corpus_covers_the_ways_a_brace_can_hide() {
    let c = corpus();
    let has = |n: &str| c.iter().any(|x| x.text.contains(n));
    assert!(has("\"}\""), "a closing brace inside a string");
    assert!(has("'}'"), "and inside a character literal");
    assert!(has("// }"), "and inside a line comment");
    assert!(has("/* } */"), "and inside a block comment");
    assert!(has("r#\"}\"#"), "and inside a raw string");
}

/// The region `RUST-2024-UNSAFE.1` reports, and that correlation matches a
/// runtime defect against.
#[test]
fn unsafe_blocks_span_what_syn_says_they_span() {
    for c in corpus() {
        assert_eq!(
            our_unsafe_blocks(&c.text),
            syn_unsafe_blocks(&c.text),
            "case `{}`: {:?}",
            c.name,
            c.text
        );
    }
}

/// Kinds, which is what every rule selects on.
#[test]
fn the_items_are_the_ones_syn_finds() {
    fn syn_kind(i: &syn::Item) -> Option<&'static str> {
        use syn::Item;
        Some(match i {
            Item::Fn(_) => "fn",
            Item::Struct(_) => "struct",
            Item::Enum(_) => "enum",
            Item::Union(_) => "union",
            Item::Trait(_) => "trait",
            Item::Mod(_) => "mod",
            Item::Const(_) => "const",
            Item::Static(s) => match s.mutability {
                syn::StaticMutability::Mut(_) => "static mut",
                _ => "static",
            },
            Item::Type(_) => "type",
            Item::Impl(_) => "impl",
            Item::Use(_) => "use",
            Item::ForeignMod(_) => "extern block",
            _ => return None,
        })
    }

    for c in corpus() {
        let file: syn::File = syn::parse_str(&c.text).expect("valid Rust");
        let theirs: Vec<&'static str> = file.items.iter().filter_map(syn_kind).collect();

        let st = analyze_rust(&c.text);
        // Top level only: syn nests an impl's methods inside the impl and this
        // crate lists them flat, so comparing everything would compare shapes.
        let ours: Vec<&'static str> = st
            .items
            .iter()
            .filter(|i| i.pos.column == 1)
            .map(|i| i.kind.as_str())
            .collect();

        assert_eq!(ours, theirs, "case `{}`: {:?}", c.name, c.text);
    }
}

#[allow(dead_code)]
fn _kind_is_used(k: RustItemKind) -> &'static str {
    k.as_str()
}
