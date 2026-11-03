//! Where a program can panic, according to a real Rust parser.
//!
//! `RustStructure::panic_sites` is what every `RUST-2024-PANIC` rule reads, and
//! HANDOFF named it as the part of `rstruct` no oracle had ever looked at. The
//! `in_test` flag beside it turned out to hold three defects; this is the other
//! half — whether the sites themselves are the ones that are really there.
//!
//! The oracle is `syn`, called rather than captured, so the comparison always
//! runs against the version in `Cargo.lock`.
//!
//! # The one difference, asserted rather than excused
//!
//! syn parses a macro invocation's arguments as an opaque token stream and does
//! not walk them, so `assert!(v.unwrap() > 0)` is one site to syn and two to
//! this crate. This crate is right: the `unwrap` is there and it can panic. The
//! difference is pinned in `a_panic_inside_a_macro_argument_is_seen_here_and_not_by_syn`
//! rather than hidden behind a filter, and the corpus compared for equality
//! keeps clear of that shape.

use sda_syntax::analyze_rust;

const CORPUS: &str = include_str!("fixtures/rust-struct-corpus.json");

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    text: String,
}

fn corpus() -> Vec<Case> {
    serde_json::from_str(CORPUS).expect("the corpus")
}

/// Methods that panic on the wrong variant, and macros that end the thread.
///
/// Deliberately restated here rather than imported: a comparison that shares its
/// subject's list cannot catch the list being wrong, only the walk.
const METHODS: &[&str] = &["unwrap", "expect", "unwrap_unchecked", "unwrap_err", "expect_err"];
const MACROS: &[&str] =
    &["panic", "unreachable", "todo", "unimplemented", "assert", "assert_eq", "assert_ne"];

/// `(operation, line)` for every site syn can see.
fn syn_sites(src: &str) -> Vec<(String, u32)> {
    struct V(Vec<(String, u32)>);
    impl<'ast> syn::visit::Visit<'ast> for V {
        fn visit_expr_method_call(&mut self, e: &'ast syn::ExprMethodCall) {
            let name = e.method.to_string();
            if METHODS.contains(&name.as_str()) {
                self.0.push((name, e.method.span().start().line as u32));
            }
            syn::visit::visit_expr_method_call(self, e);
        }
        fn visit_macro(&mut self, m: &'ast syn::Macro) {
            if let Some(last) = m.path.segments.last() {
                let name = last.ident.to_string();
                if MACROS.contains(&name.as_str()) {
                    self.0.push((format!("{name}!"), last.ident.span().start().line as u32));
                }
            }
            syn::visit::visit_macro(self, m);
        }
    }
    let file: syn::File = syn::parse_str(src).expect("the corpus is valid Rust");
    let mut v = V(Vec::new());
    syn::visit::Visit::visit_file(&mut v, &file);
    v.0.sort();
    v.0
}

fn our_sites(src: &str) -> Vec<(String, u32)> {
    let mut v: Vec<(String, u32)> = analyze_rust(src)
        .panic_sites
        .iter()
        .map(|p| (p.operation.clone(), p.pos.line))
        .collect();
    v.sort();
    v
}

/// The corpus has to contain the ways a panic can hide, or this passes by never
/// being asked a hard question.
#[test]
fn the_corpus_covers_the_ways_a_panic_can_hide() {
    let c = corpus();
    let has = |n: &str| c.iter().any(|x| x.text.contains(n));
    assert!(has("v.unwrap() and panic!()"), "a panic spelled inside a string literal");
    assert!(has("// v.unwrap() would panic!()"), "and inside a comment");
    assert!(has("assert_eq!"), "the assert family");
    assert!(has("unreachable!"), "and the diverging macros");
    assert!(has("|| w.unwrap()"), "a panic inside a closure");
}

/// The sites themselves.
#[test]
fn the_panic_sites_are_the_ones_syn_finds() {
    for c in corpus() {
        // The macro-argument case is a known difference and has its own test.
        if c.text.contains("assert!(v.unwrap()") {
            continue;
        }
        assert_eq!(
            our_sites(&c.text),
            syn_sites(&c.text),
            "case `{}`: {:?}",
            c.name,
            c.text
        );
    }
}

/// A panic spelled in a string or a comment is not a panic.
///
/// This is what the token stream buys over a regular expression, and it is worth
/// asserting on its own: both sides must agree there is nothing here.
#[test]
fn a_panic_spelled_in_a_string_or_a_comment_is_not_a_site() {
    for c in corpus() {
        if !c.name.starts_with("panic-spelled-in") {
            continue;
        }
        assert!(our_sites(&c.text).is_empty(), "case `{}`: {:?}", c.name, c.text);
        assert!(syn_sites(&c.text).is_empty(), "case `{}` (syn): {:?}", c.name, c.text);
    }
}

/// The difference, stated as a property.
///
/// syn treats a macro invocation's arguments as an opaque token stream and does
/// not walk them; this crate scans tokens and does. For a panic *inside* a macro
/// argument the two disagree, and this crate is the one that is right: the
/// `unwrap` is there and it can panic. A rule that trusted syn here would miss
/// it.
#[test]
fn a_panic_inside_a_macro_argument_is_seen_here_and_not_by_syn() {
    let src = "fn a(v: Option<u8>) {\n    assert!(v.unwrap() > 0);\n}\n";

    let ours = our_sites(src);
    let theirs = syn_sites(src);

    assert!(
        ours.contains(&("unwrap".to_string(), 2)),
        "the token scan sees into the macro argument: {ours:?}"
    );
    assert!(
        !theirs.contains(&("unwrap".to_string(), 2)),
        "and syn does not, because it does not parse macro arguments: {theirs:?}"
    );
    // Both see the `assert!` itself, so this is a difference of depth rather
    // than of disagreement about what a panic is.
    assert!(ours.contains(&("assert!".to_string(), 2)));
    assert!(theirs.contains(&("assert!".to_string(), 2)));
}
