//! Structural facts about a Rust 2024 source file.
//!
//! The focus is the boundary of the safety guarantee: `unsafe` blocks and
//! functions, `extern` declarations, and the operations that can abort a process
//! that is supposed to keep running. On an embedded target — the toolkit's
//! primary audience — an `unwrap()` in a control loop is not a style issue.

use crate::rlex::{RToken, RTokenKind, RustLexed, lex_rust};
use crate::span::{Pos, Span};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RustItemKind {
    Function,
    Struct,
    Enum,
    Trait,
    Impl,
    Module,
    Const,
    Static,
    /// A `static mut`, which is a hard error to reference in edition 2024.
    StaticMut,
    Union,
    TypeAlias,
    MacroDef,
    /// `extern "C" { ... }` or `unsafe extern "C" { ... }`.
    ExternBlock,
    Use,
}

impl RustItemKind {
    pub fn as_str(&self) -> &'static str {
        use RustItemKind::*;
        match self {
            Function => "fn",
            Struct => "struct",
            Enum => "enum",
            Trait => "trait",
            Impl => "impl",
            Module => "mod",
            Const => "const",
            Static => "static",
            StaticMut => "static mut",
            Union => "union",
            TypeAlias => "type",
            MacroDef => "macro",
            ExternBlock => "extern block",
            Use => "use",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RustItem {
    pub kind: RustItemKind,
    pub name: String,
    pub pos: Pos,
    pub span: Span,
    pub is_pub: bool,
    pub is_unsafe: bool,
    pub is_async: bool,
    pub is_const: bool,
    /// `extern "C"` and friends: an FFI boundary where Rust's guarantees stop.
    pub abi: Option<String>,
    /// Last line of the item's brace body, when it has one.
    ///
    /// `None` for `use`, `const`, a unit struct and anything else that ends at a
    /// semicolon. Recorded because deciding whether a panic site is *inside* a
    /// `#[cfg(test)]` module needs to know where the module ends, and an item
    /// that knows only where it starts cannot answer that.
    #[serde(default)]
    pub end_line: Option<u32>,

    /// Attributes written immediately above this item, in source order.
    ///
    /// Outer attributes only: `#![...]` applies to the enclosing crate or
    /// module, not to the item that follows it, and lives in
    /// [`RustStructure::crate_attributes`].
    pub attributes: Vec<String>,
}

/// A call that can panic, with the operation named.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PanicSite {
    /// `unwrap`, `expect`, `panic!`, `unreachable!`, `todo!`, indexing, integer division.
    pub operation: String,
    pub pos: Pos,
    pub span: Span,
    /// Set when the site sits inside a `#[test]` or `#[cfg(test)]` item, where
    /// panicking is the intended failure mode rather than a defect.
    pub in_test: bool,
}

/// An `unsafe` region.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsafeRegion {
    pub pos: Pos,
    pub span: Span,
    /// Last line of the block body, for an `unsafe { }` block.
    ///
    /// `pos` is the `unsafe` keyword, which is where the *finding* belongs — but
    /// the thing the finding is about is the whole region where the compiler has
    /// stopped checking, and a runtime tool reports the defect wherever inside it
    /// the defect actually is. Miri put a stacked-borrows violation three lines
    /// below the keyword; with only a point, correlation saw two unrelated
    /// claims. `None` for an `unsafe fn`, whose body is the function's, and for a
    /// block whose brace never closes.
    pub end_line: Option<u32>,
    /// True for `unsafe fn`, false for an `unsafe { }` block.
    pub is_function: bool,
    /// A `// SAFETY:` comment on one of the lines just above, which every
    /// serious Rust codebase requires and which review can then check.
    pub has_safety_comment: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RustStructure {
    pub items: Vec<RustItem>,
    pub unsafe_regions: Vec<UnsafeRegion>,
    pub panic_sites: Vec<PanicSite>,
    /// Crate-level attributes (`#![...]`).
    pub crate_attributes: Vec<String>,
    /// Macro invocations by name, e.g. `include_bytes` or `env`.
    pub macro_calls: Vec<(String, Pos)>,
    /// Line ranges covered by test modules. Exposed because more than panics
    /// care: a hazardous-looking constant in a fixture is not shipping code.
    pub test_line_ranges: Vec<(u32, u32)>,
}

impl RustStructure {
    /// Whether a line sits inside a test module.
    pub fn is_test_line(&self, line: u32) -> bool {
        self.test_line_ranges.iter().any(|(a, b)| line >= *a && line <= *b)
    }
}

impl RustStructure {
    /// True when `#![forbid(unsafe_code)]` or `#![deny(unsafe_code)]` is present.
    pub fn forbids_unsafe(&self) -> bool {
        self.crate_attributes
            .iter()
            .any(|a| a.contains("unsafe_code") && (a.contains("forbid") || a.contains("deny")))
    }
    /// True when the crate opts out of the standard library — the usual signal
    /// that this is firmware, where panics and allocation are not free.
    pub fn is_no_std(&self) -> bool {
        self.crate_attributes.iter().any(|a| a.contains("no_std"))
    }
    pub fn unsafe_without_justification(&self) -> impl Iterator<Item = &UnsafeRegion> {
        self.unsafe_regions.iter().filter(|r| !r.has_safety_comment)
    }
    pub fn production_panic_sites(&self) -> impl Iterator<Item = &PanicSite> {
        self.panic_sites.iter().filter(|p| !p.in_test)
    }
}

/// Methods whose failure mode is an abort rather than a returned error.
const PANIC_METHODS: &[&str] = &["unwrap", "expect", "unwrap_unchecked", "unwrap_err", "expect_err"];
/// Macros that terminate the current thread.
const PANIC_MACROS: &[&str] = &["panic", "unreachable", "todo", "unimplemented", "assert", "assert_eq", "assert_ne"];

pub fn analyze_rust(src: &str) -> RustStructure {
    let lexed = lex_rust(src);
    let mut st = RustStructure::default();
    let code: Vec<&RToken> = lexed.code_tokens().collect();

    collect_attributes(src, &lexed, &mut st);
    collect_items(src, &code, &mut st);
    collect_unsafe(src, &code, &lexed, &mut st);
    collect_panics(src, &code, &mut st);
    attach_attributes(src, &lexed, &code, &mut st);
    // After the attributes: which regions are test code is read off `#[test]`
    // and `#[cfg(test)]`, so it cannot run before they are attached.
    mark_test_sites(&mut st);
    st
}

fn collect_attributes(src: &str, lexed: &RustLexed, st: &mut RustStructure) {
    for a in lexed.attributes() {
        let text = a.text(src);
        if text.starts_with("#!") {
            st.crate_attributes.push(text.to_string());
        }
    }
}

/// Give each item the attributes written immediately above it.
///
/// `RustItem::attributes` was a public field, documented as "attributes written
/// immediately above this item", that nothing ever wrote to — every item carried
/// an empty list, so a consumer asking whether a function is `#[test]` or
/// `#[no_mangle]` got "no" for all of them. That is this repository's own failure
/// shape in a struct field: an absence of knowledge presented as knowledge of an
/// absence.
///
/// Attachment is positional, because that is what the language does: an
/// attribute applies to the next item, and only whitespace and comments may
/// stand between. A code token in the gap breaks the run.
fn attach_attributes(src: &str, lexed: &RustLexed, code: &[&RToken], st: &mut RustStructure) {
    let attrs: Vec<(usize, usize, &str)> = lexed
        .attributes()
        .map(|a| (a.span.start, a.span.end, a.text(src)))
        .filter(|(_, _, text)| !text.starts_with("#!"))
        .collect();
    if attrs.is_empty() {
        return;
    }
    let code_starts: Vec<usize> = code.iter().map(|t| t.span.start).collect();

    for item in &mut st.items {
        let mut boundary = item.span.start;
        let mut mine: Vec<String> = Vec::new();
        // Walk back through a run of attributes, nearest first.
        while let Some((start, end, text)) = attrs.iter().rev().find(|(_, e, _)| *e <= boundary) {
            if code_starts.iter().any(|p| *p >= *end && *p < boundary) {
                break;
            }
            mine.push((*text).to_string());
            boundary = *start;
        }
        mine.reverse();
        item.attributes = mine;
    }
}

fn collect_items(src: &str, code: &[&RToken], st: &mut RustStructure) {
    let mut i = 0usize;
    while i < code.len() {
        let t = code[i];
        if t.kind != RTokenKind::Keyword {
            i += 1;
            continue;
        }
        // Gather the modifiers that may precede the item keyword.
        let mut j = i;
        let mut is_pub = false;
        let mut is_unsafe = false;
        let mut is_async = false;
        let mut is_const = false;
        let mut abi = None;

        loop {
            match code[j].text(src) {
                "pub" => {
                    is_pub = true;
                    j += 1;
                    // `pub(crate)`, `pub(super)`
                    if j < code.len() && code[j].is(src, "(") {
                        while j < code.len() && !code[j].is(src, ")") {
                            j += 1;
                        }
                        j += 1;
                    }
                }
                "unsafe" => {
                    is_unsafe = true;
                    j += 1;
                }
                "async" => {
                    is_async = true;
                    j += 1;
                }
                "const" if j + 1 < code.len() && code[j + 1].is(src, "fn") => {
                    is_const = true;
                    j += 1;
                }
                "extern" => {
                    j += 1;
                    if j < code.len() && code[j].kind == RTokenKind::String {
                        abi = Some(code[j].text(src).trim_matches('"').to_string());
                        j += 1;
                    } else {
                        abi = Some("C".to_string());
                    }
                }
                _ => break,
            }
            if j >= code.len() {
                return;
            }
        }

        let kw = code[j].text(src);
        let kind = match kw {
            "fn" => RustItemKind::Function,
            "struct" => RustItemKind::Struct,
            "enum" => RustItemKind::Enum,
            "trait" => RustItemKind::Trait,
            "impl" => RustItemKind::Impl,
            "mod" => RustItemKind::Module,
            "union" => RustItemKind::Union,
            "type" => RustItemKind::TypeAlias,
            "macro" => RustItemKind::MacroDef,
            "use" => RustItemKind::Use,
            "const" => RustItemKind::Const,
            "static" => {
                if j + 1 < code.len() && code[j + 1].is(src, "mut") {
                    RustItemKind::StaticMut
                } else {
                    RustItemKind::Static
                }
            }
            "{" if abi.is_some() => RustItemKind::ExternBlock,
            _ => {
                i += 1;
                continue;
            }
        };

        // `extern "C" { ... }` has no keyword of its own.
        if abi.is_some() && code[j].is(src, "{") {
            st.items.push(RustItem {
                kind: RustItemKind::ExternBlock,
                name: abi.clone().unwrap_or_default(),
                pos: code[i].pos,
                span: code[i].span,
                is_pub,
                is_unsafe,
                is_async: false,
                is_const: false,
                abi,
                end_line: body_end_line(src, code, j, RustItemKind::ExternBlock),
                attributes: Vec::new(),
            });
            i = j + 1;
            continue;
        }

        let name_idx = if kind == RustItemKind::StaticMut { j + 2 } else { j + 1 };
        let name = code
            .get(name_idx)
            .filter(|t| t.kind == RTokenKind::Identifier || t.kind == RTokenKind::Keyword)
            .map(|t| t.text(src).to_string())
            .unwrap_or_default();

        st.items.push(RustItem {
            kind,
            name,
            pos: code[i].pos,
            span: code[i].span,
            is_pub,
            is_unsafe,
            is_async,
            is_const,
            abi,
            end_line: body_end_line(src, code, j, kind),
            attributes: Vec::new(),
        });
        i = j + 1;
    }
}

/// Line of the `}` closing this item's body, if it has one.
///
/// `use`, `const`, `static` and type aliases never have one, whatever braces
/// they contain: `use a::{b, c};` and `const C: S = S { a: 1 };` used to report
/// the line of an inner `}`. For the rest, scans forward from the item keyword:
/// a `;` reached before any `{` means no body — `struct S;`, `struct T(u8);`.
/// Both are ignored inside `( )` and `[ ]`, or `fn f(x: [u8; 4]) { }` ended at
/// the array length's `;` and lost its body. The brace walk compares token
/// text, so a brace inside a string or a comment is not a brace, the same
/// property `collect_unsafe` relies on.
fn body_end_line(src: &str, code: &[&RToken], from: usize, kind: RustItemKind) -> Option<u32> {
    if matches!(
        kind,
        RustItemKind::Use
            | RustItemKind::Const
            | RustItemKind::Static
            | RustItemKind::StaticMut
            | RustItemKind::TypeAlias
    ) {
        return None;
    }
    let mut i = from;
    let mut nesting = 0i32;
    while i < code.len() {
        match code[i].text(src) {
            "(" | "[" => nesting += 1,
            ")" | "]" => nesting -= 1,
            ";" if nesting == 0 => return None,
            "{" if nesting == 0 => break,
            _ => {}
        }
        i += 1;
    }
    if i >= code.len() {
        return None;
    }
    let mut depth = 0i32;
    while i < code.len() {
        match code[i].text(src) {
            "{" => depth += 1,
            "}" => {
                depth -= 1;
                if depth == 0 {
                    return Some(code[i].pos.line);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn collect_unsafe(src: &str, code: &[&RToken], lexed: &RustLexed, st: &mut RustStructure) {
    for i in 0..code.len() {
        if !code[i].is(src, "unsafe") {
            continue;
        }
        let next = code.get(i + 1).map(|t| t.text(src)).unwrap_or("");
        // `unsafe impl` / `unsafe trait` / `unsafe extern` are declarations, not
        // regions of unchecked code; `unsafe fn` and `unsafe {` are.
        let is_function = next == "fn";
        if !is_function && next != "{" {
            continue;
        }
        let line = code[i].pos.line;
        // The justification is whatever comment block sits directly above the
        // keyword, however long it is — and it has to be a justification.
        //
        // The reach was a fixed three lines, which punished the comments worth
        // having. Rust style puts `// SAFETY:` on the first line and continues
        // below it, so a four-line justification — the kind a subtle invariant
        // deserves — put the marker four lines up and the rule fired. Measured:
        // one file, two blocks identical apart from the length of their
        // reasoning, and only the thorough one was reported. For a toolkit whose
        // claim is that the justification is the evidence, rewarding the terse
        // one is precisely backwards.
        //
        // Widening it alone was wrong, and the rustc differential caught it
        // within the hour. The corpus documents its own cases in prose — "an
        // unsafe block with no SAFETY comment above it" — so a long doc comment
        // that merely *mentions* the word began silencing the rule it was
        // describing. One real finding disappeared.
        //
        // So a marker is required, and there are two because the language has
        // two conventions. An `unsafe` *block* is justified by `// SAFETY:` with
        // its colon, which is what sixteen of the nineteen occurrences in this
        // workspace write. An `unsafe fn` documents its contract under a rustdoc
        // `# Safety` heading, which is what clippy's `missing_safety_doc` asks
        // for and what the near-miss corpus holds as conforming code — it has no
        // colon and never will.
        //
        // The near-miss test caught that distinction the same way the rustc
        // differential caught the first one: by holding a conforming source and
        // insisting the rule stay quiet on it. Requiring only the colon made
        // `UNSAFE.2` fire on a function documented exactly as the guideline asks.
        //
        // Prose satisfies neither. "an unsafe block with no SAFETY comment above
        // it" is a sentence about safety, which is the thing that must not count
        // as a contract.
        //
        // The walk climbs the contiguous run of comment lines ending just above
        // the keyword. `line - 3` stays as a floor so a `/* */` block, which the
        // lexer reports at its opening line only, keeps the reach it had.
        let comment_lines: std::collections::BTreeSet<u32> =
            lexed.tokens.iter().filter(|t| t.kind.is_comment()).map(|t| t.pos.line).collect();
        let mut top = line;
        while top > 1 && comment_lines.contains(&(top - 1)) {
            top -= 1;
        }
        let top = top.min(line.saturating_sub(3));

        let has_safety_comment = lexed
            .tokens
            .iter()
            .filter(|t| t.kind.is_comment())
            .any(|t| {
                let text = t.text(src).to_ascii_uppercase();
                (text.contains("SAFETY:") || text.contains("# SAFETY"))
                    && t.pos.line >= top
                    && t.pos.line <= line
            });
        // The block's closing brace, by the same depth walk `mark_test_sites`
        // uses. Only for a block: an `unsafe fn`'s extent is the function's, and
        // claiming the keyword spans it would be a different assertion.
        let end_line = if is_function {
            None
        } else {
            let mut j = i;
            while j < code.len() && !code[j].is(src, "{") {
                j += 1;
            }
            let mut depth = 0i32;
            let mut end = None;
            let mut k = j;
            while k < code.len() {
                if code[k].is(src, "{") {
                    depth += 1;
                } else if code[k].is(src, "}") {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(code[k].pos.line);
                        break;
                    }
                }
                k += 1;
            }
            end
        };
        st.unsafe_regions.push(UnsafeRegion {
            pos: code[i].pos,
            span: code[i].span,
            end_line,
            is_function,
            has_safety_comment,
        });
    }
}

fn collect_panics(src: &str, code: &[&RToken], st: &mut RustStructure) {
    // Sites are collected first and attributed to test regions afterwards, in
    // `mark_test_sites`, which needs the whole token stream to find the ranges.
    for i in 0..code.len() {
        let t = code[i];
        let text = t.text(src);

        // `.unwrap()` / `.expect(...)`
        if t.kind == RTokenKind::Identifier
            && PANIC_METHODS.contains(&text)
            && i > 0
            && code[i - 1].is(src, ".")
        {
            st.panic_sites.push(PanicSite {
                operation: text.to_string(),
                pos: t.pos,
                span: t.span,
                in_test: false,
            });
            continue;
        }

        // `name!(` — a macro invocation.
        if t.kind == RTokenKind::Identifier
            && i + 1 < code.len()
            && code[i + 1].is(src, "!")
        {
            st.macro_calls.push((text.to_string(), t.pos));
            if PANIC_MACROS.contains(&text) {
                st.panic_sites.push(PanicSite {
                    operation: format!("{text}!"),
                    pos: t.pos,
                    span: t.span,
                    in_test: false,
                });
            }
        }
    }

}

/// Mark the panic sites that live in test code, where a panic is the intended
/// way to fail rather than a defect.
///
/// This used to look for a `mod` whose *name contained* the substring `test`,
/// and nothing else. Three things were wrong with that, and the first is the one
/// that matters:
///
/// * `mod latest`, `mod attestation`, `mod testbed` were all test modules, so
///   every panic inside them was silently excused. A rule that suppresses real
///   findings is worse than one that misses them, because the report comes back
///   clean.
/// * `#[test] fn` outside a module was not test code — which the old function's
///   own doc comment claimed it handled.
/// * `#[cfg(test)] mod checks` was not test code either, and that is the
///   canonical idiom whenever the module is not literally named `tests`.
///
/// It now reads the attributes, which `attach_attributes` populates, and the
/// item extents, which `body_end_line` records. A module named exactly `tests`
/// is still accepted without an attribute: the convention is near-universal, and
/// requiring `#[cfg(test)]` on it would turn the old false-positive into a new
/// false-negative.
fn mark_test_sites(st: &mut RustStructure) {
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for item in &st.items {
        let by_attribute = item.attributes.iter().any(|a| marks_test_code(a));
        let by_convention = item.kind == RustItemKind::Module && item.name == "tests";
        if (by_attribute || by_convention)
            && let Some(end) = item.end_line {
                ranges.push((item.pos.line, end));
            }
    }

    for site in &mut st.panic_sites {
        if ranges.iter().any(|(a, b)| site.pos.line >= *a && site.pos.line <= *b) {
            site.in_test = true;
        }
    }
    st.test_line_ranges = ranges;
}

/// Whether an attribute says the thing it is attached to is test code.
///
/// `#[test]`, `#[tokio::test]`, `#[cfg(test)]`, `#[cfg(all(test, unix))]`. Not
/// `#[cfg(feature = "testing")]`: string literals are removed before the word is
/// looked for, so a feature that merely mentions testing is not test code.
fn marks_test_code(attr: &str) -> bool {
    let inner = attr
        .trim_start_matches("#!")
        .trim_start_matches('#')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();

    let path: String =
        inner.chars().take_while(|c| *c != '(' && *c != '=').collect::<String>().trim().to_string();
    if path == "test" || path.ends_with("::test") {
        return true;
    }
    if path != "cfg" {
        return false;
    }
    let args = without_string_literals(inner);
    args.split(|c: char| !(c.is_alphanumeric() || c == '_')).any(|w| w == "test")
}

/// The text with every `"..."` removed, so a word inside a literal is not read
/// as a word in the code.
fn without_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for c in text.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c_rust(src: &str) -> RustStructure {
        analyze_rust(src)
    }

    /// Which code is test code, and which merely has "test" in its name.
    ///
    /// `in_test` decides whether a panic site is a defect or the intended way to
    /// fail, so getting it wrong in the permissive direction *suppresses real
    /// findings* and the report comes back clean. The old rule matched any `mod`
    /// whose name contained the substring `test`, which made `mod latest` a test
    /// module — and did not recognise `#[test]` or `#[cfg(test)]` at all.
    #[test]
    fn test_code_is_recognised_by_its_attributes_and_not_by_its_name() {
        let marked = |src: &str| -> Vec<bool> {
            c_rust(src).panic_sites.iter().map(|p| p.in_test).collect()
        };

        // The false positive that mattered: a name containing `test` is not a
        // claim about anything.
        assert_eq!(
            marked("mod latest {\n    pub fn v() -> u8 { Some(1u8).unwrap() }\n}\n"),
            [false],
            "`mod latest` is not test code, and calling it so hides the panic in it"
        );

        // The two false negatives, both idiomatic Rust.
        assert_eq!(marked("#[test]\nfn t() { Some(1u8).unwrap(); }\n"), [true]);
        assert_eq!(
            marked("#[cfg(test)]\nmod checks {\n    fn t() { Some(1u8).unwrap(); }\n}\n"),
            [true]
        );

        // Still accepted without an attribute: the convention is near-universal,
        // and demanding `#[cfg(test)]` would trade the old false positive for a
        // new false negative.
        assert_eq!(marked("mod tests {\n    fn t() { Some(1u8).unwrap(); }\n}\n"), [true]);

        // A feature that merely mentions testing is not test code. String
        // literals are removed before the word is looked for.
        assert_eq!(
            marked("#[cfg(feature = \"testing\")]\nmod m {\n    fn t() { Some(1u8).unwrap(); }\n}\n"),
            [false]
        );

        assert_eq!(
            marked("#[cfg(all(test, unix))]\nmod m {\n    fn t() { Some(1u8).unwrap(); }\n}\n"),
            [true],
            "`test` inside a `cfg` predicate still marks test code"
        );

        // And ordinary code stays ordinary.
        assert_eq!(marked("fn ship() { Some(1u8).unwrap(); }\n"), [false]);
    }

    /// An item knows where its body ends, which is what makes the above possible.
    #[test]
    fn an_item_with_a_body_records_where_it_ends() {
        let st = c_rust("mod m {\n    fn a() {}\n}\nuse core::mem;\nstruct S;\n");
        assert_eq!(st.items[0].name, "m");
        assert_eq!(st.items[0].end_line, Some(3), "the module closes on line 3");
        assert_eq!(
            st.items.iter().find(|i| i.kind == RustItemKind::Use).unwrap().end_line,
            None,
            "a `use` ends at its semicolon and has no body"
        );
        assert_eq!(
            st.items.iter().find(|i| i.name == "S").unwrap().end_line,
            None,
            "and neither does a unit struct"
        );
    }

    #[test]
    fn finds_items_with_their_modifiers() {
        let st = analyze_rust("pub unsafe fn raw() {}\nasync fn a() {}\nstruct S;\n");
        assert_eq!(st.items[0].kind, RustItemKind::Function);
        assert_eq!(st.items[0].name, "raw");
        assert!(st.items[0].is_pub && st.items[0].is_unsafe);
        assert!(st.items[1].is_async);
        assert_eq!(st.items[2].kind, RustItemKind::Struct);
    }

    #[test]
    fn pub_crate_visibility_does_not_break_item_parsing() {
        let st = analyze_rust("pub(crate) fn helper() {}\n");
        assert_eq!(st.items[0].name, "helper");
        assert!(st.items[0].is_pub);
    }

    #[test]
    fn static_mut_is_its_own_kind() {
        let st = analyze_rust("static mut COUNTER: u32 = 0;\nstatic LIMIT: u32 = 5;\n");
        assert_eq!(st.items[0].kind, RustItemKind::StaticMut);
        assert_eq!(st.items[0].name, "COUNTER");
        assert_eq!(st.items[1].kind, RustItemKind::Static);
    }

    #[test]
    fn extern_blocks_and_abis_are_recorded() {
        let st = analyze_rust("unsafe extern \"C\" { fn hal_init() -> i32; }\n");
        let ext = st.items.iter().find(|i| i.kind == RustItemKind::ExternBlock).unwrap();
        assert_eq!(ext.abi.as_deref(), Some("C"));
    }

    #[test]
    fn unsafe_blocks_and_functions_are_both_regions() {
        let st = analyze_rust("unsafe fn f() {}\nfn g() { unsafe { h(); } }\n");
        assert_eq!(st.unsafe_regions.len(), 2);
        assert!(st.unsafe_regions[0].is_function);
        assert!(!st.unsafe_regions[1].is_function);
    }

    #[test]
    fn unsafe_impl_is_not_a_region_of_unchecked_code() {
        let st = analyze_rust("unsafe impl Send for S {}\n");
        assert!(st.unsafe_regions.is_empty());
    }

    /// A long justification counts, and that used to be the failing case.
    ///
    /// The lookback was a fixed three lines. Rust style puts `// SAFETY:` on the
    /// first line of the comment and continues below it, so a four-line
    /// justification — the kind a subtle invariant deserves — put the marker four
    /// lines above the keyword and `UNSAFE.1` fired. Measured on one file holding
    /// two blocks identical apart from the length of their reasoning: only the
    /// thorough one was reported.
    ///
    /// For a toolkit whose claim is that the justification is the only remaining
    /// evidence once the compiler stops checking, rewarding the terse one is
    /// exactly backwards.
    #[test]
    fn a_justification_longer_than_three_lines_still_counts() {
        let long = analyze_rust(
            "fn g() {\n\
             // SAFETY: the pointer is non-null, aligned and valid for reads of\n\
             // `len` bytes, because the caller obtained it from `as_ptr` on a\n\
             // slice that outlives this call, and the surrounding lock keeps any\n\
             // other thread from holding a mutable reference for the duration.\n\
             unsafe { h(); }\n}\n",
        );
        assert!(
            long.unsafe_regions[0].has_safety_comment,
            "a four-line justification is a better one, not a missing one"
        );
    }

    /// An `unsafe fn` documents its contract with a rustdoc heading, not a marker.
    ///
    /// The language has two conventions and the rule has to know both. A block is
    /// justified by `// SAFETY:` with its colon; a function documents itself
    /// under `# Safety`, which is what clippy's `missing_safety_doc` asks for and
    /// has no colon in it anywhere.
    ///
    /// Requiring only the colon made `UNSAFE.2` fire on a function documented
    /// exactly as the guideline asks — caught by the near-miss corpus, which
    /// exists to hold conforming sources and insist the rules stay quiet on them.
    #[test]
    fn a_rustdoc_safety_heading_documents_an_unsafe_function() {
        let heading = analyze_rust(
            "/// Reads the status register.
             ///
             /// # Safety
             ///
             /// The caller must ensure the peripheral clock is enabled first.
             pub unsafe fn read_status() -> u32 { 0 }
",
        );
        assert!(
            heading.unsafe_regions[0].has_safety_comment,
            "`# Safety` is the documented contract, and it never carries a colon"
        );
    }

    /// And absence, irrelevance and distance are all still absence.
    ///
    /// Widening a check is how a check stops checking. Each of these fired before
    /// the lookback changed and has to keep firing: no comment at all, a comment
    /// that says nothing about the invariants, and a `SAFETY:` that belongs to
    /// something else further up with code in between.
    #[test]
    fn a_widened_lookback_still_rejects_what_is_not_a_justification() {
        let bare = analyze_rust("fn g() {\n unsafe { h(); }\n}\n");
        assert!(!bare.unsafe_regions[0].has_safety_comment, "no comment at all");

        let unrelated = analyze_rust(
            "fn g() {\n // this says nothing about why the invariants hold\n unsafe { h(); }\n}\n",
        );
        assert!(
            !unrelated.unsafe_regions[0].has_safety_comment,
            "a comment is not a justification"
        );

        // Prose about safety is not a safety contract. This is the case the
        // rustc differential caught within the hour of the reach being widened:
        // the corpus documents its own test cases in a doc comment -- "an unsafe
        // block with no SAFETY comment above it" -- and a long comment that
        // merely mentions the word began silencing the rule it was describing.
        let prose = analyze_rust(
            "/// UNSAFE.1: an unsafe block with no
             /// SAFETY comment above it, described here in prose.
             pub unsafe fn reads_raw(p: *const u8) -> u8 {
 unsafe { *p }
}
",
        );
        assert!(
            !prose.unsafe_regions[0].has_safety_comment,
            "the marker is `SAFETY:` with its colon; a sentence containing the word is              documentation about safety, not a contract"
        );

        let distant = analyze_rust(
            "fn g() {\n // SAFETY: this belongs to something else\n\n let _x = 1;\n \
             let _y = 2;\n unsafe { h(); }\n}\n",
        );
        assert!(
            !distant.unsafe_regions[0].has_safety_comment,
            "the run of comment lines has to reach the keyword; a blank line and two \
             statements is not `directly above`"
        );
    }

    #[test]
    fn safety_comments_are_detected_above_the_block() {
        let with = analyze_rust("fn g() {\n // SAFETY: ptr is non-null and aligned\n unsafe { h(); }\n}\n");
        assert!(with.unsafe_regions[0].has_safety_comment);
        let without = analyze_rust("fn g() {\n unsafe { h(); }\n}\n");
        assert!(!without.unsafe_regions[0].has_safety_comment);
        assert_eq!(without.unsafe_without_justification().count(), 1);
    }

    #[test]
    fn panic_sites_cover_methods_and_macros() {
        let st = analyze_rust("fn f() { let x = opt.unwrap(); let y = r.expect(\"why\"); panic!(\"no\"); }\n");
        let ops: Vec<&str> = st.panic_sites.iter().map(|p| p.operation.as_str()).collect();
        assert!(ops.contains(&"unwrap"));
        assert!(ops.contains(&"expect"));
        assert!(ops.contains(&"panic!"));
    }

    #[test]
    fn a_field_named_unwrap_is_not_a_panic_site() {
        let st = analyze_rust("fn f() { let unwrap = 1; g(unwrap); }\n");
        assert!(st.panic_sites.is_empty(), "only method-call position counts");
    }

    #[test]
    fn panics_inside_test_modules_are_not_production_defects() {
        let src = "fn f() { o.unwrap(); }\n#[cfg(test)]\nmod tests {\n fn t() { o.unwrap(); }\n}\n";
        let st = analyze_rust(src);
        assert_eq!(st.panic_sites.len(), 2);
        assert_eq!(st.production_panic_sites().count(), 1);
    }

    #[test]
    fn crate_attributes_drive_no_std_and_forbid_unsafe() {
        let st = analyze_rust("#![no_std]\n#![forbid(unsafe_code)]\nfn main() {}\n");
        assert!(st.is_no_std());
        assert!(st.forbids_unsafe());
        let plain = analyze_rust("fn main() {}\n");
        assert!(!plain.is_no_std() && !plain.forbids_unsafe());
    }

    #[test]
    fn macro_calls_are_inventoried() {
        let st = analyze_rust("fn f() { let d = include_bytes!(\"model.gguf\"); }\n");
        assert!(st.macro_calls.iter().any(|(n, _)| n == "include_bytes"));
    }

    #[test]
    fn unsafe_in_a_comment_or_string_is_not_a_region() {
        let st = analyze_rust("fn f() { let s = \"unsafe {\"; /* unsafe { */ }\n");
        assert!(st.unsafe_regions.is_empty());
    }
}

