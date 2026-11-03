//! The native Rust 2024 static checker.
//!
//! Rust already has a borrow checker, and clippy already has thousands of lints.
//! This checker deliberately does not compete with either. It covers what they
//! do not: the *discipline* around the escape hatches. Whether an `unsafe` block
//! carries a justification, whether an FFI declaration documents its contract,
//! whether a firmware crate can panic, whether an embedded model artifact is
//! verified before it is trusted. Those are review obligations, and review is
//! exactly what scales worst.

use sda_core::{
    Analyzer, AnalyzerKind, Availability, Capability, Confidence, Evidence, Finding, Language,
    Location, ProviderInfo, RunOptions, Severity, Target,
};
use sda_rules::{Catalog, Coverage, Rule, Standard};
use sda_syntax::{RTokenKind, RustItemKind, RustStructure, analyze_rust, lex_rust};
use std::path::Path;

pub struct RustStaticAnalyzer {
    catalog: Catalog,
    /// Files this analyzer could not read, drained by [`Analyzer::take_notices`].
    notices: std::sync::Mutex<Vec<sda_core::Exclusion>>,
}

impl Default for RustStaticAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl RustStaticAnalyzer {
    pub fn new() -> Self {
        RustStaticAnalyzer {
            catalog: Catalog::load(Standard::Rust2024),
            notices: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Build with a supplied catalogue, so a project's overrides reach findings.
    pub fn with_catalog(catalog: Catalog) -> Self {
        RustStaticAnalyzer { catalog, notices: std::sync::Mutex::new(Vec::new()) }
    }

    pub fn check_source(&self, path: &Path, src: &str) -> Vec<Finding> {
        let mut st = analyze_rust(src);
        // Test code is recognised syntactically, by `mod tests { … }` — which
        // an integration test does not have, because Cargo says the whole file
        // is test code by virtue of living in `tests/`. The lexer cannot know
        // that; it never sees the path. So the file's *location* is applied
        // here, where the path is in hand.
        //
        // Without this, every `assert!` in an integration test is a production
        // panic site and every fixture filename is a model artifact being
        // shipped. That is not a quirk of this repository: it is what the
        // analyzer would say about any Rust project with a `tests/` directory,
        // which is most of them.
        if is_non_production_path(path) {
            st.test_line_ranges = vec![(1, u32::MAX)];
            for site in &mut st.panic_sites {
                site.in_test = true;
            }
        }
        let st = st;
        let lexed = lex_rust(src);
        let lines = sda_syntax::LineIndex::new(src);
        let mut cx = RCx {
            path,
            src,
            st: &st,
            lines: &lines,
            catalog: &self.catalog,
            findings: Vec::new(),
        };
        cx.run_all(&lexed);
        cx.findings
    }
}

impl Analyzer for RustStaticAnalyzer {
    fn info(&self) -> ProviderInfo {
        ProviderInfo::native(
            "sda.static.rust",
            "NERVOSYS native Rust checker",
            AnalyzerKind::Static,
            vec![Language::Rust],
            vec![Capability::StyleCompliance, Capability::MemorySafety, Capability::ModelArtifactScan],
            "Native Rust 2024 safety-profile checker. Covers the discipline around Rust's escape \
             hatches — unsafe justification, FFI contracts, panic freedom, edition-2024 migration, \
             and embedded model-artifact handling — rather than duplicating clippy.",
        )
    }

    fn available(&self) -> Availability {
        Availability::Available
    }

    fn take_notices(&self) -> Vec<sda_core::Exclusion> {
        let mut held = self.notices.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut *held)
    }

    fn analyze(&self, target: &Target, opts: &RunOptions) -> sda_core::Result<Vec<Finding>> {
        let mut out = Vec::new();
        for file in target.files_in(&[Language::Rust]) {
            // Per-file, for the reason the C analyzer states at length: one
            // unreadable source must not discard every finding from every other.
            let src = match std::fs::read_to_string(&file.path) {
                Ok(src) => src,
                Err(e) => {
                    let mut held = self.notices.lock().unwrap_or_else(|p| p.into_inner());
                    held.push(sda_core::Exclusion {
                        provider: "sda.static.rust".into(),
                        reason: format!(
                            "`{}` was discovered as a source file and could not be read ({e}),                              so no guideline was checked against it. The findings in this report                              describe the files that were read",
                            target.relativize(&file.path).display()
                        ),
                    });
                    continue;
                }
            };
            let rel = target.relativize(&file.path).to_path_buf();

            // A file that will not tokenise is a hole in the scan, and this one
            // was silent even by the standards of the C analyzer.
            //
            // `RustLexed::unterminated_block_comments` has always been computed
            // and has never been read outside the lexer's own tests — the
            // "function nobody calls" shape, three of which this document already
            // records. Its consequence, measured: a file holding an unsafe fn and
            // an index expression reports one finding, and the same file behind an
            // unclosed `/*` reports none. Not a finding, not a notice, nothing.
            // C at least emitted `SDA-C-LEXICAL`; here the file left the analysis
            // without a trace, which is a file that was never checked presented as
            // a file with nothing wrong.
            let lexed = lex_rust(&src);
            if let Some(pos) = lexed.unterminated_block_comments.first() {
                let mut held = self.notices.lock().unwrap_or_else(|p| p.into_inner());
                held.push(sda_core::Exclusion {
                    provider: "sda.static.rust".into(),
                    reason: format!(
                        "`{}` could not be tokenised: a block comment opened at line {} runs to \
                         the end of the file. Everything after it was swallowed, so no guideline \
                         was checked below that line. Finding nothing there is not the same as \
                         there being nothing there. Close it and scan again before reading this \
                         file as clean",
                        rel.display(),
                        pos.line
                    ),
                });
            }

            out.extend(self.check_source(&rel, &src));
        }
        // Manifest-level rules need the project root, not a source file.
        out.extend(self.check_manifest(target));
        out.extend(self.check_crate_unsafe_declaration(target));
        out.retain(|f| !opts.disabled_rules.iter().any(|r| f.rule.as_str().ends_with(r)));
        Ok(out)
    }
}

impl sda_core::StaticAnalyzer for RustStaticAnalyzer {}

impl RustStaticAnalyzer {
    /// UNSAFE.3, decided where the crate is visible.
    ///
    /// The guideline is *"a crate with no need for unsafe code shall declare
    /// `#![forbid(unsafe_code)]`"*, and it was decided from one file: any
    /// `lib.rs` containing no `unsafe` and no `forbid` raised it. A crate whose
    /// root is clean and whose modules are not satisfies both conditions, so the
    /// finding appeared — and its advice was worse than wrong.
    /// `#![forbid(unsafe_code)]` is crate-wide, so a reader who followed it would
    /// not get a stricter crate, they would get one that does not compile.
    ///
    /// It is `system` scope now, for the reason MISRA 5.1 and D4.5 are: the
    /// answer is not in the file the finding points at. Every source under the
    /// crate root is consulted first.
    ///
    /// Decided here rather than in `check_source` because this is the only place
    /// that knows what else is in the crate — which is also why the editor's
    /// buffer path no longer raises it. One file is not evidence about a crate,
    /// and a rule that cannot be decided from a buffer should not appear to have
    /// been. That makes it fixture-exempt, beside `DEP.3` and `ED2024.5`, for the
    /// same reason they are.
    fn check_crate_unsafe_declaration(&self, target: &Target) -> Vec<Finding> {
        let Some(rule) = self.catalog.get("UNSAFE.3").cloned() else {
            return Vec::new();
        };
        let mut out = Vec::new();

        // Every crate root this scan can see: the directory holding a `lib.rs`.
        let roots: std::collections::BTreeSet<std::path::PathBuf> = target
            .files_in(&[Language::Rust])
            .into_iter()
            .filter(|f| f.path.file_name().and_then(|n| n.to_str()) == Some("lib.rs"))
            .filter_map(|f| f.path.parent().map(Path::to_path_buf))
            .collect();

        for dir in roots {
            let root_file = dir.join("lib.rs");
            let Ok(root_src) = std::fs::read_to_string(&root_file) else { continue };
            let root_st = analyze_rust(&root_src);
            if root_st.forbids_unsafe() {
                continue;
            }

            // Any source under the crate root, the root itself included.
            let mut crate_uses_unsafe = false;
            let mut unread = false;
            for file in target.files_in(&[Language::Rust]) {
                if !file.path.starts_with(&dir) {
                    continue;
                }
                match std::fs::read_to_string(&file.path) {
                    Ok(src) => {
                        if !analyze_rust(&src).unsafe_regions.is_empty() {
                            crate_uses_unsafe = true;
                            break;
                        }
                    }
                    // A file nobody could read is not evidence that the crate is
                    // unsafe-free. The per-file loop has already reported it;
                    // here it means the claim cannot be made, so it is not made.
                    Err(_) => unread = true,
                }
            }
            if crate_uses_unsafe || unread {
                continue;
            }

            let loc = Location::new(target.relativize(&root_file).to_string_lossy().to_string(), 1, 1);
            out.push(finding_for(
                &rule,
                loc,
                "this crate contains no `unsafe` and does not declare \
                 `#![forbid(unsafe_code)]`; declaring it turns a property that happens to hold \
                 today into one the compiler keeps",
                rule.confidence_ceiling(),
            ));
        }
        out
    }

    /// ED2024.5 and DEP.3: facts that live in `Cargo.toml`, not in source.
    fn check_manifest(&self, target: &Target) -> Vec<Finding> {
        let manifest = target.root.join("Cargo.toml");
        // No manifest is the ordinary case — a directory of Rust files need not
        // be a crate root — and says nothing worth reporting. A manifest that
        // *exists* and cannot be read is different: `ED2024.5` and `DEP.3` are
        // decided here and nowhere else, so they silently do not run, and a
        // clean result covers two rules that were never checked.
        let text = match std::fs::read_to_string(&manifest) {
            Ok(text) => text,
            Err(e) => {
                if manifest.exists() {
                    let mut held = self.notices.lock().unwrap_or_else(|p| p.into_inner());
                    held.push(sda_core::Exclusion {
                        provider: "sda.static.rust".into(),
                        reason: format!(
                            "`Cargo.toml` exists and could not be read ({e}), so the two \
                             guidelines decided from the manifest — ED2024.5 and DEP.3 — were \
                             not checked at all"
                        ),
                    });
                }
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        // The manifest is the one place this analyzer reported a bare file with
        // no position, even though each of these findings is *about* a specific
        // table header that the check has already located in the text. Pointing
        // at `Cargo.toml:1:1` sent the reader to the wrong line of their own
        // manifest; bracketing the header sends them to the right one.
        let lines = sda_syntax::LineIndex::new(&text);
        let at_header = |header: &str| match text.find(header) {
            Some(offset) => {
                let start = lines.pos(offset);
                let end = lines.pos(offset + header.len());
                Location::new("Cargo.toml", start.line, start.column)
                    .spanning(end.line, end.column)
            }
            None => Location::file_only("Cargo.toml"),
        };

        let declares_2024 = text.contains("edition = \"2024\"")
            || text.contains("edition.workspace = true")
            || text.contains("edition = \"2024\"");
        if !declares_2024 && text.contains("[package]")
            && let Some(rule) = self.catalog.get("ED2024.5") {
                out.push(
                    finding_for(
                        rule,
                        at_header("[package]"),
                        "this package does not declare `edition = \"2024\"`; without it the crate \
                         builds under older edition semantics, and the 2024 rules in this profile \
                         do not apply to it",
                        Confidence::High,
                    ),
                );
            }

        if !target.root.join("Cargo.lock").exists() && text.contains("[dependencies]")
            && let Some(rule) = self.catalog.get("DEP.3") {
                out.push(finding_for(
                    rule,
                    at_header("[dependencies]"),
                    "there is no checked-in `Cargo.lock`; two builds of the same commit can resolve \
                     to different dependency versions, which makes an analysis result unreproducible \
                     and a supply-chain audit meaningless",
                    Confidence::High,
                ));
            }
        out
    }
}

/// Whether this file is one of Cargo's non-production targets.
///
/// `tests/`, `benches/` and `examples/` are compiled only for `cargo test`,
/// `cargo bench` and `cargo run --example`; nothing in them ships. A panic there
/// is the test doing its job, and a fixture path there is not a supply chain.
///
/// Matched on any path component rather than only the crate root's direct
/// child, so `src/tests/helpers.rs` counts too — that is test code by any
/// reading. The cost is a production module deliberately named `examples`,
/// which would be exempted wrongly; that is rare enough, and visible enough in
/// a path, to be the better trade.
fn is_non_production_path(path: &Path) -> bool {
    path.components().any(|c| {
        matches!(c.as_os_str().to_str(), Some("tests") | Some("benches") | Some("examples"))
    })
}

/// Whether the string literal at `i` is an argument to a string-matching
/// predicate — `name.ends_with(".pkl")` — rather than a path being used.
fn is_match_pattern(tokens: &[&sda_syntax::RToken], i: usize, src: &str) -> bool {
    // Look back over `( ident .`, skipping comments, which the token list keeps.
    let mut back = Vec::new();
    let mut k = i;
    while k > 0 && back.len() < 3 {
        k -= 1;
        if tokens[k].kind.is_comment() {
            continue;
        }
        back.push(tokens[k].text(src));
    }
    matches!(back.as_slice(), ["(", method, "."] if matches!(
        *method,
        "ends_with" | "starts_with" | "contains" | "strip_suffix" | "strip_prefix" | "eq"
            | "eq_ignore_ascii_case" | "matches" | "find" | "split" | "trim_end_matches"
            | "trim_start_matches"
    ))
}

fn finding_for(rule: &Rule, loc: Location, message: impl Into<String>, conf: Confidence) -> Finding {
    let mut f = Finding::new("sda.static.rust", rule.id.clone(), rule.title.clone(), rule.severity(), loc)
        .message(message)
        .confidence(conf);
    for t in rule.taxonomy_refs() {
        f = f.taxonomy(t);
    }
    f
}

struct RCx<'a> {
    path: &'a Path,
    src: &'a str,
    st: &'a RustStructure,
    lines: &'a sda_syntax::LineIndex,
    catalog: &'a Catalog,
    findings: Vec<Finding>,
}

impl<'a> RCx<'a> {
    fn run_all(&mut self, lexed: &sda_syntax::RustLexed) {
        self.check_unsafe();
        self.check_panics();
        self.check_ffi(lexed);
        self.check_edition_2024(lexed);
        self.check_concurrency(lexed);
        self.check_embedded(lexed);
        self.check_model_handling(lexed);
        self.check_build_scripts();
    }

    /// A location carrying the extent of the token it points at. See the C
    /// analyzer's `located` for why the span is derived here rather than
    /// tracked by every check.
    fn located(&self, line: u32, column: u32) -> Location {
        let (line, column) = (line.max(1), column.max(1));
        let loc = Location::new(self.path, line, column);
        match self.lines.line_text(self.src, line) {
            Some(text) => {
                let end = sda_syntax::token_end_column(text, column);
                if end > column { loc.spanning(line, end) } else { loc }
            }
            None => loc,
        }
    }

    fn emit(&mut self, number: &str, line: u32, column: u32, message: impl Into<String>) {
        let Some(rule) = self.catalog.get(number).cloned() else {
            return;
        };
        let loc = self.located(line, column);
        let mut f = finding_for(&rule, loc.clone(), message, rule.confidence_ceiling());
        let (first, text) = self.lines.context(self.src, line, 1);
        f = f.evidence(Evidence::source(loc, first, text));
        if rule.coverage == Coverage::Partial {
            f = f.evidence(Evidence::note(
                "This rule is only partially checked; a clean result does not establish conformance.",
            ));
        }
        self.findings.push(f);
    }

    fn emit_with(
        &mut self,
        number: &str,
        line: u32,
        column: u32,
        message: impl Into<String>,
        severity: Severity,
    ) {
        let before = self.findings.len();
        self.emit(number, line, column, message);
        // `emit` appends at most one finding, so its index is exactly `before`.
        if let Some(f) = self.findings.get_mut(before) {
            f.severity = severity;
        }
    }

    // --- unsafe -----------------------------------------------------------

    fn check_unsafe(&mut self) {
        let regions: Vec<(u32, u32, bool, bool, Option<u32>)> = self
            .st
            .unsafe_regions
            .iter()
            .map(|r| {
                (r.pos.line, r.pos.column, r.is_function, r.has_safety_comment, r.end_line)
            })
            .collect();

        for (line, col, is_fn, justified, end_line) in regions {
            if !justified {
                if is_fn {
                    self.emit(
                        "UNSAFE.2",
                        line,
                        col,
                        "this `unsafe fn` has no documented safety contract; every caller is now \
                         responsible for preconditions nobody has written down",
                    );
                } else {
                    self.emit(
                        "UNSAFE.1",
                        line,
                        col,
                        "this `unsafe` block has no `// SAFETY:` comment. The compiler has stopped \
                         checking here, so the justification is the only remaining evidence that \
                         the invariants hold",
                    );
                    // The finding is *located* at the keyword and *about* the
                    // whole block. Stating the extent lets a runtime tool that
                    // faults inside the block confirm this finding, instead of
                    // arriving as an unrelated `unpredicted` defect: Miri put a
                    // stacked-borrows violation three lines below the keyword,
                    // outside the correlator's two-line noise allowance, and one
                    // block was reported as two unconnected claims.
                    //
                    // The extent is measured, not assumed. `end_line` is `None`
                    // when the brace never closes, and no span is claimed then —
                    // the same rule the external parsers follow, where a tool
                    // that states no extent gets a point.
                    if let (Some(end), Some(f)) = (end_line, self.findings.last_mut())
                        && end > f.location.line {
                            f.location = f.location.clone().spanning(end, 1);
                        }
                }
            }
        }

        // UNSAFE.3 is decided in `analyze`, where the whole crate is visible —
        // see `check_crate_unsafe_declaration`. It was decided here, from one
        // file, and a crate whose root is clean while its modules are not got
        // told to add a crate-wide `#![forbid(unsafe_code)]` that would not
        // compile.

        // UNSAFE.4: `static mut` is a hard error to reference in edition 2024.
        let static_muts: Vec<(String, u32, u32)> = self
            .st
            .items
            .iter()
            .filter(|i| i.kind == RustItemKind::StaticMut)
            .map(|i| (i.name.clone(), i.pos.line, i.pos.column))
            .collect();
        for (name, line, col) in static_muts {
            self.emit_with(
                "UNSAFE.4",
                line,
                col,
                format!(
                    "`static mut {name}` — any reference to this is a hard error under edition 2024. \
                     Replace it with an atomic, a `Mutex`, or `SyncUnsafeCell` with a documented \
                     access discipline"
                ),
                Severity::High,
            );
        }
    }

    // --- panics -----------------------------------------------------------

    fn check_panics(&mut self) {
        // Panic freedom is a hard requirement in firmware and a strong default
        // elsewhere; `no_std` is the signal that separates the two.
        let severity =
            if self.st.is_no_std() { Severity::High } else { Severity::Medium };

        let sites: Vec<(String, u32, u32)> = self
            .st
            .production_panic_sites()
            .map(|p| (p.operation.clone(), p.pos.line, p.pos.column))
            .collect();

        for (op, line, col) in sites {
            let rule = if op.ends_with('!') { "PANIC.2" } else { "PANIC.1" };
            let context = if self.st.is_no_std() {
                "in a `no_std` crate a panic reaches the panic handler, which on most targets \
                 halts or resets the device"
            } else {
                "an unhandled panic terminates the thread, discarding whatever state it held"
            };
            self.emit_with(
                rule,
                line,
                col,
                format!("`{op}` can abort at runtime: {context}"),
                severity,
            );
        }
    }

    // --- FFI --------------------------------------------------------------

    fn check_ffi(&mut self, lexed: &sda_syntax::RustLexed) {
        let doc_lines: Vec<u32> = lexed
            .tokens
            .iter()
            .filter(|t| t.kind.is_comment())
            .map(|t| t.pos.line)
            .collect();

        // FFI.1 is about *every extern function declaration*, and this used to
        // be about the `extern` block. The block is one item; the declarations
        // inside it are others, and the check demanded a comment within three
        // lines *above the block*.
        //
        // That was wrong in both directions. Documenting each function where it
        // is declared — inside the block, which is where rustdoc renders it and
        // where a reviewer looks — put the comment *below* the block's line, so
        // it did not count and the finding fired on code that complies. And a
        // single comment above the block satisfied it however many undocumented
        // declarations the block held.
        //
        // The second direction is the one that matters: a comment above a block
        // cannot state what `buf` must point to, because it does not know which
        // function is being described.
        let blocks: Vec<(String, u32, u32)> = self
            .st
            .items
            .iter()
            .filter(|i| i.kind == RustItemKind::ExternBlock)
            .map(|i| {
                (
                    i.abi.clone().unwrap_or_else(|| "C".into()),
                    i.pos.line,
                    i.end_line.unwrap_or(i.pos.line),
                )
            })
            .collect();

        let enclosing = |line: u32| blocks.iter().find(|(_, a, b)| line >= *a && line <= *b);

        let externs: Vec<(String, u32, u32)> = self
            .st
            .items
            .iter()
            .filter(|i| i.kind != RustItemKind::ExternBlock)
            .filter_map(|i| {
                // A declaration inside an extern block takes the block's ABI; a
                // definition carrying its own (`extern "C" fn`) is a boundary in
                // the other direction and is equally a promise to a caller that
                // Rust does not check.
                let abi = match enclosing(i.pos.line) {
                    Some((abi, _, _)) if i.kind == RustItemKind::Function => Some(abi.clone()),
                    _ => i.abi.clone(),
                }?;
                Some((abi, i.pos.line, i.pos.column))
            })
            .collect();

        for (abi, line, col) in externs {
            // Immediately above, not "within three lines above". The window
            // meant one comment at the top of a block documented every
            // declaration in the first few lines of it — two, in the test below,
            // neither of them described. A doc comment belongs against the thing
            // it documents, and the last line of it is the line before.
            //
            // This errs toward reporting: an attribute written between the
            // comment and the declaration defeats it. For a guideline about
            // whether a contract is written down, a spurious request to write
            // one is the better failure.
            let documented = line > 1 && doc_lines.contains(&(line - 1));
            if !documented {
                self.emit(
                    "FFI.1",
                    line,
                    col,
                    format!(
                        "this `extern \"{abi}\"` declaration is undocumented. Everything Rust \
                         guarantees stops here: lifetimes, aliasing, null-ness and thread safety \
                         all become the foreign side's promise, and an unwritten promise cannot be \
                         reviewed"
                    ),
                );
            }
        }
    }

    // --- edition 2024 -----------------------------------------------------

    fn check_edition_2024(&mut self, lexed: &sda_syntax::RustLexed) {
        // ED2024.1: `gen` became a keyword in edition 2024, so the lexer already
        // classifies it as one. What matters is whether it is being *used* as a
        // keyword (`gen fn`, `gen {`, `gen move`) or as a leftover identifier.
        let code: Vec<&sda_syntax::RToken> = lexed.code_tokens().collect();
        let gen_idents: Vec<(u32, u32)> = code
            .iter()
            .enumerate()
            .filter(|(i, t)| {
                t.text(self.src) == "gen"
                    && !code
                        .get(i + 1)
                        .is_some_and(|next| matches!(next.text(self.src), "fn" | "{" | "move"))
            })
            .map(|(_, t)| (t.pos.line, t.pos.column))
            .collect();
        for (line, col) in gen_idents {
            self.emit(
                "ED2024.1",
                line,
                col,
                "`gen` is a keyword in edition 2024; using it as an identifier will not compile. \
                 Rename it or write `r#gen`",
            );
        }

        // ED2024.3: extern blocks must be `unsafe extern`.
        let bare_externs: Vec<(u32, u32)> = self
            .st
            .items
            .iter()
            .filter(|i| i.kind == RustItemKind::ExternBlock && !i.is_unsafe)
            .map(|i| (i.pos.line, i.pos.column))
            .collect();
        for (line, col) in bare_externs {
            self.emit(
                "ED2024.3",
                line,
                col,
                "edition 2024 requires `unsafe extern \"C\" { ... }`; the `unsafe` marks that the \
                 declarations inside are unchecked assertions about a foreign ABI",
            );
        }

        // ED2024.4: unsafe attributes must be written in their unsafe form.
        let unsafe_attrs: Vec<(String, u32, u32)> = lexed
            .attributes()
            .filter_map(|t| {
                let text = t.text(self.src);
                let inner = text.trim_start_matches("#![").trim_start_matches("#[").trim_end_matches(']');
                ["no_mangle", "export_name", "link_section"]
                    .iter()
                    .find(|a| inner.trim_start().starts_with(**a))
                    .map(|a| (a.to_string(), t.pos.line, t.pos.column))
            })
            .collect();
        for (attr, line, col) in unsafe_attrs {
            self.emit(
                "ED2024.4",
                line,
                col,
                format!(
                    "`#[{attr}]` is an unsafe attribute in edition 2024 — it lets other code refer \
                     to this symbol by a name Rust no longer controls. Write `#[unsafe({attr})]`"
                ),
            );
        }
    }

    // --- concurrency ------------------------------------------------------

    fn check_concurrency(&mut self, lexed: &sda_syntax::RustLexed) {
        let comment_lines: Vec<u32> =
            lexed.tokens.iter().filter(|t| t.kind.is_comment()).map(|t| t.pos.line).collect();

        let code: Vec<&sda_syntax::RToken> = lexed.code_tokens().collect();
        let mut hits = Vec::new();
        for i in 0..code.len() {
            if code[i].text(self.src) != "unsafe" {
                continue;
            }
            let is_marker_impl = code
                .get(i + 1)
                .is_some_and(|t| t.text(self.src) == "impl")
                && (i + 2..(i + 6).min(code.len()))
                    .any(|k| matches!(code[k].text(self.src), "Send" | "Sync"));
            if !is_marker_impl {
                continue;
            }
            let line = code[i].pos.line;
            let justified = comment_lines.iter().any(|l| *l + 3 >= line && *l <= line);
            if !justified {
                hits.push((line, code[i].pos.column));
            }
        }
        for (line, col) in hits {
            self.emit_with(
                "CONC.1",
                line,
                col,
                "an `unsafe impl Send`/`Sync` asserts thread safety the compiler could not derive. \
                 Without a written argument, nothing distinguishes a considered decision from a \
                 borrow-checker workaround",
                Severity::High,
            );
        }
    }

    // --- embedded ---------------------------------------------------------

    fn check_embedded(&mut self, lexed: &sda_syntax::RustLexed) {
        if !self.st.is_no_std() {
            return;
        }
        let allocating: Vec<(String, u32, u32)> = lexed
            .code_tokens()
            .filter(|t| {
                matches!(t.text(self.src), "Vec" | "String" | "Box" | "HashMap" | "BTreeMap")
            })
            .map(|t| (t.text(self.src).to_string(), t.pos.line, t.pos.column))
            .collect();

        for (name, line, col) in allocating {
            self.emit(
                "EMB.1",
                line,
                col,
                format!(
                    "`{name}` allocates. In a `no_std` crate that means a global allocator whose \
                     failure mode, fragmentation behaviour and worst-case timing all have to be \
                     accounted for; a fixed-capacity container avoids the question entirely"
                ),
            );
        }
    }

    // --- supply chain -----------------------------------------------------

    fn check_build_scripts(&mut self) {
        if self.path.file_name().and_then(|n| n.to_str()) != Some("build.rs") {
            return;
        }
        // Cargo runs `build.rs` only at the package root. One under `src/`,
        // `tests/`, `benches/` or `examples/` is an ordinary module that happens
        // to share the name, and Cargo never executes it at build time — so the
        // thing DEP.2 is about, code running with the developer's privileges
        // before anything is reviewed, is not happening.
        //
        // Tested on the parent's components rather than on the whole path so a
        // workspace member keeps working: `member/build.rs` is a real build
        // script, and requiring the file to sit at the scan root would have
        // stopped reporting every one of them.
        const NEVER_A_PACKAGE_ROOT: &[&str] = &["src", "tests", "benches", "examples"];
        if self.path.parent().is_some_and(|p| {
            p.components()
                .any(|c| NEVER_A_PACKAGE_ROOT.contains(&c.as_os_str().to_string_lossy().as_ref()))
        }) {
            return;
        }
        self.emit_with(
            "DEP.2",
            1,
            1,
            "this build script runs with the full privileges of the building user, before any \
             review gate that looks at compiled code. Its network access, file writes and \
             environment reads all belong in the supply-chain threat model",
            Severity::Medium,
        );
    }

    // --- embedded AI model handling ---------------------------------------

    fn check_model_handling(&mut self, lexed: &sda_syntax::RustLexed) {
        // MODEL.1: a model embedded at build time with no digest check.
        let embeds: Vec<(u32, u32, String)> = self
            .st
            .macro_calls
            .iter()
            .filter(|(name, _)| name == "include_bytes" || name == "include_str")
            .map(|(name, p)| (p.line, p.column, name.clone()))
            .collect();

        let verifies_digest = self.src.contains("sha256")
            || self.src.contains("Sha256")
            || self.src.contains("blake3")
            || self.src.contains("DIGEST")
            || self.src.contains("verify");

        for (line, col, name) in embeds {
            let looks_like_model = self
                .lines
                .line_text(self.src, line)
                .is_some_and(|l| {
                    ["gguf", "safetensors", "onnx", "tflite", ".pt", ".bin", "model", "weights"]
                        .iter()
                        .any(|ext| l.to_ascii_lowercase().contains(ext))
                });
            // MODEL.3 already exempts test lines; MODEL.1 did not, so the same
            // fixture reference was a supply-chain finding under one rule and
            // not the other. The inconsistency was the defect: embedding a
            // fixture in a test is not shipping a model into firmware.
            if looks_like_model && !verifies_digest && !self.st.is_test_line(line) {
                self.emit_with(
                    "MODEL.1",
                    line,
                    col,
                    format!(
                        "`{name}!` embeds what looks like a model artifact with no digest check \
                         anywhere in this file. A model is executable behaviour: swapping the file \
                         in the build tree changes what the firmware does, and nothing here would \
                         notice"
                    ),
                    Severity::High,
                );
            }
        }

        // MODEL.3: a code-executing deserialization format.
        //
        // What counts is *deserializing* with such a format, not naming it. An
        // earlier version matched any identifier containing "pickle", which
        // flagged every tool that inspects pickle files — including this one,
        // 60 times, at Critical. A security checker that cannot tell analysing a
        // hazard from using it produces findings nobody reads.
        let code: Vec<&sda_syntax::RToken> = lexed.code_tokens().collect();
        let mut hits = Vec::new();

        for (i, t) in code.iter().enumerate() {
            // Only a call site: `path::to::load(...)`.
            if t.kind != RTokenKind::Identifier
                || code.get(i + 1).map(|n| n.text(self.src)) != Some("(")
            {
                continue;
            }
            let callee = t.text(self.src);
            if !matches!(callee, "load" | "loads" | "from_slice" | "from_reader" | "from_value") {
                continue;
            }
            // Walk back over `::`-separated segments to recover the path.
            let mut path = vec![callee.to_string()];
            let mut k = i;
            while k >= 2 && code[k - 1].text(self.src) == "::" {
                path.push(code[k - 2].text(self.src).to_string());
                k -= 2;
            }
            let qualified = path.iter().rev().cloned().collect::<Vec<_>>().join("::");
            let lower = qualified.to_ascii_lowercase();
            if lower.contains("pickle") || lower.contains("torch") {
                hits.push((t.pos.line, t.pos.column, qualified));
            }
        }

        // A string literal naming a pickle-format file: the model being loaded,
        // even when the loader is on the far side of an FFI boundary.
        //
        // Three things are excluded, each a distinct way of *naming* the format
        // rather than loading one:
        //   * `".pkl"` alone — the extension, as any format-recognising code has;
        //   * a literal handed to `ends_with` and friends — a match pattern;
        //   * a fixture inside a test module — not shipping code.
        //
        // MODEL.3 is Mandatory, so these cannot be waived by a deviation. That is
        // deliberate: loading a pickle is remote code execution, and the right
        // response to a false positive on a Mandatory rule is a better rule.
        let all: Vec<&sda_syntax::RToken> = lexed.tokens.iter().collect();
        for (i, t) in all.iter().enumerate() {
            if !matches!(t.kind, RTokenKind::String | RTokenKind::RawString) {
                continue;
            }
            let literal = t.text(self.src).to_ascii_lowercase();
            let name = literal.trim_matches(|c| c == '"' || c == 'r' || c == '#');
            let names_a_file = [".pkl", ".pt", ".pth", ".ckpt"]
                .iter()
                .any(|ext| name.ends_with(ext) && name.len() > ext.len());
            if !names_a_file || self.st.is_test_line(t.pos.line) {
                continue;
            }
            if is_match_pattern(&all, i, self.src) {
                continue;
            }
            hits.push((t.pos.line, t.pos.column, t.text(self.src).to_string()));
        }
        for (line, col, what) in hits {
            self.emit_with(
                "MODEL.3",
                line,
                col,
                format!(
                    "`{what}` refers to a Python pickle-based model format. Pickle is not a data \
                     format — it is a stack machine that can call arbitrary functions during load, \
                     so deserializing an untrusted one is remote code execution by design. Use \
                     safetensors or GGUF"
                ),
                Severity::Critical,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn check(src: &str) -> Vec<Finding> {
        RustStaticAnalyzer::new().check_source(&PathBuf::from("src/lib.rs"), src)
    }
    fn rules(src: &str) -> Vec<String> {
        check(src).into_iter().map(|f| f.rule.to_string()).collect()
    }
    fn hit(src: &str, rule: &str) -> bool {
        rules(src).iter().any(|r| r.ends_with(rule))
    }

    /// The manifest checks knew exactly which table they were complaining
    /// about — they had just searched the text for it — and reported
    /// `Cargo.toml:1:1` anyway, sending the reader to a line that has nothing
    /// to do with the finding.
    #[test]
    fn manifest_findings_bracket_the_table_they_are_about() {
        let dir = std::env::temp_dir()
            .join(format!("sda-rstatic-manifest-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        // A leading comment so the tables are not on line 1: a location of 1:1
        // would then be indistinguishable from "we did not look".
        std::fs::write(
            dir.join("Cargo.toml"),
            "# a comment\n\n[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"\n",
        )
        .unwrap();

        let out = RustStaticAnalyzer::new().check_manifest(&Target::new(&dir));

        let ed = out.iter().find(|f| f.rule.as_str().ends_with("ED2024.5")).expect("ED2024.5");
        assert_eq!((ed.location.line, ed.location.column), (3, 1));
        assert_eq!(ed.location.end_column, Some(10), "`[package]` is nine columns wide");

        let dep = out.iter().find(|f| f.rule.as_str().ends_with("DEP.3")).expect("DEP.3");
        assert_eq!((dep.location.line, dep.location.column), (6, 1));
        assert_eq!(dep.location.end_line, Some(6));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Cargo compiles `tests/`, `benches/` and `examples/` only for testing, so
    /// nothing in them ships — but test code was recognised only as
    /// `mod tests { … }`, which an integration test file does not have. Every
    /// `assert!` in one was a production panic site and every fixture name was a
    /// model artifact. That is what the analyzer would say about any Rust
    /// project with a `tests/` directory.
    #[test]
    fn cargos_non_production_targets_are_treated_as_test_code() {
        let src = "#[test]\nfn t() {\n    let m = load(\"weights.pkl\");\n    assert_eq!(m.len(), 3);\n    m.unwrap();\n}\n";
        let a = RustStaticAnalyzer::new();

        for dir in ["tests", "benches", "examples"] {
            let found = a.check_source(&PathBuf::from(dir).join("harness.rs"), src);
            let rules: Vec<String> = found.iter().map(|f| f.rule.to_string()).collect();
            assert!(
                !rules.iter().any(|r| r.ends_with("PANIC.1") || r.ends_with("PANIC.2")),
                "{dir}/: a panic in a test target is the test working: {rules:?}"
            );
            assert!(
                !rules.iter().any(|r| r.ends_with("MODEL.3")),
                "{dir}/: a fixture name is not a shipped model: {rules:?}"
            );
        }
    }

    /// The other half of the claim, and the one that matters: the same code in
    /// a production path is still reported. Without this, the exemption above
    /// is indistinguishable from switching the rules off.
    ///
    /// The fixture is deliberately *not* `#[test]`. It used to be, and passed —
    /// because `in_test` was recognised only as a `mod` whose name contained
    /// "test", so a `#[test] fn` in `src/lib.rs` was production code. It is not:
    /// that is how every Rust unit test is written. Once the attribute was read,
    /// this fixture became test code and the assertions below correctly stopped
    /// holding. The test was resting on the defect it was meant to be
    /// independent of.
    #[test]
    fn the_same_code_under_src_is_still_reported() {
        let src = "fn load_model() {\n    let m = load(\"weights.pkl\");\n    assert_eq!(m.len(), 3);\n    m.unwrap();\n}\n";
        let found = RustStaticAnalyzer::new().check_source(&PathBuf::from("src/lib.rs"), src);
        let rules: Vec<String> = found.iter().map(|f| f.rule.to_string()).collect();
        assert!(
            rules.iter().any(|r| r.ends_with("MODEL.3")),
            "a pickle path in production code is still a finding: {rules:?}"
        );
        assert!(
            rules.iter().any(|r| r.ends_with("PANIC.1") || r.ends_with("PANIC.2")),
            "a panic in production code is still a finding: {rules:?}"
        );
    }

    /// MODEL.3 exempted test lines and MODEL.1 did not, so the same fixture
    /// reference was a supply-chain finding under one rule and not the other.
    #[test]
    fn model_1_exempts_test_code_the_way_model_3_already_did() {
        let embed =
            "#[cfg(test)]\nmod tests {\n    const F: &str = include_str!(\"fixtures/model.bin\");\n}\n";
        assert!(!hit(embed, "MODEL.1"), "a fixture embedded in a test is not a shipped model");

        // And still reported outside one.
        let production = "const F: &[u8] = include_bytes!(\"weights/model.bin\");\n";
        assert!(hit(production, "MODEL.1"), "an unverified embedded model still counts");
    }

    #[test]
    fn unsafe_block_without_justification_is_reported() {
        assert!(hit("fn f() { unsafe { g(); } }\n", "UNSAFE.1"));
    }

    #[test]
    fn a_safety_comment_satisfies_the_rule() {
        assert!(!hit("fn f() {\n // SAFETY: p is valid for reads of len bytes\n unsafe { g(); }\n}\n", "UNSAFE.1"));
    }

    #[test]
    fn static_mut_is_high_severity_because_edition_2024_rejects_it() {
        let f: Vec<Finding> = check("static mut COUNT: u32 = 0;\n")
            .into_iter()
            .filter(|f| f.rule.as_str().ends_with("UNSAFE.4"))
            .collect();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn panics_are_more_severe_in_no_std_firmware() {
        let hosted = check("fn f() { o.unwrap(); }\n");
        let firmware = check("#![no_std]\nfn f() { o.unwrap(); }\n");
        let sev = |v: &[Finding]| {
            v.iter().find(|f| f.rule.as_str().ends_with("PANIC.1")).map(|f| f.severity)
        };
        assert_eq!(sev(&hosted), Some(Severity::Medium));
        assert_eq!(sev(&firmware), Some(Severity::High));
    }

    /// FFI.1 is about each declaration, not the block that holds them.
    ///
    /// A comment above the block satisfied the old check however many
    /// undocumented declarations were inside it — and a comment above a block
    /// cannot say what `buf` must point to, because it does not know which
    /// function it is describing. This is the direction that mattered: the
    /// other one merely reported conforming code, while this one reported
    /// nothing at all.
    #[test]
    fn a_comment_above_an_extern_block_does_not_document_what_is_inside_it() {
        let src = "/// Bindings to the vendor HAL.
unsafe extern \"C\" {
    pub fn fill(buf: *mut u8, len: usize);
    pub fn tick();
}
";
        assert!(
            hit(src, "FFI.1"),
            "two undocumented declarations behind one block comment: {:?}",
            rules(src)
        );
    }

    /// And a declaration documented where it is written is accepted.
    #[test]
    fn a_declaration_documented_inside_the_block_is_accepted() {
        let src = "unsafe extern \"C\" {
    /// # Safety
    ///
    /// `buf` must point to `len` writable bytes.
    pub fn fill(buf: *mut u8, len: usize);
}
";
        assert!(
            !hit(src, "FFI.1"),
            "documented at the declaration, which is where rustdoc renders it: {:?}",
            rules(src)
        );
    }

    #[test]
    fn panics_in_test_modules_are_not_reported() {
        let src = "#[cfg(test)]\nmod tests {\n #[test]\n fn t() { x.unwrap(); }\n}\n";
        assert!(!hit(src, "PANIC.1"));
    }

    #[test]
    fn bare_extern_block_flags_the_edition_2024_migration() {
        assert!(hit("extern \"C\" { fn hal(); }\n", "ED2024.3"));
        assert!(!hit("unsafe extern \"C\" { fn hal(); }\n", "ED2024.3"));
    }

    #[test]
    fn undocumented_ffi_boundary_is_reported() {
        assert!(hit("unsafe extern \"C\" { fn hal(); }\n", "FFI.1"));
        assert!(!hit("// hal() must be called after clock init\nunsafe extern \"C\" { fn hal(); }\n", "FFI.1"));
    }

    #[test]
    fn gen_as_an_identifier_is_an_edition_2024_error() {
        assert!(hit("fn f() { let gen = 1; }\n", "ED2024.1"));
    }

    #[test]
    fn unsafe_attributes_must_use_the_unsafe_form() {
        assert!(hit("#[no_mangle]\npub fn entry() {}\n", "ED2024.4"));
        assert!(!hit("#[unsafe(no_mangle)]\npub fn entry() {}\n", "ED2024.4"));
    }

    #[test]
    fn unjustified_unsafe_send_impl_is_high_severity() {
        let f = check("unsafe impl Send for Handle {}\n");
        let c = f.iter().find(|f| f.rule.as_str().ends_with("CONC.1")).unwrap();
        assert_eq!(c.severity, Severity::High);
        assert!(!hit("// SAFETY: the handle is only ever moved, never shared\nunsafe impl Send for Handle {}\n", "CONC.1"));
    }

    #[test]
    fn allocation_is_only_flagged_in_no_std_crates() {
        assert!(hit("#![no_std]\nfn f() -> Vec<u8> { Vec::new() }\n", "EMB.1"));
        assert!(!hit("fn f() -> Vec<u8> { Vec::new() }\n", "EMB.1"));
    }

    #[test]
    fn embedded_model_without_a_digest_check_is_reported() {
        assert!(hit(
            "static W: &[u8] = include_bytes!(\"../model/tiny.gguf\");\n",
            "MODEL.1"
        ));
    }

    #[test]
    fn a_digest_check_in_the_file_satisfies_model_1() {
        assert!(!hit(
            "const DIGEST: [u8; 32] = [0; 32];\nstatic W: &[u8] = include_bytes!(\"../model/tiny.gguf\");\n",
            "MODEL.1"
        ));
    }

    #[test]
    fn non_model_includes_are_not_flagged() {
        assert!(!hit("static LOGO: &[u8] = include_bytes!(\"../assets/logo.png\");\n", "MODEL.1"));
    }

    #[test]
    fn pickle_formats_are_critical() {
        let f = check("const PATH: &str = \"weights.pth\";\n");
        let m = f.iter().find(|f| f.rule.as_str().ends_with("MODEL.3")).unwrap();
        assert_eq!(m.severity, Severity::Critical);
        assert!(m.message.contains("remote code execution"));
    }

    #[test]
    fn loading_through_a_pickle_api_is_flagged() {
        assert!(hit("fn f() { let m = serde_pickle::from_slice(&bytes); }\n", "MODEL.3"));
        assert!(hit("fn f() { let m = torch::load(path); }\n", "MODEL.3"));
    }

    #[test]
    fn analysing_pickle_is_not_using_pickle() {
        // The self-scan false positive: a tool that inspects pickle files was
        // flagged 60 times at Critical for naming the thing it inspects. A
        // checker that cannot tell analysis from use produces noise, and noise
        // at Critical is worse than silence.
        let analyser = "mod pickle;\n\
                        use crate::pickle::PickleScan;\n\
                        pub fn looks_like_pickle(data: &[u8]) -> bool { data[0] == 0x80 }\n\
                        pub fn scan_pickle(&self, head: &[u8]) { let s = pickle::scan(head); }\n";
        assert!(
            !hit(analyser, "MODEL.3"),
            "naming, importing or inspecting pickle must not be reported as using it"
        );

        // An unrelated `load` call is not a pickle load either.
        assert!(!hit("fn f() { let c = config::load(path); }\n", "MODEL.3"));

        // Nor is recognising the extension the same as loading one.
        assert!(!hit("fn f(n: &str) -> bool { n.ends_with(\".pkl\") }\n", "MODEL.3"));
        assert!(hit("const P: &str = \"weights.pkl\";\n", "MODEL.3"), "a real filename still counts");

        // A filename handed to a matching predicate is a pattern, not a path.
        assert!(!hit("fn f(n: &str) -> bool { n.ends_with(\"data.pkl\") }\n", "MODEL.3"));
        assert!(!hit("fn f(n: &str) -> bool { n.contains(\"model.pth\") }\n", "MODEL.3"));

        // A fixture in a test module is not shipping code.
        let fixture = "#[cfg(test)]\nmod tests {\n #[test]\n fn t() { scan(\"evil.pkl\"); }\n}\n";
        assert!(!hit(fixture, "MODEL.3"));

        // ...but the same literal in production code still is.
        assert!(hit("fn load() { scan(\"evil.pkl\"); }\n", "MODEL.3"));
    }

    #[test]
    fn build_scripts_are_flagged_as_supply_chain_surface() {
        let f = RustStaticAnalyzer::new().check_source(&PathBuf::from("build.rs"), "fn main() {}\n");
        assert!(f.iter().any(|f| f.rule.as_str().ends_with("DEP.2")));
        // ...but an ordinary source file is not.
        assert!(!hit("fn main() {}\n", "DEP.2"));
    }

    #[test]
    fn findings_carry_the_rust_2024_taxonomy_and_a_source_snippet() {
        let f = check("fn f() { unsafe { g(); } }\n");
        let u = f.iter().find(|f| f.rule.as_str().ends_with("UNSAFE.1")).unwrap();
        assert!(u.taxonomy.iter().any(|t| t.scheme == sda_core::Taxonomy::Rust2024));
        assert!(u.evidence.iter().any(|e| matches!(e, Evidence::Source { .. })));
    }
}

