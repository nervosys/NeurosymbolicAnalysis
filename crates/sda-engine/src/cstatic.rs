//! The native C/C++ static checker — the toolkit's default static provider.
//!
//! Every check here runs on the token stream and structural facts from
//! `sda-syntax`, with no compiler, no configuration, and no external process.
//! That buys three things worth having:
//!
//! * it runs on code that does not build, which is most code most of the time;
//! * it runs in milliseconds, so it can drive an editor and an agent loop;
//! * its claims are bounded by construction — nothing here needs type
//!   information, so nothing here can be wrong about types.
//!
//! Guidelines that genuinely need semantics are *not* faked. They are recorded
//! in `sda-rules` as [`Coverage::Semantics`](sda_rules::Coverage) and routed to a
//! real compiler through `sda-build`, and a run says so.

use crate::checks::{CheckId, IMPLEMENTED_C};
use sda_core::{
    Analyzer, AnalyzerKind, Availability, Capability, Confidence, Evidence, Finding, Language,
    Location, ProviderInfo, RunOptions, Severity, Target,
};
use sda_rules::{Catalog, Coverage, Rule, Standard};
use sda_syntax::{
    CStructure, CToken, CTokenKind, Dialect, LexNoteKind, Lexed, Span, cstruct, lex,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Identifiers whose mere use violates a library-restriction guideline, mapped
/// to the guideline they violate.
const BANNED_FUNCTIONS: &[(&str, &str)] = &[
    // 21.3 dynamic memory
    ("malloc", "21.3"),
    ("calloc", "21.3"),
    ("realloc", "21.3"),
    ("free", "21.3"),
    ("aligned_alloc", "21.3"),
    // 21.4 setjmp
    ("setjmp", "21.4"),
    ("longjmp", "21.4"),
    // 21.5 signals
    ("signal", "21.5"),
    ("raise", "21.5"),
    // 21.6 stdio
    ("printf", "21.6"),
    ("fprintf", "21.6"),
    ("sprintf", "21.6"),
    ("snprintf", "21.6"),
    ("vprintf", "21.6"),
    ("vsprintf", "21.6"),
    ("scanf", "21.6"),
    ("fscanf", "21.6"),
    ("sscanf", "21.6"),
    ("gets", "21.6"),
    ("puts", "21.6"),
    ("fopen", "21.6"),
    ("fclose", "21.6"),
    ("fread", "21.6"),
    ("fwrite", "21.6"),
    ("perror", "21.6"),
    ("vfprintf", "21.6"),
    ("vsnprintf", "21.6"),
    ("vscanf", "21.6"),
    ("vfscanf", "21.6"),
    ("vsscanf", "21.6"),
    ("getchar", "21.6"),
    ("putchar", "21.6"),
    ("getc", "21.6"),
    ("putc", "21.6"),
    ("fgetc", "21.6"),
    ("fputc", "21.6"),
    ("fgets", "21.6"),
    ("fputs", "21.6"),
    ("ungetc", "21.6"),
    ("freopen", "21.6"),
    ("fflush", "21.6"),
    ("setbuf", "21.6"),
    ("setvbuf", "21.6"),
    ("fseek", "21.6"),
    ("ftell", "21.6"),
    ("rewind", "21.6"),
    ("fgetpos", "21.6"),
    ("fsetpos", "21.6"),
    ("clearerr", "21.6"),
    ("feof", "21.6"),
    ("ferror", "21.6"),
    ("tmpfile", "21.6"),
    ("tmpnam", "21.6"),
    // `remove` and `rename` are <stdio.h> functions too, and are left out: a
    // free call named either is as likely `std::remove` or the project's own.
    // Including <stdio.h> is reported, which covers them in a C file.
    // 21.7 unchecked string-to-number conversion
    ("atof", "21.7"),
    ("atoi", "21.7"),
    ("atol", "21.7"),
    ("atoll", "21.7"),
    // 21.8 termination
    ("abort", "21.8"),
    ("exit", "21.8"),
    ("_Exit", "21.8"),
    ("quick_exit", "21.8"),
    // 21.9 search and sort
    ("bsearch", "21.9"),
    ("qsort", "21.9"),
    // 21.10 time and date
    ("time", "21.10"),
    ("clock", "21.10"),
    ("difftime", "21.10"),
    ("mktime", "21.10"),
    ("asctime", "21.10"),
    ("ctime", "21.10"),
    ("gmtime", "21.10"),
    ("localtime", "21.10"),
    ("strftime", "21.10"),
    // 21.12 floating-point exception handling
    ("feclearexcept", "21.12"),
    ("fegetexceptflag", "21.12"),
    ("feraiseexcept", "21.12"),
    ("fesetexceptflag", "21.12"),
    ("fetestexcept", "21.12"),
    // 21.21 command execution
    ("system", "21.21"),
    // 21.24 random numbers
    ("rand", "21.24"),
    ("srand", "21.24"),
];

/// Headers whose inclusion violates a guideline.
const BANNED_HEADERS: &[(&str, &str)] = &[
    ("stdio.h", "21.6"),
    ("setjmp.h", "21.4"),
    ("signal.h", "21.5"),
    ("tgmath.h", "21.11"),
    ("stdarg.h", "17.1"),
    ("cstdio", "21.6"),
    ("csetjmp", "21.4"),
    ("csignal", "21.5"),
    ("iostream", "21.6"),
];

/// Checks are written once and emit a *canonical* guideline number — the MISRA
/// C:2023 one. This table translates that to the equivalent MISRA C++:2023
/// guideline so the same check serves both dialects.
///
/// Without it the C++ analyzer silently emits nothing: every `emit("15.6", ..)`
/// looks up a number that does not exist in the C++ catalogue and is dropped.
/// An entry mapping to `None` means the guideline has no C++ counterpart, or is
/// subsumed by another that is already reported.
const C_TO_CPP: &[(&str, Option<&str>)] = &[
    ("3.1", Some("5.7.1")),
    ("3.2", Some("5.7.2")),
    ("7.1", Some("5.13.1")),
    ("7.3", Some("5.13.2")),
    ("15.1", Some("9.6.1")),
    ("15.6", Some("9.4.1")),
    ("16.3", Some("9.4.2")),
    ("16.4", Some("9.4.3")),
    ("18.5", Some("11.3.1")),
    ("19.2", Some("12.2.1")),
    ("D4.9", Some("19.0.1")),
    ("20.10", Some("19.3.1")),
    ("D4.10", Some("19.6.1")),
    ("21.3", Some("21.6.1")),
    ("21.4", Some("21.10.1")),
    ("21.5", Some("21.10.2")),
    ("21.6", Some("30.0.1")),
    // Subsumed by 21.6.1, which the allocation-function check already reports.
    ("D4.12", None),
];

/// C++-only checks, keyed by the guideline they report.
const CPP_ONLY: &[&str] = &["8.2.1", "8.2.2", "8.2.3", "24.5.1"];

/// `<cstring>` functions banned by MISRA C++:2023 clause 24.
const CSTRING_FUNCTIONS: &[&str] = &[
    "strcpy", "strncpy", "strcat", "strncat", "strlen", "strcmp", "strncmp", "strtok", "memcpy",
    "memmove", "memset", "sprintf",
];

/// Reserved identifier prefixes that may not be `#define`d or `#undef`ed (21.1).
fn is_reserved_identifier(name: &str) -> bool {
    if name.starts_with("__") {
        return true;
    }
    if let Some(rest) = name.strip_prefix('_') {
        // `_X` with an uppercase second letter is reserved to the implementation.
        return rest.chars().next().is_some_and(|c| c.is_ascii_uppercase());
    }
    matches!(
        name,
        "errno" | "assert" | "NULL" | "offsetof" | "size_t" | "EOF" | "stdin" | "stdout" | "stderr"
    )
}

/// The basic numerical types MISRA asks be replaced by width-explicit typedefs.
const BASIC_NUMERIC_TYPES: &[&str] = &["short", "long", "int", "float", "double"];

/// Keywords that can stand immediately before a `*` in a declarator.
///
/// Deliberately not "any keyword": `else *p = 0;` and `return *p = 0;` are
/// statements, not declarations, and telling them apart is the whole job.
const DECLARATION_HEADS: &[&str] = &[
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool",
    "bool", "const", "volatile", "restrict", "struct", "union", "enum", "static", "extern",
    "register", "_Atomic",
];

/// Keywords that begin a declaration, or a construct that is not an expression.
/// A statement starting with one is never a comma operator at its top level.
const DECLARATION_START: &[&str] = &[
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool",
    "bool", "const", "volatile", "restrict", "struct", "union", "enum", "static", "extern",
    "register", "_Atomic", "typedef", "auto", "inline", "constexpr", "consteval", "thread_local",
    "_Thread_local", "_Noreturn", "_Complex", "_BitInt", "typeof", "typeof_unqual", "using",
    "template", "typename", "class", "namespace", "friend", "public", "private", "protected",
    "virtual", "explicit", "mutable", "static_assert", "_Static_assert",
];

/// The type qualifiers, which may stand between pointer levels or after `[`.
fn is_type_qualifier(token: &str) -> bool {
    matches!(token, "const" | "volatile" | "restrict" | "__restrict" | "_Atomic")
}

/// A directive's condition or argument with any trailing comment removed.
fn directive_condition(body: &str) -> &str {
    let body = body.split("//").next().unwrap_or(body);
    body.split("/*").next().unwrap_or(body).trim()
}

/// The macro named by a condition of the form `!defined(X)` or `!defined X`,
/// when that is the whole condition. Anything more (`&& Y`, `!defined(X) || Z`)
/// is not a guard and is not read as one.
fn negated_defined_name(body: &str) -> Option<&str> {
    let is_name_byte = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let rest = directive_condition(body).strip_prefix('!')?.trim_start();
    let rest = rest.strip_prefix("defined")?;
    if rest.starts_with(is_name_byte) {
        return None; // `definedX` is some other word
    }
    let rest = rest.trim_start();
    let (name, tail) = match rest.strip_prefix('(') {
        Some(inner) => {
            let inner = inner.trim_start();
            let end = inner.find(|c| !is_name_byte(c)).unwrap_or(inner.len());
            (&inner[..end], inner[end..].trim_start().strip_prefix(')')?)
        }
        None => {
            let end = rest.find(|c| !is_name_byte(c)).unwrap_or(rest.len());
            (&rest[..end], &rest[end..])
        }
    };
    (!name.is_empty() && tail.trim().is_empty()).then_some(name)
}

/// Characters that are typographically confusable, collapsed to a canonical
/// form so `l1I` and `O0` style collisions can be found (D4.5).
fn ambiguity_key(ident: &str) -> String {
    ident
        .chars()
        .map(|c| match c {
            'l' | 'I' | '1' | '|' => '1',
            'O' | '0' | 'o' => '0',
            'S' | '5' | 's' => '5',
            'Z' | '2' | 'z' => '2',
            'B' | '8' => '8',
            '_' => '_',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// The native C/C++ static analyzer.
pub struct CStaticAnalyzer {
    dialect: Dialect,
    catalog: Catalog,
    /// Files this analyzer could not read, drained by [`Analyzer::take_notices`].
    ///
    /// Behind a lock because `analyze` takes `&self`, exactly as the external
    /// adapters do it.
    notices: std::sync::Mutex<Vec<sda_core::Exclusion>>,
}

impl CStaticAnalyzer {
    pub fn c() -> Self {
        CStaticAnalyzer {
            dialect: Dialect::C23,
            catalog: Catalog::load(Standard::MisraC2023),
            notices: std::sync::Mutex::new(Vec::new()),
        }
    }
    pub fn cpp() -> Self {
        CStaticAnalyzer {
            dialect: Dialect::Cpp23,
            catalog: Catalog::load(Standard::MisraCpp2023),
            notices: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Build with a supplied catalogue, so a project's licensed guideline list
    /// reaches the findings.
    ///
    /// Without this the analyzers always loaded the built-in catalogue and an
    /// imported list changed nothing — findings kept citing a clause and saying
    /// the number was unconfirmed, while the authoritative list sat unread in
    /// `.sda/`.
    pub fn with_catalog(dialect: Dialect, catalog: Catalog) -> Self {
        CStaticAnalyzer { dialect, catalog, notices: std::sync::Mutex::new(Vec::new()) }
    }

    /// Record a file this analyzer was given and could not read.
    ///
    /// It says *unchecked*, not *clean*: a file discovery counted and analysis
    /// skipped is the difference between "we looked at your tree" and "we looked
    /// at most of your tree", and only the report can tell the reader which.
    /// A file that was read and could not be tokenised.
    ///
    /// `SDA-C-LEXICAL` already reports this as a finding, and the finding is not
    /// enough. An unterminated comment on line 1 swallows the rest of the file:
    /// measured on a six-line function, `plain.c` produced three MISRA findings
    /// and the same function behind an unclosed comment produced none. The
    /// findings are not suspect, they are *absent*, and *NOT CHECKED* — the
    /// section whose whole job is to say which files a clean result does not
    /// cover — did not mention the file at all.
    ///
    /// Both halves of that matter. A reader who sees the finding and then sees
    /// no MISRA findings for the file concludes "suspect, but clean". A reader
    /// auditing what was covered reads the section built for the question and is
    /// told nothing.
    fn note_unlexable(&self, shown: &str, what: &str, line: u32) {
        let mut held = self.notices.lock().unwrap_or_else(|p| p.into_inner());
        held.push(sda_core::Exclusion {
            provider: match self.dialect {
                Dialect::C23 => "sda.static.c".into(),
                Dialect::Cpp23 => "sda.static.cpp".into(),
            },
            reason: format!(
                "`{shown}` could not be tokenised: {what} at line {line} runs to the end of the \
                 file. Everything after it was swallowed, so no guideline was checked below \
                 that line. Finding nothing there is not the same as there being nothing \
                 there. Close it and scan again before reading this file as clean"
            ),
        });
    }

    fn note_unreadable(&self, shown: &str, e: &std::io::Error) {
        let mut held = self.notices.lock().unwrap_or_else(|p| p.into_inner());
        held.push(sda_core::Exclusion {
            provider: match self.dialect {
                Dialect::C23 => "sda.static.c".into(),
                Dialect::Cpp23 => "sda.static.cpp".into(),
            },
            reason: format!(
                "`{shown}` was discovered as a source file and could not be read ({e}), so no \
                 guideline was checked against it. The findings in this report describe the \
                 files that were read"
            ),
        });
    }

    fn provider_id(&self) -> &'static str {
        match self.dialect {
            Dialect::C23 => "sda.static.c",
            Dialect::Cpp23 => "sda.static.cpp",
        }
    }

    fn language(&self) -> Language {
        match self.dialect {
            Dialect::C23 => Language::C,
            Dialect::Cpp23 => Language::Cpp,
        }
    }

    /// Check one source text. Exposed directly so the GUI and the agent can
    /// check a buffer that was never written to disk.
    pub fn check_source(&self, path: &Path, src: &str) -> Vec<Finding> {
        let lexed = lex(src, self.dialect);
        let structure = cstruct::analyze_c(src, &lexed);
        self.check_parsed(path, src, &lexed, &structure)
    }

    /// The same checks, over a file the caller has already lexed and parsed.
    ///
    /// `analyze` needs the structural model for the whole-program pass below,
    /// and parsing every file twice to get it would double the cost of the
    /// largest run this toolkit does.
    fn check_parsed(
        &self,
        path: &Path,
        src: &str,
        lexed: &Lexed,
        structure: &CStructure,
    ) -> Vec<Finding> {
        let mut cx = Cx {
            path,
            src,
            lexed,
            st: structure,
            code: lexed.code_tokens().collect(),
            catalog: &self.catalog,
            provider: self.provider_id(),
            dialect: self.dialect,
            findings: Vec::new(),
        };
        cx.run_all();
        cx.findings
    }

    /// Emit findings whose *reason* was computed across files, at positions in
    /// one of them.
    ///
    /// Re-lexes, and is meant to: it runs only for a file that owns a name
    /// involved in a collision, which on a conforming project is no files at
    /// all.
    fn emit_at(&self, path: &Path, src: &str, hits: &[CrossFileHit]) -> Vec<Finding> {
        let lexed = lex(src, self.dialect);
        let structure = cstruct::analyze_c(src, &lexed);
        let mut cx = Cx {
            path,
            src,
            lexed: &lexed,
            st: &structure,
            code: lexed.code_tokens().collect(),
            catalog: &self.catalog,
            provider: self.provider_id(),
            dialect: self.dialect,
            findings: Vec::new(),
        };
        for h in hits {
            cx.emit(h.number, h.line, h.column, h.message.clone());
        }
        cx.findings
    }
}

/// One external definition, as the whole-program pass needs to see it.
struct ExternalDef {
    name: String,
    /// Path as the report will name it, relative to the target root.
    rel: std::path::PathBuf,
    /// Path to read back, when this file turns out to own a collision.
    abs: std::path::PathBuf,
    line: u32,
    column: u32,
}

/// A finding the per-file pass could not have reached.
struct CrossFileHit {
    number: &'static str,
    line: u32,
    column: u32,
    message: String,
}

/// MISRA 5.1 and D4.5, across translation units.
///
/// Both guidelines are `system` scope — judged across the whole program — and
/// both were checked one file at a time, which is the case that cannot matter:
/// two indistinguishable external identifiers *in the same file* are a compile
/// error long before MISRA is consulted. See
/// `crates/sda-engine/tests/system_scope_needs_the_whole_program.rs`.
///
/// Only external linkage is compared. Two `static` functions with the same name
/// in different files are correct C, and treating them as a collision would make
/// this check unusable on any real project.
fn cross_file_identifier_hits(
    defs: &[ExternalDef],
) -> BTreeMap<std::path::PathBuf, Vec<CrossFileHit>> {
    fn collect(
        defs: &[ExternalDef],
        key: fn(&str) -> String,
        number: &'static str,
        describe: fn(&str, &str, &Path) -> String,
        out: &mut BTreeMap<std::path::PathBuf, Vec<CrossFileHit>>,
    ) {
        // The first definition of a key holds it; every later one spelled
        // differently, in a different file, is reported against it. A pair is
        // therefore named once, at the second of the two.
        let mut first: BTreeMap<String, &ExternalDef> = BTreeMap::new();
        for d in defs {
            let k = key(&d.name);
            match first.get(&k) {
                Some(other) if other.name != d.name && other.rel != d.rel => {
                    out.entry(d.abs.clone()).or_default().push(CrossFileHit {
                        number,
                        line: d.line,
                        column: d.column,
                        message: describe(&d.name, &other.name, &other.rel),
                    });
                }
                Some(_) => {}
                None => {
                    first.insert(k, d);
                }
            }
        }
    }

    let mut out: BTreeMap<std::path::PathBuf, Vec<CrossFileHit>> = BTreeMap::new();
    collect(defs, significant, "5.1", describe_5_1, &mut out);
    collect(defs, ambiguity_key, "D4.5", describe_d4_5, &mut out);
    out
}

fn describe_5_1(name: &str, other: &str, where_: &Path) -> String {
    format!(
        "`{name}` is not distinct from `{other}` in {} within the first 31 significant \
         characters, which is all a conforming linker must consider",
        where_.display()
    )
}

fn describe_d4_5(name: &str, other: &str, where_: &Path) -> String {
    format!(
        "`{name}` is typographically ambiguous with `{other}` in {}; both have external linkage, \
         so their visibility overlaps",
        where_.display()
    )
}

impl Analyzer for CStaticAnalyzer {
    fn info(&self) -> ProviderInfo {
        let (name, desc) = match self.dialect {
            Dialect::C23 => (
                "NERVOSYS native C checker",
                "Native MISRA C:2023 checker over the C23 token stream and structural model. \
                 No compiler, no configuration, no external process; runs on code that does not build.",
            ),
            Dialect::Cpp23 => (
                "NERVOSYS native C++ checker",
                "Native MISRA C++:2023 checker over the C++23 token stream and structural model. \
                 Guidelines whose numbers are unconfirmed are reported against their clause.",
            ),
        };
        ProviderInfo::native(
            self.provider_id(),
            name,
            AnalyzerKind::Static,
            vec![self.language()],
            vec![
                Capability::StyleCompliance,
                Capability::MetricsCollection,
                Capability::ProgramFactExtraction,
            ],
            desc,
        )
    }

    fn available(&self) -> Availability {
        Availability::Available
    }

    /// Drained, not read, exactly as the external adapters do it: a second
    /// collection must not repeat the first run's story.
    fn take_notices(&self) -> Vec<sda_core::Exclusion> {
        let mut held = self.notices.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut *held)
    }

    fn analyze(&self, target: &Target, opts: &RunOptions) -> sda_core::Result<Vec<Finding>> {
        let mut out = Vec::new();
        let langs = match self.dialect {
            Dialect::C23 => vec![Language::C],
            Dialect::Cpp23 => vec![Language::Cpp],
        };
        let mut externals: Vec<ExternalDef> = Vec::new();
        for file in target.files_in(&langs) {
            // One unreadable file must not discard the analysis of every other
            // one. This used to be `?`, so a single source that is not valid
            // UTF-8 — a Latin-1 name in a copyright comment, which is ordinary
            // in legacy C — failed the whole provider and took every finding
            // from every other file with it. Four findings became zero on a
            // two-file tree. The same rule the `--artifact` launch already
            // learned: an inability to check one thing must not throw away the
            // checks that did happen, and must not pass silently either.
            let src = match std::fs::read_to_string(&file.path) {
                Ok(src) => src,
                Err(e) => {
                    self.note_unreadable(&target.relativize(&file.path).display().to_string(), &e);
                    continue;
                }
            };
            let rel = target.relativize(&file.path).to_path_buf();
            let lexed = lex(&src, self.dialect);

            // Before anything is checked against this file, decide whether it is
            // a file at all as far as the lexer is concerned.
            if let Some(note) = lexed.notes.iter().find(|n| {
                matches!(
                    n.kind,
                    sda_syntax::clex::LexNoteKind::UnterminatedComment
                        | sda_syntax::clex::LexNoteKind::UnterminatedLiteral
                )
            }) {
                let what = match note.kind {
                    sda_syntax::clex::LexNoteKind::UnterminatedComment => "a block comment opened",
                    _ => "a literal opened",
                };
                self.note_unlexable(&rel.display().to_string(), what, note.pos.line);
            }
            let structure = cstruct::analyze_c(&src, &lexed);
            // C only, and translation units only.
            //
            // C++ has namespaces and overloading, so two identical external
            // names in different files say nothing on their own. And a header is
            // not a translation unit: it is text included into one. This toolkit
            // analyses headers standalone on purpose — that is what lets it run
            // on code that does not build — which attributes their definitions to
            // the header rather than to each unit that includes it. Comparing
            // across those attributions manufactures pairs no linker ever sees.
            // On PX4 that was `virtual void run()` in one C++ header against
            // `Run` in another, neither of them a C function with external
            // linkage.
            let is_translation_unit =
                file.path.extension().is_some_and(|e| e.eq_ignore_ascii_case("c"));
            if self.dialect == Dialect::C23 && is_translation_unit {
                let functions =
                    structure.functions.iter().filter(|f| !f.internal_linkage).map(|f| {
                        (f.name.clone(), f.pos)
                    });
                // Objects with external linkage are external identifiers too,
                // and 5.1 is about identifiers. Reading them is deliberately
                // incomplete — see `cstruct::parse_objects` — so this closes most
                // of the remaining gap rather than all of it.
                let objects = structure
                    .objects
                    .iter()
                    .filter(|o| !o.internal_linkage)
                    .map(|o| (o.name.clone(), o.pos));
                externals.extend(functions.chain(objects).map(|(name, pos)| ExternalDef {
                    name,
                    rel: rel.clone(),
                    abs: file.path.clone(),
                    line: pos.line,
                    column: pos.column,
                }));
            }
            out.extend(self.check_parsed(&rel, &src, &lexed, &structure));
        }

        // The whole-program pass. Nothing to do unless two files collide, which
        // is why re-reading the ones that do costs nothing on a clean project.
        for (abs, hits) in cross_file_identifier_hits(&externals) {
            let Ok(src) = std::fs::read_to_string(&abs) else { continue };
            let rel = target.relativize(&abs).to_path_buf();
            out.extend(self.emit_at(&rel, &src, &hits));
        }
        out.retain(|f| !opts.disabled_rules.iter().any(|r| f.rule.as_str().ends_with(r)));
        Ok(out)
    }
}

impl sda_core::StaticAnalyzer for CStaticAnalyzer {}

// --- the check context -----------------------------------------------------

struct Cx<'a> {
    path: &'a Path,
    src: &'a str,
    lexed: &'a Lexed,
    st: &'a CStructure,
    code: Vec<&'a CToken>,
    catalog: &'a Catalog,
    provider: &'static str,
    dialect: Dialect,
    findings: Vec<Finding>,
}

/// What a `{` opens, as far as the bit-field rule cares.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Union,
    Struct,
    Other,
}

/// What `check_switches` needs to know about one `switch`, copied out of the
/// structure before reporting.
///
/// A named type rather than a seven-element tuple, which nothing but position
/// explained. The copy is not incidental: `emit` takes `&mut self`, so the borrow
/// of `self.st.switches` has to end before any finding is reported.
type SwitchFacts = (u32, u32, bool, usize, bool, Vec<(u32, u32)>, Vec<(u32, u32)>);

impl<'a> Cx<'a> {
    fn run_all(&mut self) {
        self.check_lexical();
        self.check_comments();
        self.check_literals();
        self.check_identifiers();
        self.check_directives();
        self.check_includes();
        self.check_declarations();
        self.check_control_flow();
        self.check_switches();
        self.check_jumps();
        self.check_expressions();
        self.check_library_use();
        self.check_recursion();
        self.check_unused_macros();
        self.check_external_identifier_distinctness();
        self.check_for_loop_form();
        self.check_switch_wellformedness();
        self.check_reserved_declarations();
        self.check_assembly_documentation();
        if self.dialect.is_cpp() {
            self.check_cpp_casts();
            self.check_cpp_library_use();
        }
        self.emit_metrics();
    }

    /// Resolve a canonical (MISRA C) guideline number to the one this dialect's
    /// catalogue uses. Returns `None` when the guideline genuinely has no
    /// counterpart here, which is the only case where dropping a finding is correct.
    fn resolve(&self, canonical: &str) -> Option<String> {
        match self.dialect {
            Dialect::C23 => Some(canonical.to_string()),
            Dialect::Cpp23 => {
                // A C++-only check names its own guideline directly.
                if CPP_ONLY.contains(&canonical) {
                    return Some(canonical.to_string());
                }
                match C_TO_CPP.iter().find(|(c, _)| *c == canonical) {
                    Some((_, mapped)) => mapped.map(|m| m.to_string()),
                    // Unmapped: the check has no C++ counterpart in the partial
                    // catalogue. Dropping it is correct, and the coverage audit
                    // already reports the catalogue as incomplete.
                    None => None,
                }
            }
        }
    }

    /// A location carrying the extent of the token it points at.
    ///
    /// Checks report where a violation starts; the span is derived from the
    /// source so SARIF regions bracket the offending token instead of naming a
    /// point, and the editor underlines that token instead of the whole line.
    fn located(&self, line: u32, column: u32) -> Location {
        let (line, column) = (line.max(1), column.max(1));
        let loc = Location::new(self.path, line, column);
        let Some(span) = self.lexed.lines.line_span(line) else { return loc };

        // Prefer the lexer's own tokenisation: it already knows that a
        // directive, a block comment or an `L"..."` literal is a single token.
        let offset = span.start + (column - 1) as usize;
        if let Some(tok) = self.lexed.token_at_offset(offset) {
            let end = self.lexed.lines.pos(tok.span.end);
            if (end.line, end.column) > (line, column) {
                return loc.spanning(end.line, end.column);
            }
        }

        // Positions a check synthesised rather than took from a token still get
        // an extent, just a text-derived one.
        match self.lexed.lines.line_text(self.src, line) {
            Some(text) => {
                let end = sda_syntax::token_end_column(text, column);
                // A zero-width span is no better than none, and worse to render.
                if end > column { loc.spanning(line, end) } else { loc }
            }
            None => loc,
        }
    }

    /// Emit a finding for canonical guideline `number`.
    /// Function declarations at file scope: `(name, position, parameter text)`.
    ///
    /// `CStructure::functions` holds definitions, so a prototype in a header was
    /// invisible to every check that reads it. This walks `;`-terminated runs at
    /// brace depth zero and keeps the ones shaped like `name ( ... ) ;`.
    fn file_scope_declarations(&self) -> Vec<(String, sda_syntax::Pos, String)> {
        let mut out = Vec::new();
        let mut depth = 0i32;
        let mut start = 0usize;
        let n = self.code.len();
        for i in 0..n {
            match self.tok(i) {
                "{" => {
                    depth += 1;
                    start = i + 1;
                }
                "}" => {
                    depth -= 1;
                    start = i + 1;
                }
                ";" => {
                    if depth == 0 && i > start {
                        self.read_prototype(start, i, &mut out);
                    }
                    start = i + 1;
                }
                _ => {}
            }
        }
        out
    }

    fn read_prototype(
        &self,
        start: usize,
        end: usize,
        out: &mut Vec<(String, sda_syntax::Pos, String)>,
    ) {
        // The declarator is the last `name ( ... )` whose `)` ends the run, which
        // rules out a function-pointer parameter's own parentheses.
        if !self.code[end - 1].is(self.src, ")") {
            return;
        }
        let mut open = None;
        let mut depth = 0i32;
        for k in (start..end).rev() {
            match self.tok(k) {
                ")" => depth += 1,
                "(" => {
                    depth -= 1;
                    if depth == 0 {
                        open = Some(k);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(open) = open else { return };
        if open == start || self.code[open - 1].kind != CTokenKind::Identifier {
            return;
        }
        // A declaration has declaration specifiers — at least a return type —
        // before the name. Without that requirement a file-scope macro
        // invocation reads as a prototype: PX4 has hundreds of
        // `PARAM_DEFINE_INT32(SLNK_RADIO_CHAN, 80);`, whose `80` then looks like
        // an unnamed parameter. Nothing here expands macros, so the shape is all
        // there is to go on, and this is the half of it that is unambiguous.
        if open - 1 == start {
            return;
        }
        // Names the implementation owns are not function declarations.
        // `__attribute__((format(printf, 3, 4)))` at file scope otherwise reads
        // as a prototype named `__attribute__` whose parameter is `4))`.
        let name = self.code[open - 1].text(self.src);
        if name.starts_with("__") {
            return;
        }
        // A `.h` in a C++ project is read by this analyzer as C, on purpose —
        // that is what lets it run on code that does not build. What it must not
        // do is report C++ as malformed C. A run carrying `::`, a reference, a
        // default argument or `decltype` is not a C prototype, whatever else it
        // is, and PX4's headers are full of all four.
        if (start..end).any(|k| matches!(self.tok(k), "::" | "&" | "=" | "decltype" | "template")) {
            return;
        }
        // A definition is handled through `CStructure::functions`; this run ends
        // at a `;`, so it is a declaration by construction.
        let name_tok = self.code[open - 1];
        let params = if end - 1 > open + 1 {
            sda_syntax::Span::new(self.code[open + 1].span.start, self.code[end - 2].span.end)
                .slice(self.src)
                .to_string()
        } else {
            String::new()
        };
        out.push((name_tok.text(self.src).to_string(), name_tok.pos, params));
    }

    fn emit(&mut self, number: &str, line: u32, column: u32, message: impl Into<String>) {
        let Some(resolved) = self.resolve(number) else {
            return;
        };
        let Some(rule) = self.catalog.get(&resolved).cloned() else {
            return;
        };
        let f = self.build(&rule, line, column, message.into());
        self.findings.push(f);
    }

    /// Same, but overriding the severity implied by the guideline's category.
    fn emit_with(
        &mut self,
        number: &str,
        line: u32,
        column: u32,
        message: impl Into<String>,
        severity: Severity,
    ) {
        let Some(resolved) = self.resolve(number) else {
            return;
        };
        let Some(rule) = self.catalog.get(&resolved).cloned() else {
            return;
        };
        let mut f = self.build(&rule, line, column, message.into());
        f.severity = severity;
        self.findings.push(f);
    }

    /// Report an observation that is *not* a conformance check against any
    /// catalogued guideline.
    ///
    /// Cyclomatic complexity, a multi-character constant, a lexical error — all
    /// are worth surfacing, and all were once reported here under a nearby MISRA
    /// directive. That was wrong: it made a run appear to check a guideline it
    /// does not check, which is exactly what `checks::claimed_but_missing`
    /// exists to prevent. They get their own identifiers instead.
    fn advise(
        &mut self,
        id: &str,
        title: &str,
        line: u32,
        column: u32,
        message: impl Into<String>,
        severity: Severity,
    ) {
        let function = self.st.function_at(line).map(|f| f.name.clone());
        let mut loc = self.located(line, column);
        if let Some(name) = function {
            loc = loc.in_function(name);
        }
        let (first, text) = self.lexed.lines.context(self.src, line, 1);
        let f = Finding::new(self.provider, id, title, severity, loc.clone())
            .message(message)
            .confidence(Confidence::High)
            .evidence(Evidence::source(loc, first, text));
        self.findings.push(f);
    }

    fn build(&self, rule: &Rule, line: u32, column: u32, message: String) -> Finding {
        let function = self.st.function_at(line).map(|f| f.name.clone());
        let mut loc = self.located(line, column);
        if let Some(name) = function {
            loc = loc.in_function(name);
        }

        // Confidence is the lesser of what the guideline's coverage allows and
        // what the structural pass can stand behind. A file whose braces did not
        // balance gets everything downgraded, because the facts may be wrong.
        let mut confidence = rule.confidence_ceiling();
        if !self.st.is_reliable() && confidence > Confidence::Low {
            confidence = Confidence::Low;
        }

        let mut f =
            Finding::new(self.provider, rule.id.clone(), rule.title.clone(), rule.severity(), loc.clone())
                .message(message)
                .confidence(confidence);
        for t in rule.taxonomy_refs() {
            f = f.taxonomy(t);
        }
        // The source line is attached so a reviewer never has to open the file
        // to judge a finding.
        let (first, text) = self.lexed.lines.context(self.src, line, 1);
        f = f.evidence(Evidence::source(loc, first, text));
        if !rule.confirmed {
            f = f.evidence(Evidence::note(format!(
                "Cited as {} — the guideline number is not confirmed against the published \
                 document. Run `sda rules import` with a licensed list to get a citable number.",
                rule.citation()
            )));
        }
        if rule.coverage == Coverage::Partial {
            f = f.evidence(Evidence::note(
                "This guideline is only partially checked; absence of further findings for it \
                 does not establish conformance.",
            ));
        }
        f
    }

    fn pos_of(&self, idx: usize) -> (u32, u32) {
        let p = self.code[idx].pos;
        (p.line, p.column)
    }

    fn tok(&self, idx: usize) -> &str {
        self.code[idx].text(self.src)
    }

    /// The number of `*` in the pointer declarator from `start` on, counting
    /// through the type qualifiers that may sit between the levels.
    fn pointer_levels_from(&self, start: usize) -> usize {
        let mut levels = 0usize;
        for k in start..self.code.len() {
            match self.tok(k) {
                "*" => levels += 1,
                t if is_type_qualifier(t) => {}
                _ => break,
            }
        }
        levels
    }

    /// Whether the `*` at `i` is the first star of its declarator, so that
    /// [`Self::pointer_levels_from`] is not counted again from a later star.
    fn starts_pointer_chain(&self, i: usize) -> bool {
        let mut k = i;
        while k > 0 && is_type_qualifier(self.tok(k - 1)) {
            k -= 1;
        }
        k == 0 || self.tok(k - 1) != "*"
    }

    fn is_header(&self) -> bool {
        matches!(
            self.path.extension().and_then(|e| e.to_str()),
            Some("h" | "hpp" | "hh" | "hxx" | "h++")
        )
    }

    // --- lexical ----------------------------------------------------------

    fn check_lexical(&mut self) {
        let notes: Vec<(LexNoteKind, u32, u32, String)> = self
            .lexed
            .notes
            .iter()
            .map(|n| (n.kind, n.pos.line, n.pos.column, n.detail.clone()))
            .collect();
        for (kind, line, col, detail) in notes {
            match kind {
                LexNoteKind::NestedBlockCommentOpen => {
                    self.emit("3.1", line, col, format!("{detail}: the sequence /* inside a comment silently extends it, which usually means code below is no longer compiled"));
                }
                LexNoteKind::LineSplicedComment => {
                    self.emit("3.2", line, col, detail);
                }
                LexNoteKind::Trigraph => {
                    self.emit("4.2", line, col, format!("{detail}: trigraphs were removed in C23 and C++17, so this text means something different to a modern compiler"));
                }
                LexNoteKind::MultiCharacterConstant => {
                    self.advise(
                        "SDA-C-MULTICHAR",
                        "character constant holds more than one character",
                        line,
                        col,
                        format!("{detail}. MISRA Directive 4.1 requires the resulting implementation-defined value to be documented, but whether it is documented is not something this checker can determine."),
                        Severity::Medium,
                    );
                }
                LexNoteKind::UnterminatedComment | LexNoteKind::UnterminatedLiteral => {
                    self.advise(
                        "SDA-C-LEXICAL",
                        "source does not lex cleanly",
                        line,
                        col,
                        format!("{detail}. Everything after this point was swallowed, so the guidelines below it were not checked at all — this file's other findings are missing, not merely suspect. See NOT CHECKED, which names the file."),
                        Severity::High,
                    );
                }
                _ => {}
            }
        }
    }

    fn check_comments(&mut self) {
        // D4.4: code that has been commented out rather than deleted. The
        // heuristic looks for statement shape, not keywords, so a prose comment
        // mentioning `if` is not a hit.
        let candidates: Vec<(u32, u32, String)> = self
            .lexed
            .comments()
            .filter_map(|t| {
                let text = t.text(self.src);
                let body = text
                    .trim_start_matches("//")
                    .trim_start_matches("/*")
                    .trim_end_matches("*/");
                looks_like_code(body).then(|| (t.pos.line, t.pos.column, first_line(body)))
            })
            .collect();
        for (line, col, snippet) in candidates {
            self.emit(
                "D4.4",
                line,
                col,
                format!("this comment appears to be commented-out code, not documentation: `{snippet}`. Deleted code belongs in version control, not in a comment."),
            );
        }
    }

    // --- literals ---------------------------------------------------------

    fn check_literals(&mut self) {
        let numbers: Vec<(usize, String)> = self
            .code
            .iter()
            .enumerate()
            .filter(|(_, t)| t.kind == CTokenKind::Number)
            .map(|(i, t)| (i, t.text(self.src).to_string()))
            .collect();

        for (i, text) in numbers {
            let (line, col) = self.pos_of(i);
            if sda_syntax::clex::is_octal_constant(&text) {
                self.emit(
                    "7.1",
                    line,
                    col,
                    format!("`{text}` is an octal constant: the leading zero changes its value, which is a classic source of misread permission and register masks"),
                );
            }
            if sda_syntax::clex::has_lowercase_l_suffix(&text) {
                self.emit(
                    "7.3",
                    line,
                    col,
                    format!("`{text}` uses a lowercase `l` suffix, which reads as a digit 1 in most fonts"),
                );
            }
        }

        let strings: Vec<(usize, String)> = self
            .code
            .iter()
            .enumerate()
            .filter(|(_, t)| matches!(t.kind, CTokenKind::String | CTokenKind::Char))
            .map(|(i, t)| (i, t.text(self.src).to_string()))
            .collect();
        for (i, text) in strings {
            if let Some(detail) = unterminated_escape(&text) {
                let (line, col) = self.pos_of(i);
                self.emit("4.1", line, col, detail);
            }
        }
    }

    // --- identifiers ------------------------------------------------------

    fn check_identifiers(&mut self) {
        // 5.4 / 5.5: macro names must be distinct from each other and from
        // ordinary identifiers, within the significant-character limit.
        let macros: Vec<(String, u32, u32)> =
            self.st.macros.iter().map(|(n, p)| (n.clone(), p.line, p.column)).collect();

        // 5.4 is about names that *differ* yet collide within the significant
        // length. Two definitions of the same name are a different matter
        // entirely — and in a header they are usually the two arms of an
        // `#if`/`#else`, which is the standard idiom for compiling a facility
        // out. Reporting those made the rule fire on every guarded header.
        let mut seen: BTreeMap<String, (String, u32)> = BTreeMap::new();
        let mut collisions = Vec::new();
        for (name, line, col) in &macros {
            let key = significant_macro(name);
            match seen.get(&key) {
                Some((previous, prev_line)) if previous != name => {
                    collisions.push((
                        name.clone(),
                        previous.clone(),
                        *prev_line,
                        *line,
                        *col,
                    ));
                }
                Some(_) => {} // same name: a redefinition or a conditional arm
                None => {
                    seen.insert(key, (name.clone(), *line));
                }
            }
        }
        for (name, previous, prev_line, line, col) in collisions {
            self.emit(
                "5.4",
                line,
                col,
                format!(
                    "macro `{name}` is not distinct from `{previous}` (line {prev_line}) within \
                     the first 63 significant characters, which is all a conforming preprocessor \
                     must consider"
                ),
            );
        }

        let macro_names: BTreeSet<String> = macros.iter().map(|(n, _, _)| n.clone()).collect();
        let mut reported: BTreeSet<String> = BTreeSet::new();
        let idents: Vec<(usize, String)> = self
            .code
            .iter()
            .enumerate()
            .filter(|(_, t)| t.kind == CTokenKind::Identifier)
            .map(|(i, t)| (i, t.text(self.src).to_string()))
            .collect();

        // D4.5: typographically ambiguous identifier pairs.
        let mut by_key: BTreeMap<String, (String, u32)> = BTreeMap::new();
        for (i, name) in &idents {
            if name.len() < 3 {
                continue;
            }
            let key = ambiguity_key(name);
            let (line, col) = self.pos_of(*i);
            match by_key.get(&key) {
                Some((other, other_line)) if other != name && !reported.contains(name) => {
                    let (other, other_line) = (other.clone(), *other_line);
                    reported.insert(name.clone());
                    self.emit(
                        "D4.5",
                        line,
                        col,
                        format!("`{name}` is typographically ambiguous with `{other}` (line {other_line}); the two differ only in characters that look alike"),
                    );
                }
                None => {
                    by_key.insert(key, (name.clone(), line));
                }
                _ => {}
            }
        }

        // 5.5: an ordinary identifier colliding with a macro name.
        let mut warned: BTreeSet<String> = BTreeSet::new();
        for (i, name) in &idents {
            if macro_names.contains(name) || warned.contains(name) {
                continue;
            }
            let key = significant_macro(name);
            if macro_names.iter().any(|m| significant_macro(m) == key && m != name) {
                warned.insert(name.clone());
                let (line, col) = self.pos_of(*i);
                self.emit(
                    "5.5",
                    line,
                    col,
                    format!("identifier `{name}` is not distinct from a macro name within the first 63 significant characters"),
                );
            }
        }
    }

    // --- preprocessor -----------------------------------------------------

    fn check_directives(&mut self) {
        use sda_syntax::DirectiveKind as D;

        let directives: Vec<(D, u32, u32, Option<String>, String, bool)> = self
            .st
            .directives
            .iter()
            .map(|d| (d.kind, d.pos.line, d.pos.column, d.name.clone(), d.body.clone(), d.function_like))
            .collect();

        for (kind, line, col, name, body, function_like) in directives {
            match kind {
                D::Undef => {
                    self.emit("20.5", line, col, "`#undef` makes a macro's meaning depend on position in the file, which defeats a reader tracing where a name came from");
                    if name.as_deref().is_some_and(is_reserved_identifier) {
                        self.emit_with("21.1", line, col, format!("`#undef` of the reserved identifier `{}`", name.clone().unwrap_or_default()), Severity::High);
                    }
                }
                D::Define => {
                    let n = name.clone().unwrap_or_default();
                    if is_reserved_identifier(&n) {
                        self.emit_with("21.1", line, col, format!("`#define` of the reserved identifier `{n}`; the implementation may already define it"), Severity::High);
                    }
                    if is_keyword(&n, self.lexed.dialect) {
                        self.emit_with("20.4", line, col, format!("macro `{n}` has the same name as a keyword, so the language itself changes meaning wherever this header is included"), Severity::High);
                    }
                    let operators = macro_operators(&body);
                    if function_like {
                        // D4.9 asks for a function "where they are
                        // interchangeable". A replacement list using `#` or `##`
                        // is not: neither operator can be written inside a
                        // function at all, so there is no function to prefer.
                        // Firing anyway made every stringising or pasting macro
                        // a finding — assert wrappers, logging macros, register
                        // definitions — and told the author to replace them with
                        // something the language cannot express.
                        //
                        // The construct is still reported, by 20.10, which is
                        // the guideline that actually covers `#` and `##`. Both
                        // read the same `operators`, so they cannot disagree about
                        // what a stringising macro is.
                        //
                        // The same goes for a parameter naming the type of a
                        // compound literal: a function cannot take a type.
                        if !operators.contains('#') && !parameter_is_a_type(&body) {
                            self.emit("D4.9", line, col, format!("function-like macro `{n}` — a function or, in C++, a template gives the same result with type checking and a debuggable call frame"));
                        }
                        if let Some(param) = unparenthesized_parameter(&body) {
                            self.emit("20.7", line, col, format!("parameter `{param}` of macro `{n}` is used without enclosing parentheses, so an argument that is an expression will bind wrongly at the call site"));
                        }
                    }
                    if operators.contains("##") {
                        self.emit("20.10", line, col, format!("macro `{n}` uses the `##` token-pasting operator; the result is unreadable and its evaluation order is a common defect source"));
                        if pastes_adjacent_to_stringize(&operators) {
                            self.emit("20.11", line, col, format!("macro `{n}` applies `#` and `##` to adjacent parameters, whose evaluation order is unspecified"));
                        }
                    } else if operators.contains('#') {
                        self.emit("20.10", line, col, format!("macro `{n}` uses the `#` stringizing operator"));
                    }
                }
                D::Unknown => {
                    self.emit_with("20.13", line, col, "a line beginning with `#` that is not a valid preprocessing directive", Severity::High);
                }
                _ => {}
            }
        }

        // 20.14: conditional directives must balance within the file.
        let unbalanced: Vec<(u32, u32)> =
            self.st.unbalanced_conditionals.iter().map(|p| (p.line, p.column)).collect();
        for (line, col) in unbalanced {
            self.emit_with("20.14", line, col, "conditional compilation directive has no matching partner in this file", Severity::High);
        }
        // A second `#else`, or an `#elif` after one, at the same level.
        let after_else: Vec<(u32, u32)> =
            self.st.after_else.iter().map(|p| (p.line, p.column)).collect();
        for (line, col) in after_else {
            self.emit_with("20.14", line, col, "conditional compilation directive follows the `#else` of its own level; a conditional takes one `#else`, last", Severity::High);
        }

        // D4.10: a header must not be includable twice.
        if self.is_header() && !self.has_include_guard() {
            self.emit(
                "D4.10",
                1,
                1,
                "this header has neither an include guard nor `#pragma once`; including it twice will redefine its contents",
            );
        }
    }

    /// Inclusive line ranges of `#if 0` groups, which the preprocessor never
    /// compiles.
    ///
    /// Only the literal `0` is decided here. `#if FOO` stays code: whether it is
    /// live depends on a macro this pass does not evaluate, and guessing would
    /// hide real code. A group ends at the first `#elif`, `#else` or `#endif` at
    /// its own level, since the branch after that is live or undecided.
    fn literal_false_lines(&self) -> Vec<(u32, u32)> {
        use sda_syntax::DirectiveKind as D;
        let ds = &self.st.directives;
        let mut out = Vec::new();
        for (i, d) in ds.iter().enumerate() {
            if d.kind != D::If || directive_condition(&d.body) != "0" {
                continue;
            }
            let end = ds[i + 1..]
                .iter()
                .find(|e| {
                    e.depth == d.depth && (e.kind.continues_conditional() || e.kind.closes_conditional())
                })
                .map_or(u32::MAX, |e| e.pos.line);
            out.push((d.pos.line, end));
        }
        out
    }

    fn has_include_guard(&self) -> bool {
        use sda_syntax::DirectiveKind as D;
        if self.st.directives.iter().any(|d| d.kind == D::Pragma && d.body.contains("once")) {
            return true;
        }
        // The classic form: `#ifndef X` followed by `#define X`, and the
        // equivalent `#if !defined(X)` / `#if !defined X` followed by `#define X`.
        let mut it = self.st.directives.iter();
        while let Some(d) = it.next() {
            let guard = match d.kind {
                D::Ifndef => d.body.split_whitespace().next(),
                D::If => negated_defined_name(&d.body),
                _ => None,
            };
            if let Some(guard) = guard
                && let Some(next) = it.next()
                && next.kind == D::Define
                && next.name.as_deref() == Some(guard)
            {
                return true;
            }
        }
        false
    }

    fn check_includes(&mut self) {
        let includes: Vec<(String, u32, u32, bool)> = self
            .st
            .includes()
            .map(|d| {
                (
                    d.name.clone().unwrap_or_default(),
                    d.pos.line,
                    d.pos.column,
                    d.is_system_include(),
                )
            })
            .collect();

        for (raw, line, col, _system) in &includes {
            // 20.3: the operand must be a bracketed or quoted header name.
            if !(raw.starts_with('<') && raw.ends_with('>'))
                && !(raw.starts_with('"') && raw.ends_with('"'))
            {
                self.emit_with(
                    "20.3",
                    *line,
                    *col,
                    format!("`#include {raw}` does not name a header directly; a macro-expanded include hides the dependency from every reader and every build system"),
                    Severity::Medium,
                );
                continue;
            }
            let target = raw.trim_matches(|c| c == '<' || c == '>' || c == '"');

            // 20.2: characters whose meaning inside a header name is undefined.
            if target.contains('\'') || target.contains('\\') || target.contains("/*") || target.contains("//") {
                self.emit_with(
                    "20.2",
                    *line,
                    *col,
                    format!("header name `{target}` contains a character whose behaviour in an include is undefined — note that `\\` is undefined even on Windows, where `/` works"),
                    Severity::Medium,
                );
            }

            if let Some((_, rule)) = BANNED_HEADERS.iter().find(|(h, _)| *h == target) {
                let rule = *rule;
                self.emit(
                    rule,
                    *line,
                    *col,
                    format!("`{target}` is not permitted in this profile; on a freestanding or safety-critical target its facilities pull in unbounded code, allocation, or I/O"),
                );
            }
        }

        // 20.1: includes must come first. Code the preprocessor never compiles
        // (an `#if 0` group) is not code for this purpose, so it neither counts
        // as the code an include must precede nor holds an include to account.
        let dead = self.literal_false_lines();
        let live = |line: u32| !dead.iter().any(|(a, b)| (*a..=*b).contains(&line));
        if let Some(first_code) = self.code.iter().find(|t| live(t.pos.line)) {
            let offenders: Vec<(u32, u32)> = self
                .st
                .includes()
                .filter(|d| live(d.pos.line) && d.pos.line > first_code.pos.line)
                .map(|d| (d.pos.line, d.pos.column))
                .collect();
            for (line, col) in offenders {
                self.emit(
                    "20.1",
                    line,
                    col,
                    "this `#include` appears after code; where a header lands in a file changes what it sees, so includes belong at the top",
                );
            }
        }
    }

    // --- declarations -----------------------------------------------------

    fn check_declarations(&mut self) {
        let n = self.code.len();
        let mut hits: Vec<(&'static str, u32, u32, String)> = Vec::new();

        for i in 0..n {
            let t = self.tok(i);
            let (line, col) = self.pos_of(i);

            match t {
                // 8.14
                // `__restrict` and `__restrict__` are GCC's and Clang's spellings.
                "restrict" | "__restrict" | "__restrict__" => hits.push((
                    "8.14",
                    line,
                    col,
                    "`restrict` asserts non-aliasing that the compiler cannot verify; if the assertion is ever false the resulting miscompilation is silent".into(),
                )),
                // 19.2 / union prohibition
                "union" => hits.push((
                    "19.2",
                    line,
                    col,
                    "a union reads one member as another's bit pattern, which is implementation-defined and defeats type-based reasoning".into(),
                )),
                // 17.1
                // The `__builtin_` spellings are what the variadic macros of
                // <stdarg.h> expand to on GCC and Clang.
                "va_list" | "va_start" | "va_arg" | "va_end" | "va_copy"
                | "__builtin_va_list" | "__builtin_va_start" | "__builtin_va_arg"
                | "__builtin_va_end" | "__builtin_va_copy" => hits.push((
                    "17.1",
                    line,
                    col,
                    format!("`{t}` gives a call whose argument types no compiler can check"),
                )),
                // 8.10: an inline function must be static.
                "inline" => {
                    if !self.has_linkage_specifier(i) {
                        hits.push((
                            "8.10",
                            line,
                            col,
                            "an `inline` function without `static` has an external definition the standard does not require any translation unit to provide".into(),
                        ));
                    }
                }
                // 17.10: _Noreturn must have void return type.
                "_Noreturn" | "noreturn" => {
                    // Only a return type that is decidably not `void` is a
                    // finding. A typedef name might name `void`, so it is left
                    // alone rather than guessed at.
                    if self.noreturn_returns_non_void(i) {
                        hits.push((
                            "17.10",
                            line,
                            col,
                            "a function that never returns cannot deliver a return value; declare it `void`".into(),
                        ));
                    }
                }
                // 8.16 / 8.17: alignment specifiers.
                "alignas" | "_Alignas" => {
                    // Only a bare integer literal is read. `alignas(0 + 16)` is
                    // not judged: its value is not in the tokens.
                    if i + 3 < n
                        && self.tok(i + 1) == "("
                        && self.code[i + 2].kind == CTokenKind::Number
                        && self.tok(i + 3) == ")"
                        && integer_literal_value(self.tok(i + 2)) == Some(0)
                    {
                        hits.push(("8.16", line, col, "an alignment specification of zero has no effect and is almost certainly a mistake".into()));
                    }
                    // Stops at the end of the declaration: the next one along
                    // may carry its own specifier, and that is not a second. A
                    // struct body is stepped over rather than a stop, because
                    // its members are declarations and what follows it is not.
                    let mut depth = 0usize;
                    let mut second = false;
                    for k in i + 1..n.min(i + 40) {
                        match self.tok(k) {
                            "{" => depth += 1,
                            "}" if depth == 0 => break,
                            "}" => depth -= 1,
                            ";" if depth == 0 => break,
                            "alignas" | "_Alignas" if depth == 0 => {
                                second = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    if second {
                        hits.push(("8.17", line, col, "more than one alignment specifier in one declaration; which one applies is not obvious to a reader".into()));
                    }
                }
                "*" => {
                    // 18.5: pointer nesting depth. Counted from the first `*` of
                    // the chain, so `*const *const *p` is three levels and is
                    // reported once rather than once per star.
                    if self.starts_pointer_chain(i) && self.pointer_levels_from(i) >= 3 {
                        hits.push((
                            "18.5",
                            line,
                            col,
                            "three or more levels of pointer indirection; each level is a separate lifetime and nullability question".into(),
                        ));
                    }
                    // 11.9, in the shape that had been missed: a pointer
                    // *declarator* initialised with a bare `0`. `int *head = 0;`
                    // is a null pointer constant written as an integer, which is
                    // what the guideline exists to stop; the `(void *)0` form
                    // handled above is the rarer one. Found by cppcheck's addon
                    // on a corpus file this engine read clean.
                    //
                    // The token before the `*` decides whether this is a
                    // declaration at all. `*revision = 0;` is a dereference
                    // storing an integer through a pointer — ordinary C, and
                    // what the first attempt at this check reported 28 times on
                    // PX4 before the guard existed. A declarator has a type
                    // ahead of it; a statement has a `;`, a `}` or a `)`.
                    let declared = i > 0
                        && (self.code[i - 1].kind == CTokenKind::Identifier
                            || DECLARATION_HEADS.contains(&self.tok(i - 1))
                            || self.tok(i - 1) == ",");
                    if declared
                        && i + 4 < n
                        && self.code[i + 1].kind == CTokenKind::Identifier
                        && self.tok(i + 2) == "="
                        && self.tok(i + 3) == "0"
                        && matches!(self.tok(i + 4), ";" | ",")
                    {
                        hits.push((
                            "11.9",
                            line,
                            col,
                            format!(
                                "pointer `{}` is initialised with the integer `0`; `NULL` is the only permitted spelling of a null pointer constant",
                                self.tok(i + 1)
                            ),
                        ));
                    }
                }
                // 17.6: `static` inside an array parameter's brackets.
                "[" => {
                    // Type qualifiers may precede `static`: `[const static 10]`.
                    let mut k = i + 1;
                    while k < n && is_type_qualifier(self.tok(k)) {
                        k += 1;
                    }
                    if k < n && self.tok(k) == "static" {
                        hits.push((
                            "17.6",
                            line,
                            col,
                            "`static` in an array parameter promises the caller always passes at least that many elements — a promise nothing checks".into(),
                        ));
                    }
                }
                // 7.6: the small-width minimum-width constant macros promote in
                // ways that surprise, so the profile bans them outright.
                "INT8_C" | "INT16_C" | "UINT8_C" | "UINT16_C" => hits.push((
                    "7.6",
                    line,
                    col,
                    format!("`{t}` yields a value that has already been promoted to `int`, so the width the name promises is not the width you get"),
                )),
                // 11.10: `_Atomic` may not be applied to `void`.
                "_Atomic" => {
                    // `_Atomic(void)` exactly. `_Atomic(void *)` qualifies a
                    // pointer, which is complete, so the closing paren must
                    // follow the `void` directly.
                    if i + 3 < n
                        && self.tok(i + 1) == "("
                        && self.tok(i + 2) == "void"
                        && self.tok(i + 3) == ")"
                    {
                        hits.push((
                            "11.10",
                            line,
                            col,
                            "`_Atomic(void)` qualifies an incomplete type, which has no defined meaning".into(),
                        ));
                    }
                }
                // 11.9: the only permitted null pointer constant is NULL.
                "(" => {
                    if i + 4 < n
                        && self.tok(i + 1) == "void"
                        && self.tok(i + 2) == "*"
                        && self.tok(i + 3) == ")"
                        && self.tok(i + 4) == "0"
                    {
                        hits.push((
                            "11.9",
                            line,
                            col,
                            "`(void *)0` used as a null pointer constant; `NULL` is the only permitted spelling".into(),
                        ));
                    }
                }
                // D4.6: width-explicit typedefs are preferred.
                _ if BASIC_NUMERIC_TYPES.contains(&t) => {
                    // `int main(...)` is required to be spelled that way.
                    let is_main = i + 1 < n && self.tok(i + 1) == "main";
                    if !is_main && !self.defines_a_sized_name(i) {
                        hits.push((
                            "D4.6",
                            line,
                            col,
                            format!("`{t}` has an implementation-defined width; a width-explicit typedef such as `int32_t` says what the code actually depends on"),
                        ));
                    }
                }
                _ => {}
            }
        }

        // 8.2: prototype form, with named parameters.
        //
        // `st.functions` holds *definitions* only, so until this scan existed
        // the rule never saw a declaration — and a prototype in a header is
        // where 8.2 matters most. cppcheck's addon reported
        // `extern int older(int, int);` on a corpus file this engine read clean.
        for f in &self.st.functions {
            // `struct s { ... } __attribute__((packed));` parses as a definition
            // named `__attribute__`. Names the implementation owns are not
            // functions this rule has anything to say about.
            if f.name.starts_with("__") {
                continue;
            }
            if let Some(why) = prototype_fault(&f.params, self.reads_lone_words(&f.name, f.pos)) {
                hits.push((
                    "8.2",
                    f.pos.line,
                    f.pos.column,
                    format!("`{}` {why}", f.name),
                ));
            }
        }
        for (name, pos, params) in self.file_scope_declarations() {
            if let Some(why) = prototype_fault(&params, self.reads_lone_words(&name, pos)) {
                hits.push(("8.2", pos.line, pos.column, format!("`{name}` {why}")));
            }
        }
        // Prototypes inside a function body are declarations too. A struct body
        // also sits at nonzero depth, but a member's declarator is not a prototype.
        for (name, pos, params) in self.block_scope_declarations() {
            if self.function_scope_of(pos.line, pos.column).is_none() {
                continue;
            }
            if let Some(why) = prototype_fault(&params, self.reads_lone_words(&name, pos)) {
                hits.push(("8.2", pos.line, pos.column, format!("`{name}` {why}")));
            }
        }
        for (name, pos) in self.kr_definitions() {
            hits.push((
                "8.2",
                pos.line,
                pos.column,
                format!("`{name}` is defined with an old-style identifier list and separate parameter declarations; give each parameter its type in prototype form"),
            ));
        }

        // 6.3 / 6.2: bit-fields.
        hits.extend(self.bitfield_findings());

        // 8.11: an extern array must state its size.
        for i in 0..n {
            if self.tok(i) == "extern" && self.declares_unsized_array(i) {
                        let (line, col) = self.pos_of(i);
                        hits.push((
                            "8.11",
                            line,
                            col,
                            "an array declared `extern` without a size gives every translation unit a different idea of its bounds".into(),
                        ));
                    }
        }

        for (rule, line, col, msg) in hits {
            self.emit(rule, line, col, msg);
        }
    }

    /// Whether the declarator `name` at `pos` looks enough like a typed function
    /// for a lone word among its parameters to be read as a typedef name.
    ///
    /// Without expanding macros the shape is all there is. `CU_Test(suite, name) {`
    /// and `static DEFINE_mutex(lock);` have no return type before the name, only
    /// storage classes at most. `char buf[4] aligned_data(x);` has a declarator
    /// already. `int a ALIGNED(x);` is spelled like a macro. All are invocations.
    fn reads_lone_words(&self, name: &str, pos: sda_syntax::Pos) -> bool {
        if looks_like_macro(name) {
            return false;
        }
        let at = self.code.partition_point(|t| (t.pos.line, t.pos.column) < (pos.line, pos.column));
        let mut k = at;
        while k > 0 {
            k -= 1;
            match self.tok(k) {
                "static" | "extern" | "inline" | "__inline" | "__inline__" | "_Noreturn" => {}
                ";" | "{" | "}" | "]" => return false,
                _ => return true,
            }
        }
        false
    }

    /// Whether the declaration after the `extern` at `at` has an empty `[]` on one
    /// of its own declarators.
    ///
    /// Read to the end of the declaration, however long its specifiers. Brackets
    /// inside parentheses belong to a parameter or an attribute, and `(*p)[]` is
    /// a pointer, so neither counts. Nothing after the `;` is this declaration's.
    fn declares_unsized_array(&self, at: usize) -> bool {
        let n = self.code.len();
        let mut depth = 0i32;
        for k in at + 1..n {
            match self.tok(k) {
                "(" => depth += 1,
                ")" => depth -= 1,
                ";" | "{" | "=" if depth == 0 => return false,
                "[" if depth == 0
                    && k + 1 < n
                    && self.tok(k + 1) == "]"
                    && self.tok(k - 1) != ")" =>
                {
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// Whether the basic type at `at` is part of a `typedef` whose new name states
    /// a width, such as `typedef unsigned int u32_t;`. That is how a width-explicit
    /// name comes to exist, so there is nothing else for it to use.
    ///
    /// Read from the name alone, a digit being the only sign this pass has.
    fn defines_a_sized_name(&self, at: usize) -> bool {
        let boundary = |t: &str| matches!(t, ";" | "{" | "}");
        let start = (0..at).rev().find(|k| boundary(self.tok(*k))).map_or(0, |k| k + 1);
        if !(start..at).any(|k| self.tok(k) == "typedef") {
            return false;
        }
        let Some(end) = (at..self.code.len()).find(|k| boundary(self.tok(*k))) else {
            return false;
        };
        end > at
            && self.tok(end) == ";"
            && self.code[end - 1].kind == CTokenKind::Identifier
            && self.tok(end - 1).bytes().any(|b| b.is_ascii_digit())
    }

    /// Whether the declaration that `inline` at `at` belongs to says `static` or
    /// `extern` among its specifiers, in any order.
    ///
    /// Read back to the start of the declaration, so an attribute between the
    /// two (`static __attribute__((unused)) inline`) is no obstacle; forward a
    /// few tokens for `inline static`.
    fn has_linkage_specifier(&self, at: usize) -> bool {
        let mut k = at;
        while k > 0 {
            k -= 1;
            match self.tok(k) {
                ";" | "{" | "}" => break,
                "static" | "extern" => return true,
                _ => {}
            }
        }
        (at + 1..(at + 6).min(self.code.len()))
            .take_while(|k| !matches!(self.tok(*k), ";" | "{" | "}" | "(" | "="))
            .any(|k| matches!(self.tok(k), "static" | "extern"))
    }

    /// Whether the function declared with `_Noreturn` at `at` has a return type
    /// that is decidably something other than `void`.
    ///
    /// The specifiers and attributes before the return type are skipped, and the
    /// declarator's name is the last word before its parameter list. A return
    /// type that is one bare identifier is a typedef name, which may name
    /// `void`; that is not decided here, so it is not a finding.
    fn noreturn_returns_non_void(&self, at: usize) -> bool {
        const SPECIFIERS: &[&str] = &[
            "static", "extern", "inline", "_Noreturn", "noreturn", "__inline", "__inline__",
            "__forceinline", "_Thread_local", "__extension__",
        ];
        let n = self.code.len();
        let mut words: Vec<usize> = Vec::new();
        let mut k = at + 1;
        // `noreturn` may be the word inside `__attribute__((noreturn, cold))`,
        // `__declspec(noreturn)` or `[[noreturn]]`; what it qualifies starts after
        // the closing brackets. A trailing attribute then meets `;` or `{` with no
        // words read, which decides nothing.
        if at > 0 && matches!(self.tok(at - 1), "(" | "," | "[") {
            let mut depth = 0i32;
            while k < n {
                match self.tok(k) {
                    "(" | "[" => depth += 1,
                    ")" | "]" => depth -= 1,
                    _ if depth < 0 => break,
                    _ => {}
                }
                k += 1;
            }
        }
        let mut stop = None;
        while k < n {
            let t = self.tok(k);
            if SPECIFIERS.contains(&t) {
                k += 1;
                continue;
            }
            if matches!(t, "__attribute__" | "__attribute" | "__declspec" | "alignas" | "_Alignas")
                && k + 1 < n
                && self.tok(k + 1) == "("
            {
                match cstruct::matching(self.src, &self.code, k + 1, "(", ")") {
                    Some(close) => k = close + 1,
                    None => break,
                }
                continue;
            }
            if t == "[" && k + 1 < n && self.tok(k + 1) == "[" {
                match cstruct::matching(self.src, &self.code, k, "[", "]") {
                    Some(close) => k = close + 1,
                    None => break,
                }
                continue;
            }
            if matches!(t, ";" | "{" | "}" | "(" | "=" | ",") {
                stop = Some(t);
                break;
            }
            words.push(k);
            k += 1;
        }
        // No parameter list ahead means this is not a function being declared:
        // `noreturn` is an ordinary identifier to code without <stdnoreturn.h>.
        if stop != Some("(") {
            return false;
        }
        let Some(&last) = words.last() else { return false };
        let named = self.code[last].kind == CTokenKind::Identifier;
        let ret: Vec<&str> = words[..words.len() - usize::from(named)]
            .iter()
            .map(|&w| self.tok(w))
            .filter(|w| !matches!(*w, "const" | "volatile"))
            .collect();
        match ret.as_slice() {
            [] | ["void"] => false,
            [single] => BASIC_RETURN_WORDS.contains(single) || *single == "*",
            _ => true,
        }
    }

    /// Function declarations inside a function body: `;`-terminated runs at a
    /// nonzero brace depth that begin with a declaration specifier.
    ///
    /// A run that begins with anything else is a statement, so `g(a, b);` is a
    /// call and not a prototype, while `int older(int, int);` is a declaration.
    fn block_scope_declarations(&self) -> Vec<(String, sda_syntax::Pos, String)> {
        let mut out = Vec::new();
        let mut depth = 0i32;
        let mut start = 0usize;
        let n = self.code.len();
        for i in 0..n {
            match self.tok(i) {
                "{" => {
                    depth += 1;
                    start = i + 1;
                }
                "}" => {
                    depth -= 1;
                    start = i + 1;
                }
                ";" => {
                    if depth > 0 && i > start && DECLARATION_HEADS.contains(&self.tok(start)) {
                        self.read_prototype(start, i, &mut out);
                    }
                    start = i + 1;
                }
                _ => {}
            }
        }
        out
    }

    /// Old-style (K&R) function definitions: `name ( identifier-list )
    /// declaration... {` at file scope.
    ///
    /// Reported only when every part of that shape is present: a return type
    /// before the name, bare identifiers in the parentheses, a declaration
    /// after `)` that opens with a type keyword, a `{` that follows those
    /// declarations, and a declaration in that run for every listed name. A
    /// macro invocation such as `FOO(a) int a; {` has none of this shape in
    /// practice, and `name(a) {` with no declarations is not decided here.
    fn kr_definitions(&self) -> Vec<(String, sda_syntax::Pos)> {
        const DECLARATION_OPENERS: &[&str] = &[
            "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned",
            "_Bool", "struct", "union", "enum", "const", "volatile", "register",
        ];
        let n = self.code.len();
        let mut out = Vec::new();
        let mut depth = 0i32;
        for i in 0..n {
            match self.tok(i) {
                "{" => depth += 1,
                "}" => depth -= 1,
                _ => {}
            }
            if depth != 0 || i == 0 || self.code[i].kind != CTokenKind::Identifier {
                continue;
            }
            if i + 2 >= n || self.tok(i + 1) != "(" {
                continue;
            }
            let prev = self.code[i - 1];
            if !(matches!(prev.kind, CTokenKind::Identifier | CTokenKind::Keyword)
                || prev.is(self.src, "*"))
            {
                continue;
            }
            let Some(close) = cstruct::matching(self.src, &self.code, i + 1, "(", ")") else {
                continue;
            };
            // The identifier list: names separated by single commas, at least one.
            let inner: Vec<usize> = (i + 2..close).collect();
            if inner.is_empty() || inner.len().is_multiple_of(2) {
                continue;
            }
            let mut names: Vec<&str> = Vec::new();
            let mut well_formed = true;
            for (pos, &k) in inner.iter().enumerate() {
                if pos % 2 == 0 {
                    if self.code[k].kind != CTokenKind::Identifier {
                        well_formed = false;
                        break;
                    }
                    names.push(self.tok(k));
                } else if self.tok(k) != "," {
                    well_formed = false;
                    break;
                }
            }
            if !well_formed || close + 1 >= n || !DECLARATION_OPENERS.contains(&self.tok(close + 1)) {
                continue;
            }
            // Declarations run to a `{` at the parameter list's level; a `}` first
            // means there was no body.
            let mut body = None;
            let mut nest = 0i32;
            for k in close + 1..n {
                match self.tok(k) {
                    "(" | "[" => nest += 1,
                    ")" | "]" => nest -= 1,
                    "{" if nest == 0 => {
                        body = Some(k);
                        break;
                    }
                    "}" => break,
                    _ => {}
                }
            }
            let Some(body) = body else { continue };
            if body == 0 || self.tok(body - 1) != ";" {
                continue;
            }
            let declared = |name: &str| {
                (close + 1..body)
                    .any(|m| self.code[m].kind == CTokenKind::Identifier && self.tok(m) == name)
            };
            if names.iter().all(|nm| declared(nm)) {
                out.push((self.tok(i).to_string(), self.code[i].pos));
            }
        }
        out
    }

    /// Whether the `{` at `open` closes on `};`, which makes the struct anonymous.
    fn closes_with_no_declarator(&self, open: usize) -> bool {
        let mut depth = 0i32;
        for k in open..self.code.len() {
            match self.tok(k) {
                "{" => depth += 1,
                "}" => {
                    depth -= 1;
                    if depth == 0 {
                        return k + 1 < self.code.len() && self.tok(k + 1) == ";";
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Bit-field checks: a single-bit signed field cannot hold the value 1, and
    /// a bit-field in a union has no defined layout at all.
    ///
    /// A bit-field is a `:` directly inside a struct or union body, after a member
    /// name (or a type, for an unnamed one), and ended by `;` or `,`. Anything
    /// else with a colon, a ternary, a label, a `case`, a designator, is not one.
    /// The width is any constant expression, so `WIDTH` and `(2)` count; only a
    /// width of exactly `1` is read for the signed rule.
    ///
    /// "In a union" means a member of it. A bit-field in a named struct inside a
    /// union belongs to that struct, while one in an anonymous struct counts as
    /// a member of the union, which is what C says of anonymous members.
    fn bitfield_findings(&self) -> Vec<(&'static str, u32, u32, String)> {
        let mut out = Vec::new();
        let n = self.code.len();
        // What each open `{` opened, and whether its members are union members.
        let mut bodies: Vec<(BodyKind, bool)> = Vec::new();

        for i in 0..n {
            let t = self.tok(i);
            match t {
                "{" => {
                    let (kind, anonymous) = self.body_kind_before(i);
                    // Members of a union, or of an anonymous struct that is itself one.
                    let inside_union = bodies.last().is_some_and(|(_, member)| *member);
                    let member = match kind {
                        BodyKind::Union => true,
                        BodyKind::Struct => {
                            anonymous && inside_union && self.closes_with_no_declarator(i)
                        }
                        BodyKind::Other => false,
                    };
                    bodies.push((kind, member));
                }
                "}" => {
                    bodies.pop();
                }
                ":" => {
                    let Some(&(kind, member)) = bodies.last() else { continue };
                    if kind == BodyKind::Other || i == 0 {
                        continue;
                    }
                    // The name of a member, or the type of an unnamed bit-field.
                    let before = self.code[i - 1];
                    let names_a_member = before.kind == CTokenKind::Identifier
                        || matches!(
                            before.text(self.src),
                            "int" | "unsigned" | "signed" | "_Bool" | "bool" | "char" | "short" | "long"
                        );
                    if !names_a_member {
                        continue;
                    }
                    // The width runs to the `;` or `,` that ends the member.
                    let mut end = None;
                    let mut nest = 0i32;
                    for k in i + 1..n {
                        match self.tok(k) {
                            "(" | "[" => nest += 1,
                            ")" | "]" => {
                                nest -= 1;
                                if nest < 0 {
                                    break;
                                }
                            }
                            ";" | "," if nest == 0 => {
                                end = Some(k);
                                break;
                            }
                            "{" | "}" | "?" | ":" => break,
                            _ => {}
                        }
                    }
                    let Some(end) = end else { continue };
                    if end == i + 1 {
                        continue; // `name : ;` has no width
                    }
                    let (line, col) = self.pos_of(i);
                    if member {
                        out.push((
                            "6.3",
                            line,
                            col,
                            "a bit-field inside a union has no portable layout; where its bits land is entirely up to the implementation".to_string(),
                        ));
                    }
                    if end == i + 2 && self.tok(i + 1) == "1" {
                        // Walk back to the declaration's base type.
                        let start = (0..i).rev().find(|k| matches!(self.tok(*k), ";" | "{" | "}"));
                        let from = start.map(|s| s + 1).unwrap_or(0);
                        let signed = (from..i).any(|k| matches!(self.tok(k), "signed" | "int" | "short" | "long"))
                            && !(from..i).any(|k| self.tok(k) == "unsigned");
                        if signed {
                            out.push((
                                "6.2",
                                line,
                                col,
                                "a one-bit signed bit-field can only hold 0 and -1, never 1 — almost never what the author meant".to_string(),
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// What the `{` at `open` opens: a struct or union body, or anything else,
    /// and whether it is anonymous (`struct {`, `union {`).
    ///
    /// Read back from the brace to the start of its declaration. An attribute
    /// group between the keyword and the brace (`struct __attribute__((packed))
    /// S {`) is stepped over; any other parenthesis, `=`, or statement boundary
    /// ends the search, so a function body or an initializer is `Other`.
    fn body_kind_before(&self, open: usize) -> (BodyKind, bool) {
        let anonymous = open > 0 && matches!(self.tok(open - 1), "struct" | "union");
        let mut words: Vec<&str> = Vec::new();
        let mut k = open;
        while k > 0 {
            k -= 1;
            match self.tok(k) {
                ";" | "{" | "}" | "=" | "," | "(" => break,
                ")" => {
                    // Find the `(` this `)` closes, then the word before it.
                    let mut depth = 0i32;
                    let mut o = k;
                    loop {
                        match self.tok(o) {
                            ")" => depth += 1,
                            "(" => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                        if o == 0 {
                            return (BodyKind::Other, anonymous);
                        }
                        o -= 1;
                    }
                    if o > 0 && matches!(self.tok(o - 1), "__attribute__" | "__attribute" | "__declspec") {
                        k = o;
                    } else {
                        break;
                    }
                }
                w => words.push(w),
            }
        }
        let kind = words
            .iter()
            .find_map(|w| match *w {
                "struct" => Some(BodyKind::Struct),
                "union" => Some(BodyKind::Union),
                "enum" => Some(BodyKind::Other),
                _ => None,
            })
            .unwrap_or(BodyKind::Other);
        (kind, anonymous)
    }

    // --- control flow -----------------------------------------------------

    fn check_control_flow(&mut self) {
        let controls: Vec<(String, u32, u32, bool, bool, Option<sda_syntax::Span>)> = self
            .st
            .controls
            .iter()
            .map(|c| {
                (
                    c.kind.as_str().to_string(),
                    c.pos.line,
                    c.pos.column,
                    c.body_braced,
                    c.assignment_in_condition,
                    c.body,
                )
            })
            .collect();

        for (kind, line, col, braced, assignment, body) in &controls {
            if !*braced {
                self.emit(
                    "15.6",
                    *line,
                    *col,
                    format!("the body of this `{kind}` is not a compound statement; adding a second line later will silently leave it outside the {kind}"),
                );
            }
            if *assignment {
                self.emit(
                    "13.4",
                    *line,
                    *col,
                    format!("assignment used as the controlling expression of this `{kind}`; if `==` was meant, the code compiles and does the wrong thing"),
                );
            }
            // 15.4: more than one break or goto leaving a loop.
            if matches!(kind.as_str(), "for" | "while" | "do")
                && let Some(b) = body {
                    let exits = self.count_loop_exits(*b);
                    if exits > 1 {
                        self.emit(
                            "15.4",
                            *line,
                            *col,
                            format!("this loop has {exits} `break`/`goto` exits; a single exit point makes the loop's postcondition something a reader can state"),
                        );
                    }
                }
        }

        // 15.5: single point of exit.
        let fns: Vec<(String, u32, u32, usize)> = self
            .st
            .functions
            .iter()
            .map(|f| (f.name.clone(), f.pos.line, f.pos.column, f.exit_points))
            .collect();
        for (name, line, col, exits) in fns {
            if exits > 1 {
                self.emit(
                    "15.5",
                    line,
                    col,
                    format!("`{name}` has {exits} points of exit; with one exit, cleanup and postconditions have exactly one place to live"),
                );
            }
        }

        self.check_else_chains();
    }

    /// Count the statements that leave a loop: each `break` directly in its body,
    /// excluding those belonging to a nested loop or switch — a `break` inside
    /// a nested `switch` leaves the switch, not the loop — and each `goto` at any
    /// depth whose label is not in the body, since nesting cannot contain a jump.
    fn count_loop_exits(&self, body: sda_syntax::Span) -> usize {
        let Some(first) = self.code.iter().position(|t| t.span.start == body.start) else {
            return 0;
        };
        // Only a braced body has a span: an unbraced loop body is a 15.6
        // finding, so code that is clean of 15.6 has every body counted here.
        let Some(close) = cstruct::matching(self.src, &self.code, first, "{", "}") else {
            return 0;
        };
        let mut count = 0usize;
        let mut i = first + 1;
        while i < close {
            match self.tok(i) {
                // A nested loop or switch owns the breaks in its body, braced
                // or not, so step over the whole statement. Its extent comes
                // from the parser, not from counting braces.
                "for" | "while" | "do" | "switch" => {
                    i = cstruct::statement_end(self.src, &self.code, i, close).max(i + 1);
                }
                "break" => {
                    count += 1;
                    i += 1;
                }
                _ => i += 1,
            }
        }
        let labelled_here = |name: &str| {
            (first + 1..close).any(|m| {
                self.tok(m) == name
                    && m + 1 < close
                    && self.tok(m + 1) == ":"
                    && matches!(self.tok(m - 1), ";" | "{" | "}" | ":" | ")")
            })
        };
        count
            + (first + 1..close)
                .filter(|&k| {
                    self.tok(k) == "goto" && k + 1 < close && !labelled_here(self.tok(k + 1))
                })
                .count()
    }

    /// 15.7: an `if ... else if` chain must end in an `else`.
    fn check_else_chains(&mut self) {
        let n = self.code.len();
        let mut i = 0usize;
        let mut violations = Vec::new();

        while i < n {
            if self.tok(i) != "if" {
                i += 1;
                continue;
            }
            // Only start from a chain head: an `if` not preceded by `else`.
            if i > 0 && self.tok(i - 1) == "else" {
                i += 1;
                continue;
            }
            let start = i;
            let mut links = 1usize;
            let mut cursor = i;
            let mut terminal_else = false;

            while let Some(after_body) = self.skip_condition_and_body(cursor) {
                if after_body < n && self.tok(after_body) == "else" {
                    if after_body + 1 < n && self.tok(after_body + 1) == "if" {
                        links += 1;
                        cursor = after_body + 1;
                        continue;
                    }
                    terminal_else = true;
                }
                break;
            }

            if links >= 2 && !terminal_else {
                let (line, col) = self.pos_of(start);
                violations.push((line, col, links));
            }
            i = start + 1;
        }

        for (line, col, links) in violations {
            self.emit(
                "15.7",
                line,
                col,
                format!("this chain of {links} `if`/`else if` branches has no final `else`; nothing states what happens when every condition is false, so a future value silently falls through"),
            );
        }
    }

    /// Given the index of an `if`, return the index just past its body.
    fn skip_condition_and_body(&self, if_idx: usize) -> Option<usize> {
        let n = self.code.len();
        let open = if_idx + 1;
        if open >= n || self.tok(open) != "(" {
            return None;
        }
        let close = cstruct::matching(self.src, &self.code, open, "(", ")")?;
        let body = close + 1;
        if body >= n {
            return None;
        }
        if self.tok(body) == "{" {
            Some(cstruct::matching(self.src, &self.code, body, "{", "}")? + 1)
        } else {
            // An unbraced body runs to the next `;` at this bracket depth.
            let mut depth = 0i32;
            for k in body..n {
                match self.tok(k) {
                    "(" | "[" | "{" => depth += 1,
                    ")" | "]" | "}" => depth -= 1,
                    ";" if depth == 0 => return Some(k + 1),
                    _ => {}
                }
            }
            None
        }
    }

    // --- switches ---------------------------------------------------------


    fn check_switches(&mut self) {
        let switches: Vec<SwitchFacts> = self
            .st
            .switches
            .iter()
            .map(|s| {
                (
                    s.pos.line,
                    s.pos.column,
                    s.has_default,
                    s.clauses,
                    s.default_not_last,
                    s.fallthrough_clauses.iter().map(|p| (p.line, p.column)).collect(),
                    s.misplaced_labels.iter().map(|p| (p.line, p.column)).collect(),
                )
            })
            .collect();

        for (line, col, has_default, clauses, default_not_last, fallthrough, misplaced) in switches {
            if !has_default {
                self.emit(
                    "16.4",
                    line,
                    col,
                    "this `switch` has no `default` label; when the controlling value takes an unexpected state — and it will — the switch does nothing at all",
                );
            }
            if default_not_last {
                self.emit(
                    "16.5",
                    line,
                    col,
                    "the `default` label is neither first nor last; a reader scanning for the catch-all has to read every clause to find it",
                );
            }
            if clauses < 2 {
                self.emit(
                    "16.6",
                    line,
                    col,
                    format!("this `switch` has only {clauses} clause; an `if` states the same thing more directly"),
                );
            }
            for (fl, fc) in fallthrough {
                self.emit(
                    "16.3",
                    fl,
                    fc,
                    "this switch clause has statements but no unconditional `break`, so control falls into the next clause — the single most common switch defect",
                );
            }
            for (ml, mc) in misplaced {
                self.emit(
                    "16.2",
                    ml,
                    mc,
                    "this `case`/`default` label is nested inside a block rather than directly in the switch body, which makes it a jump into the middle of a construct",
                );
            }
        }
    }

    // --- jumps ------------------------------------------------------------

    /// The index of the function whose body contains `line:column`, if any.
    ///
    /// A label's name is only in scope in its own function (C23 6.8.1), so a
    /// `goto` and a label are matched only when they share one of these. Code
    /// outside every body this analyzer read maps to `None`, and `None` matches
    /// only `None`.
    fn function_scope_of(&self, line: u32, column: u32) -> Option<usize> {
        let at = (line, column);
        self.st.functions.iter().position(|f| {
            let start = self.lexed.lines.pos(f.body.start);
            let end = self.lexed.lines.pos(f.body.end);
            (start.line, start.column) <= at && at <= (end.line, end.column)
        })
    }

    fn check_jumps(&mut self) {
        // (name, line, column, enclosing function)
        let gotos: Vec<(String, u32, u32, Option<usize>)> = self
            .st
            .gotos
            .iter()
            .map(|(n, p)| (n.clone(), p.line, p.column, self.function_scope_of(p.line, p.column)))
            .collect();
        // (name, line, column, enclosing function)
        let labels: Vec<(String, u32, u32, Option<usize>)> = self
            .st
            .labels
            .iter()
            .map(|(n, p)| (n.clone(), p.line, p.column, self.function_scope_of(p.line, p.column)))
            .collect();

        for (target, line, col, scope) in &gotos {
            let (line, col) = (*line, *col);
            self.emit(
                "15.1",
                line,
                col,
                format!("`goto {target}` — unrestricted jumps make a function's control flow something you have to simulate rather than read"),
            );
            // The label is looked up in the function the `goto` sits in, not
            // file-wide: a forward jump to `done:` in a second function is not a
            // backward jump just because the first function had its own `done:`.
            if let Some((_, label_line, label_col, _)) =
                labels.iter().find(|(n, _, _, s)| n == target && s == scope)
                && (*label_line, *label_col) < (line, col) {
                    self.emit(
                        "15.2",
                        line,
                        col,
                        format!("`goto {target}` jumps backwards to line {label_line}, forming a loop that no loop keyword marks"),
                    );
                }
        }

        // 2.6: a label nothing jumps to. Matched within its own function, so a
        // `goto unused;` in another function does not count.
        let unused: Vec<(String, u32)> = labels
            .iter()
            .filter(|(name, _, _, scope)| {
                !gotos.iter().any(|(t, _, _, gs)| t == name && gs == scope)
            })
            .map(|(name, line, _, _)| (name.clone(), *line))
            .collect();
        for (name, line) in unused {
            self.emit(
                "2.6",
                line,
                1,
                format!("label `{name}` is never the target of a `goto`"),
            );
        }
    }

    // --- expressions ------------------------------------------------------

    fn check_expressions(&mut self) {
        let n = self.code.len();
        let mut hits: Vec<(&'static str, u32, u32, String)> = Vec::new();

        for i in 0..n {
            let t = self.tok(i);
            let (line, col) = self.pos_of(i);

            // 12.1: mixed operators whose relative precedence readers misjudge.
            if matches!(t, "&&") {
                let mixes_or = (i.saturating_sub(6)..(i + 7).min(n))
                    .any(|k| self.tok(k) == "||");
                let parenthesized = i > 0 && (self.tok(i - 1) == ")" || self.tok(i + 1) == "(");
                if mixes_or && !parenthesized {
                    hits.push((
                        "12.1",
                        line,
                        col,
                        "`&&` and `||` mixed without parentheses; `&&` binds tighter, which is not what the layout usually suggests".into(),
                    ));
                }
            }
            // `sizeof cmd - strlen(cmd) - 1` reads as "the size of the
            // remaining room" and means `(sizeof cmd) - strlen(cmd) - 1`, which
            // is the same thing only by luck: `sizeof` binds tighter than every
            // binary operator, so an unparenthesized operand silently ends at
            // the first one. Found by cppcheck's MISRA addon on a file this
            // engine read clean — see `misra_agrees_with_cppcheck.rs`.
            if t == "sizeof" && self.tok(i + 1) != "(" {
                // The operand of an unparenthesized `sizeof` is a unary
                // expression, so a binary operator immediately after a single
                // identifier or literal is where it ends.
                let ends_at_operator = matches!(
                    self.tok(i + 2),
                    "+" | "-" | "*" | "/" | "%" | "<<" | ">>" | "<" | ">" | "&" | "|" | "^"
                );
                if ends_at_operator {
                    hits.push((
                        "12.1",
                        line,
                        col,
                        format!(
                            "`sizeof {}` has no parentheses and is followed by `{}`; `sizeof`                              binds tighter than every binary operator, so its operand ends here                              rather than where the expression reads as ending",
                            self.tok(i + 1),
                            self.tok(i + 2)
                        ),
                    ));
                }
            }

            if matches!(t, "<<" | ">>") {
                let arithmetic_neighbour = (i.saturating_sub(3)..(i + 4).min(n))
                    .any(|k| matches!(self.tok(k), "+" | "-"));
                if arithmetic_neighbour {
                    hits.push((
                        "12.1",
                        line,
                        col,
                        "a shift mixed with `+`/`-` without parentheses; `+` binds tighter than `<<`, which surprises most readers".into(),
                    ));
                }
            }

            // 13.6: sizeof must have no side effects.
            if t == "sizeof" && self.sizeof_operand_has_effect(i) {
                hits.push((
                    "13.6",
                    line,
                    col,
                    "the operand of `sizeof` is not evaluated, so any side effect written here never happens".into(),
                ));
            }

            // 12.3: the comma operator inside a controlling expression, and
            // inside a `for` header — where the separators are semicolons, so a
            // comma at the header's own depth is the operator. cppcheck reported
            // `for (i = 0; i < n; i++, other++)` on a corpus file this engine
            // read clean.
            //
            // 13.4 rides along: an `=` anywhere inside a controlling expression
            // means the assignment's value is being consumed by the comparison
            // or the call around it. `if ((b = g(a)) != 0)` is the shape that was
            // missed — `ControlStatement::assignment_in_condition` looks only at
            // the outermost level, deliberately, because it is answering the
            // narrower "was `==` meant" question.
            if matches!(t, "if" | "while" | "switch" | "for") && i + 1 < n && self.tok(i + 1) == "("
                && let Some(close) = cstruct::matching(self.src, &self.code, i + 1, "(", ")") {
                    let mut depth = 0i32;
                    let mut semicolons = 0usize;
                    // The first clause of a `for` that declares its variables:
                    // the commas there separate declarators, not operands.
                    let declares_init = t == "for" && self.begins_declaration(i + 2);
                    let mut nested_assignment: Option<(u32, u32)> = None;
                    // Inside braces, `=` is a designator's: `(struct s){ .x = 1 }`.
                    let mut braces = 0i32;
                    for k in i + 1..close {
                        match self.tok(k) {
                            "(" => depth += 1,
                            ")" => depth -= 1,
                            "{" => braces += 1,
                            "}" => braces -= 1,
                            ";" if depth == 1 => semicolons += 1,
                            "," if depth == 1 && !(declares_init && semicolons == 0) => {
                                let (cl, cc) = self.pos_of(k);
                                hits.push((
                                    "12.3",
                                    cl,
                                    cc,
                                    "the comma operator here evaluates and discards its left operand; only the rightmost value is used".into(),
                                ));
                            }
                            s if depth > 1
                                && braces == 0
                                && nested_assignment.is_none()
                                && cstruct::ASSIGNMENT_OPERATORS.contains(&s) =>
                            {
                                nested_assignment = Some(self.pos_of(k));
                            }
                            _ => {}
                        }
                    }
                    if let Some((al, ac)) = nested_assignment {
                        hits.push((
                            "13.4",
                            al,
                            ac,
                            format!(
                                "the result of this assignment is used by the enclosing expression of the `{t}`; an assignment's value should not be read"
                            ),
                        ));
                    }
                }

            // 14.3: a controlling expression that is a literal constant.
            if t == "if" && i + 3 < n && self.tok(i + 1) == "(" && self.tok(i + 3) == ")" {
                let inner = self.tok(i + 2);
                if inner == "0" || inner == "1" {
                    hits.push((
                        "14.3",
                        line,
                        col,
                        format!("`if ({inner})` is invariant, so one branch is unreachable; if this is disabling code, `#if` states that intent to the reader and to coverage"),
                    ));
                }
            }
        }

        // 13.3: an increment mixed with other side effects in one statement.
        hits.extend(self.increment_statement_findings());
        // 12.3: a comma operator outside a control header.
        hits.extend(self.comma_operator_findings());

        for (rule, line, col, msg) in hits {
            self.emit(rule, line, col, msg);
        }
    }

    fn increment_statement_findings(&self) -> Vec<(&'static str, u32, u32, String)> {
        let mut out = Vec::new();
        let n = self.code.len();
        // A control header is a full expression of its own, or three of them, so
        // `for (i = 0; i < n; i++) sum += a[i];` is four, none combining anything.
        // `else` and `do` end nothing but start a new statement.
        let mut cut = vec![false; n];
        for k in 0..n {
            match self.tok(k) {
                "if" | "while" | "switch" | "for" if k + 1 < n && self.tok(k + 1) == "(" => {
                    cut[k + 1] = true;
                    if let Some(close) = cstruct::matching(self.src, &self.code, k + 1, "(", ")") {
                        cut[close] = true;
                    }
                }
                "else" | "do" => cut[k] = true,
                _ => {}
            }
        }
        let mut start = 0usize;
        for (i, &at_edge) in cut.iter().enumerate() {
            if !at_edge && !matches!(self.tok(i), ";" | "{" | "}") {
                continue;
            }
            let stmt = start..i;
            start = i + 1;
            if stmt.len() < 3 {
                continue;
            }
            let has_incdec = stmt.clone().any(|k| matches!(self.tok(k), "++" | "--"));
            if !has_incdec {
                continue;
            }
            let other_effects = stmt
                .clone()
                .filter(|k| {
                    cstruct::ASSIGNMENT_OPERATORS.contains(&self.tok(*k))
                        || (self.code[*k].kind == CTokenKind::Identifier
                            && *k + 1 < n
                            && self.tok(*k + 1) == "(")
                })
                .count();
            if other_effects > 0 {
                let (line, col) = self.pos_of(stmt.start.min(n - 1));
                out.push((
                    "13.3",
                    line,
                    col,
                    "this statement combines `++`/`--` with another side effect; the order the two happen in is not fixed by the standard".to_string(),
                ));
            }
        }
        out
    }

    /// 13.6: whether the operand of the `sizeof` at `i` has a side effect.
    ///
    /// A parenthesised operand is scanned for `++`, `--`, an assignment operator
    /// or a call. An unparenthesised one is a unary expression: prefix operators,
    /// a primary, then postfix operators, and the scan ends at the first binary
    /// operator, which is where `sizeof` itself ends.
    fn sizeof_operand_has_effect(&self, i: usize) -> bool {
        let n = self.code.len();
        if i + 1 >= n {
            return false;
        }
        if self.tok(i + 1) == "(" {
            return cstruct::matching(self.src, &self.code, i + 1, "(", ")")
                .is_some_and(|close| self.tokens_have_effect(i + 2, close));
        }
        let mut k = i + 1;
        loop {
            if k >= n {
                return false;
            }
            match self.tok(k) {
                "++" | "--" => return true,
                "*" | "&" | "-" | "+" | "!" | "~" => k += 1,
                _ => break,
            }
        }
        match self.code[k].kind {
            CTokenKind::Identifier | CTokenKind::Number => k += 1,
            _ if self.tok(k) == "(" => match cstruct::matching(self.src, &self.code, k, "(", ")") {
                Some(close) => k = close + 1,
                None => return false,
            },
            _ => return false,
        }
        loop {
            if k >= n {
                return false;
            }
            match self.tok(k) {
                // A call: an identifier followed by `(`.
                "(" => return true,
                "[" => match cstruct::matching(self.src, &self.code, k, "[", "]") {
                    Some(close) => {
                        if self.tokens_have_effect(k + 1, close) {
                            return true;
                        }
                        k = close + 1;
                    }
                    None => return false,
                },
                "." | "->" => k += 2,
                "++" | "--" => return true,
                _ => return false,
            }
        }
    }

    /// Whether `from..to`, part of an unevaluated operand, holds `++`, `--`, an
    /// assignment or a call.
    ///
    /// A `=` in braces is a designator's, in `(struct s){ .x = 1 }`. Two things
    /// that look like calls are not: `offsetof(..)`, which is a constant, and
    /// the abstract declarator in `my_t (*)[4]`, since no call has `*` for its
    /// whole argument.
    fn tokens_have_effect(&self, from: usize, to: usize) -> bool {
        let mut braces = 0i32;
        (from..to).any(|k| {
            match self.tok(k) {
                "{" => braces += 1,
                "}" => braces -= 1,
                _ => {}
            }
            let abstract_declarator = k + 3 < to
                && self.tok(k + 1) == "("
                && self.tok(k + 2) == "*"
                && self.tok(k + 3) == ")";
            matches!(self.tok(k), "++" | "--")
                || (braces == 0 && cstruct::ASSIGNMENT_OPERATORS.contains(&self.tok(k)))
                || (self.code[k].kind == CTokenKind::Identifier
                    && k + 1 < to
                    && self.tok(k + 1) == "("
                    && !matches!(self.tok(k), "offsetof" | "__builtin_offsetof")
                    && !abstract_declarator)
        })
    }

    /// D4.12, the address form: an allocation function used as a value, not
    /// called, as in `void *(*alloc)(size_t) = malloc;`.
    ///
    /// Only a position where a value is read counts. A member, `s.malloc` or
    /// `p->malloc`, follows `.` or `->`; a declarator follows a type. A variable
    /// that merely shares the name is not written to, so an assignment to it is
    /// left alone.
    fn names_allocator_as_value(&self, i: usize) -> bool {
        if !matches!(self.tok(i), "malloc" | "calloc" | "realloc" | "aligned_alloc")
            || i == 0
            || i + 1 >= self.code.len()
        {
            return false;
        }
        let value_position = matches!(
            self.tok(i - 1),
            "=" | "(" | "," | "{" | "&" | "return" | "?" | ":" | "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||"
        );
        let assigned = cstruct::ASSIGNMENT_OPERATORS.contains(&self.tok(i + 1))
            || matches!(self.tok(i + 1), "++" | "--");
        value_position && !assigned
    }

    /// Whether the tokens from `k` begin a declaration: a declaration specifier,
    /// or a type name followed by the rest of a declarator.
    fn begins_declaration(&self, k: usize) -> bool {
        let n = self.code.len();
        if k >= n {
            return false;
        }
        // Words that open a declaration whatever the lexer calls them, and no
        // expression statement: `__attribute__((unused)) int a = 0, b = 0;`.
        if k + 1 < n
            && self.tok(k + 1) == "("
            && matches!(
                self.tok(k),
                "__attribute__" | "__attribute" | "__declspec" | "__typeof__" | "__typeof"
                    | "typeof" | "typeof_unqual" | "alignas" | "_Alignas"
            )
        {
            return true;
        }
        match self.code[k].kind {
            CTokenKind::Keyword => DECLARATION_START.contains(&self.tok(k)),
            CTokenKind::Identifier => {
                k + 1 < n
                    && (self.code[k + 1].kind == CTokenKind::Identifier
                        // A word before a type is a macro for a specifier:
                        // `MAYBE_UNUSED int a = 0, b = 0;`.
                        || (self.code[k + 1].kind == CTokenKind::Keyword
                            && DECLARATION_START.contains(&self.tok(k + 1)))
                        || matches!(self.tok(k + 1), "*" | "&" | "::" | "<"))
            }
            _ => false,
        }
    }

    /// For every token, the innermost bracket enclosing it; and for every
    /// closing bracket, the bracket it closes. A closing bracket's enclosing
    /// bracket is the one around the group it closes.
    fn bracket_structure(&self) -> (Vec<Option<usize>>, Vec<Option<usize>>) {
        let n = self.code.len();
        let mut parent = vec![None; n];
        let mut partner = vec![None; n];
        let mut stack: Vec<usize> = Vec::new();
        for k in 0..n {
            let t = self.tok(k);
            match t {
                "(" | "[" | "{" => {
                    parent[k] = stack.last().copied();
                    stack.push(k);
                }
                ")" | "]" | "}" => {
                    let want = match t {
                        ")" => "(",
                        "]" => "[",
                        _ => "{",
                    };
                    if let Some(pos) = stack.iter().rposition(|&o| self.tok(o) == want) {
                        partner[k] = Some(stack[pos]);
                        stack.truncate(pos);
                    }
                    parent[k] = stack.last().copied();
                }
                _ => parent[k] = stack.last().copied(),
            }
        }
        (parent, partner)
    }

    /// 12.3 wherever a comma is an operator. The commas that separate arguments,
    /// declarators, initialisers, enumerators, parameters and macro arguments are
    /// left alone; so are those in a control header, which the caller reports.
    ///
    /// A comma is classified by the innermost bracket around it. Where that
    /// bracket cannot be read with confidence (a call through a function pointer,
    /// a C++ template argument list) the comma is not reported.
    fn comma_operator_findings(&self) -> Vec<(&'static str, u32, u32, String)> {
        let (parent, partner) = self.bracket_structure();
        let mut out = Vec::new();
        for k in 0..self.code.len() {
            if self.tok(k) != "," {
                continue;
            }
            // At file scope the comma separates declarators.
            let Some(open) = parent[k] else {
                continue;
            };
            let operator = match self.tok(open) {
                "(" => self.paren_groups_an_operand(open, &partner),
                "[" => {
                    open > 0
                        && (self.code[open - 1].kind == CTokenKind::Identifier
                            || matches!(self.tok(open - 1), ")" | "]"))
                }
                "{" => {
                    self.brace_is_block(open, &partner)
                        && self.comma_in_expression_statement(open, k, &parent, &partner)
                }
                _ => false,
            };
            if operator {
                let (line, col) = self.pos_of(k);
                out.push((
                    "12.3",
                    line,
                    col,
                    "the comma operator here evaluates and discards its left operand; only the rightmost value is used".to_string(),
                ));
            }
        }
        out
    }

    /// Whether the `(` at `open` groups an operand, so a comma inside it is an
    /// operator, rather than introducing an argument or parameter list.
    fn paren_groups_an_operand(&self, open: usize, partner: &[Option<usize>]) -> bool {
        if open == 0 {
            return true;
        }
        let p = open - 1;
        match self.code[p].kind {
            // `f(`, `FOO(`, and a declarator's parameter list: all separators.
            CTokenKind::Identifier => false,
            CTokenKind::Keyword => {
                let word = self.tok(p);
                !matches!(
                    word,
                    "if" | "while" | "for" | "switch" | "_Generic" | "_Static_assert" | "static_assert"
                ) && !DECLARATION_START.contains(&word)
            }
            _ => match self.tok(p) {
                ")" => partner[p].is_some_and(|po| {
                    // `if (c) (a, b);`: a statement after a control head.
                    let head = po > 0 && matches!(self.tok(po - 1), "if" | "while" | "for" | "switch");
                    // `(void)(a, b)`: a cast, so the group after it is an operand.
                    head || (po + 1 < self.code.len() && DECLARATION_HEADS.contains(&self.tok(po + 1)))
                }),
                "]" => false,
                // `__attribute__((section(".x"), used))`: the inner group is the
                // attribute list, and its commas separate attributes.
                "(" if p > 0 && matches!(self.tok(p - 1), "__attribute__" | "__attribute" | "__declspec") => false,
                _ => true,
            },
        }
    }

    /// Whether the `{` at `open` opens a block of statements, as opposed to an
    /// initialiser list or the body of a struct, union, enum or class.
    fn brace_is_block(&self, open: usize, partner: &[Option<usize>]) -> bool {
        if open == 0 {
            return true;
        }
        let p = open - 1;
        match self.code[p].kind {
            // `struct S {`, `enum E {`, `namespace N {`
            CTokenKind::Identifier => false,
            CTokenKind::Keyword => matches!(self.tok(p), "else" | "do" | "try"),
            _ => match self.tok(p) {
                // A function body or a control statement's body. A `)` after
                // anything else opens a compound literal, `(T){ ... }`.
                ")" => partner[p].is_some_and(|po| {
                    po > 0
                        && (self.code[po - 1].kind == CTokenKind::Identifier
                            || matches!(self.tok(po - 1), "if" | "while" | "for" | "switch"))
                }),
                ";" | "}" | ":" => true,
                // A nested brace is a block only inside a block.
                "{" => self.brace_is_block(p, partner),
                _ => false,
            },
        }
    }

    /// Whether a comma at `k`, directly inside the block opened at `open`, is in
    /// an expression statement, rather than in a declaration or among the
    /// enumerators of an initialiser.
    fn comma_in_expression_statement(
        &self,
        open: usize,
        k: usize,
        parent: &[Option<usize>],
        partner: &[Option<usize>],
    ) -> bool {
        // Walk back to the start of the statement, skipping over nested groups,
        // which stop nothing. A `;`, or a block that closed, ends the previous one.
        let mut start = open + 1;
        for m in (open + 1..k).rev() {
            if parent[m] != Some(open) {
                continue;
            }
            let ends_previous = match self.tok(m) {
                ";" => true,
                "}" => partner[m].is_some_and(|o| self.brace_is_block(o, partner)),
                _ => false,
            };
            if ends_previous {
                start = m + 1;
                break;
            }
        }
        // Labels stand before the statement they label.
        let mut first = start;
        while first < k {
            if matches!(self.tok(first), "case" | "default") {
                match (first + 1..k).find(|&m| self.tok(m) == ":" && parent[m] == Some(open)) {
                    Some(colon) => first = colon + 1,
                    None => return false,
                }
            } else if self.code[first].kind == CTokenKind::Identifier
                && first + 1 < k
                && self.tok(first + 1) == ":"
            {
                first += 2;
            } else {
                break;
            }
        }
        first < k && !self.begins_declaration(first)
    }

    // --- library use ------------------------------------------------------

    fn check_library_use(&mut self) {
        let n = self.code.len();
        let mut hits: Vec<(&'static str, u32, u32, String)> = Vec::new();

        for i in 0..n {
            if self.code[i].kind != CTokenKind::Identifier {
                continue;
            }
            // Only a call position counts for the banned functions; a variable
            // named `time` is fine. D4.12 also reaches an allocator named as a
            // value, which allocates just as well through the pointer it lands in.
            // `(printf)("x")` calls it too, by the spelling that avoids a macro.
            // The word before the parentheses must not make them a declarator's,
            // a cast's operand or a control header's.
            let parenthesised_call = i >= 1
                && self.tok(i - 1) == "("
                && i + 2 < n
                && self.tok(i + 1) == ")"
                && self.tok(i + 2) == "("
                && (i < 2
                    || self.tok(i - 2) == "return"
                    || !(matches!(self.code[i - 2].kind, CTokenKind::Identifier | CTokenKind::Keyword)
                        || matches!(self.tok(i - 2), ")" | "]" | "*")));
            if !parenthesised_call && (i + 1 >= n || self.tok(i + 1) != "(") {
                if self.names_allocator_as_value(i) {
                    let (line, col) = self.pos_of(i);
                    hits.push((
                        "D4.12",
                        line,
                        col,
                        format!("`{}` is taken as a value here, and calls through the pointer allocate dynamically; the timing and fragmentation are the same as a direct call", self.tok(i)),
                    ));
                }
                continue;
            }
            // And only a *free* call. `b.signal(1)` calls a member of `b`,
            // which is not `<csignal>`'s `signal` however it is spelled — the
            // name is ubiquitous in event-driven C++, and `logger.printf(..)`,
            // `pool.free(..)` and `p->signal(..)` are the same shape. The check
            // looked only at the token after the identifier, so every one of
            // them was reported against a library guideline.
            //
            // A qualified name is left alone deliberately: `std::signal` is the
            // library function and must still be reported, and this engine
            // cannot tell `std::` from `mylib::` without more than it has.
            if i > 0 && matches!(self.tok(i - 1), "." | "->") {
                continue;
            }
            // Nor a declaration. `struct Bus { void signal(int); };` puts the
            // name in call position without calling anything, and these
            // guidelines are about *using* the facility.
            if i > 0 && precedes_a_declarator(self.tok(i - 1), self.lexed.dialect) {
                continue;
            }
            let name = self.tok(i);
            if let Some((_, rule)) = BANNED_FUNCTIONS.iter().find(|(f, _)| *f == name) {
                let (line, col) = self.pos_of(i);
                hits.push((rule, line, col, banned_message(name, rule)));
            }
            // D4.12 restates the allocation ban as a directive; report both so
            // a project tracking directives separately sees it.
            if matches!(name, "malloc" | "calloc" | "realloc" | "aligned_alloc") {
                let (line, col) = self.pos_of(i);
                hits.push((
                    "D4.12",
                    line,
                    col,
                    format!("`{name}` allocates dynamically; on a long-running embedded target, fragmentation makes a later allocation fail at a time unrelated to this line"),
                ));
            }
        }

        // A macro body is one directive line and never reaches `code`, so a call
        // written there would otherwise be invisible everywhere it expands.
        for d in &self.st.directives {
            if d.kind != sda_syntax::DirectiveKind::Define {
                continue;
            }
            for name in calls_in_macro_body(&d.body, d.function_like) {
                let (line, col) = (d.pos.line, d.pos.column);
                if let Some((_, rule)) = BANNED_FUNCTIONS.iter().find(|(f, _)| *f == name) {
                    hits.push((rule, line, col, banned_message(name, rule)));
                }
                if matches!(name, "malloc" | "calloc" | "realloc" | "aligned_alloc") {
                    hits.push((
                        "D4.12",
                        line,
                        col,
                        format!("`{name}` allocates dynamically, here in a macro body, so every expansion does"),
                    ));
                }
            }
        }

        // 21.25: relaxed memory ordering.
        for i in 0..n {
            let t = self.tok(i);
            if t.starts_with("memory_order_") && t != "memory_order_seq_cst" {
                let (line, col) = self.pos_of(i);
                hits.push((
                    "21.25",
                    line,
                    col,
                    format!("`{t}` is weaker than sequential consistency; reasoning about the resulting reorderings is beyond what review can reliably do"),
                ));
            }
        }

        // D4.3: assembly must be isolated in its own wrapper.
        for i in 0..n {
            if matches!(self.tok(i), "asm" | "__asm" | "__asm__") {
                let (line, col) = self.pos_of(i);
                let enclosing = self.st.function_at(line);
                let isolated = enclosing.is_some_and(|f| f.statements <= 2);
                if !isolated {
                    hits.push((
                        "D4.3",
                        line,
                        col,
                        "assembly is mixed with C in this function; wrapping it in a function of its own keeps the non-portable part reviewable and replaceable".into(),
                    ));
                }
            }
        }

        for (rule, line, col, msg) in hits {
            self.emit(rule, line, col, msg);
        }
    }

    /// 17.2: recursion, direct or mutual, within this translation unit.
    fn check_recursion(&mut self) {
        let call_graph = self.call_graph();
        let mut reported = BTreeSet::new();
        let mut findings = Vec::new();

        let component = recursive_components(&call_graph);
        for f in &self.st.functions {
            if reported.contains(&f.name) {
                continue;
            }
            if let Some(cycle) = cycle_through(&call_graph, &component, &f.name) {
                reported.extend(cycle.iter().cloned());
                let path = cycle.join(" -> ");
                findings.push((
                    f.pos.line,
                    f.pos.column,
                    if cycle.len() == 1 {
                        format!("`{}` calls itself; without a bound on the depth, stack exhaustion is a runtime failure with no diagnostic", f.name)
                    } else {
                        format!("mutual recursion: {path}. Stack depth here is not statically bounded.")
                    },
                ));
            }
        }
        for (line, col, msg) in findings {
            self.emit("17.2", line, col, msg);
        }
    }

    /// Which functions each function calls, restricted to functions defined in
    /// this translation unit. Cross-unit recursion needs whole-program
    /// information and is left to a link-time provider.
    fn call_graph(&self) -> BTreeMap<String, BTreeSet<String>> {
        let defined: BTreeSet<&str> = self.st.functions.iter().map(|f| f.name.as_str()).collect();
        let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for f in &self.st.functions {
            let mut calls = BTreeSet::new();
            for (i, t) in self.code.iter().enumerate() {
                if t.span.start < f.body.start || t.span.end > f.body.end {
                    continue;
                }
                if t.kind != CTokenKind::Identifier {
                    continue;
                }
                if i + 1 < self.code.len() && self.tok(i + 1) == "(" {
                    let name = self.tok(i);
                    if defined.contains(name) {
                        calls.insert(name.to_string());
                    }
                }
            }
            graph.insert(f.name.clone(), calls);
        }
        graph
    }

    /// 2.5: a macro that is defined and never used. Within a single translation
    /// unit this is decidable; a macro consumed by another unit's include of
    /// this header is not, so headers are exempt.
    fn check_unused_macros(&mut self) {
        if self.is_header() {
            return;
        }
        let used: BTreeSet<&str> = self
            .code
            .iter()
            .filter(|t| matches!(t.kind, CTokenKind::Identifier | CTokenKind::Keyword))
            .map(|t| t.text(self.src))
            .collect();
        let unused: Vec<(String, u32, u32)> = self
            .st
            .macros
            .iter()
            .filter(|(name, pos)| {
                if used.contains(name.as_str()) {
                    return false;
                }
                // A macro may also be referenced from a `#if` or from another
                // macro's body — but *not* from its own definition, where its
                // name necessarily appears. Skipping that is the difference
                // between this check working and never firing at all.
                !self
                    .st
                    .directives
                    .iter()
                    .filter(|d| {
                        !(d.kind == sda_syntax::DirectiveKind::Define
                            && d.pos.line == pos.line
                            && d.name.as_deref() == Some(name.as_str()))
                    })
                    .any(|d| {
                        d.body
                            .split(|c: char| !c.is_alphanumeric() && c != '_')
                            .any(|w| w == name)
                    })
            })
            .map(|(n, p)| (n.clone(), p.line, p.column))
            .collect();

        for (name, line, col) in unused {
            self.emit(
                "2.5",
                line,
                col,
                format!("macro `{name}` is defined but never used in this translation unit"),
            );
        }
    }

    /// 5.1: external identifiers must be distinct within the significant length.
    /// Checked here across the functions defined in this unit; a linker-scope
    /// check across the whole program is a system-scope provider's job.
    fn check_external_identifier_distinctness(&mut self) {
        let mut seen: BTreeMap<String, (String, u32)> = BTreeMap::new();
        let mut hits = Vec::new();
        // Functions and file-scope objects both have external linkage, and a
        // linker cannot tell either kind apart past the significant length.
        // Objects were invisible here until `CStructure::objects` existed.
        let externals: Vec<(&String, sda_syntax::Pos)> = self
            .st
            .functions
            .iter()
            .filter(|f| !f.internal_linkage)
            .map(|f| (&f.name, f.pos))
            .chain(self.st.objects.iter().filter(|o| !o.internal_linkage).map(|o| (&o.name, o.pos)))
            .collect();
        for (name, pos) in externals {
            let key = significant(name);
            match seen.get(&key) {
                Some((other, other_line)) if other != name => {
                    hits.push((
                        pos.line,
                        pos.column,
                        format!("`{name}` is not distinct from `{other}` (line {other_line}) within the first 31 significant characters, which is all a conforming linker must consider"),
                    ));
                }
                _ => {
                    seen.insert(key, (name.clone(), pos.line));
                }
            }
        }
        for (line, col, msg) in hits {
            self.emit("5.1", line, col, msg);
        }
    }

    /// 14.2: a `for` loop must be well-formed. Checked partially: a comma in the
    /// initialisation or increment clause, or a missing controlling expression.
    fn check_for_loop_form(&mut self) {
        let n = self.code.len();
        let mut hits = Vec::new();
        for i in 0..n {
            if self.tok(i) != "for" || i + 1 >= n || self.tok(i + 1) != "(" {
                continue;
            }
            let Some(close) = cstruct::matching(self.src, &self.code, i + 1, "(", ")") else {
                continue;
            };
            let mut clauses: Vec<Vec<&str>> = vec![Vec::new()];
            let mut depth = 0i32;
            for k in i + 2..close {
                match self.tok(k) {
                    "(" | "[" => depth += 1,
                    ")" | "]" => depth -= 1,
                    ";" if depth == 0 => {
                        clauses.push(Vec::new());
                        continue;
                    }
                    _ => {}
                }
                if let Some(clause) = clauses.last_mut() {
                    clause.push(self.tok(k));
                }
            }
            let (line, col) = self.pos_of(i);
            if clauses.len() == 3 && clauses[1].is_empty() && !clauses[0].is_empty() {
                hits.push((line, col, "this `for` loop has an initialiser and an increment but no controlling expression, so nothing in the header says when it stops".to_string()));
            }
            if clauses.iter().any(|c| c.contains(&",")) {
                hits.push((line, col, "a clause of this `for` header contains a comma operator; the loop's control variables are no longer identifiable from the header alone".to_string()));
            }
        }
        for (line, col, msg) in hits {
            self.emit("14.2", line, col, msg);
        }
    }

    /// 16.1: a `switch` is well-formed only if its body is a sequence of
    /// clauses. Checked partially: statements appearing before the first label
    /// can never execute.
    fn check_switch_wellformedness(&mut self) {
        let n = self.code.len();
        let mut hits = Vec::new();
        for i in 0..n {
            if self.tok(i) != "switch" || i + 1 >= n || self.tok(i + 1) != "(" {
                continue;
            }
            let Some(cond_close) = cstruct::matching(self.src, &self.code, i + 1, "(", ")") else {
                continue;
            };
            let body_open = cond_close + 1;
            if body_open >= n || self.tok(body_open) != "{" {
                continue;
            }
            let Some(body_close) = cstruct::matching(self.src, &self.code, body_open, "{", "}")
            else {
                continue;
            };
            let first_label = (body_open + 1..body_close)
                .find(|k| matches!(self.tok(*k), "case" | "default"));
            if let Some(label) = first_label
                && label > body_open + 1 {
                    let (line, col) = self.pos_of(body_open + 1);
                    hits.push((
                        line,
                        col,
                        "statements appear before the first `case` label; control enters a switch only at a label, so this code can never run".to_string(),
                    ));
                }
        }
        for (line, col, msg) in hits {
            self.emit("16.1", line, col, msg);
        }
    }

    /// 21.2: a reserved identifier must not be declared. Checked over the
    /// function definitions and file-scope objects this unit provides — still
    /// partial, because a reserved name given to a parameter, a local, a member
    /// or a tag is not seen.
    fn check_reserved_declarations(&mut self) {
        let hits: Vec<(String, u32, u32)> = self
            .st
            .functions
            .iter()
            .map(|f| (&f.name, f.pos))
            .chain(self.st.objects.iter().map(|o| (&o.name, o.pos)))
            .filter(|(name, _)| is_reserved_identifier(name))
            .map(|(name, pos)| (name.clone(), pos.line, pos.column))
            .collect();
        for (name, line, col) in hits {
            self.emit(
                "21.2",
                line,
                col,
                format!("`{name}` is reserved to the implementation; defining it may collide with something the toolchain already provides, and the collision need not be diagnosed"),
            );
        }
    }

    /// D4.2: assembly should be documented. Checked as: an `asm` statement with
    /// no comment on the two lines above it.
    fn check_assembly_documentation(&mut self) {
        let comment_lines: BTreeSet<u32> = self.lexed.comments().map(|t| t.pos.line).collect();
        let sites: Vec<(u32, u32)> = self
            .code
            .iter()
            .filter(|t| matches!(t.text(self.src), "asm" | "__asm" | "__asm__"))
            .map(|t| (t.pos.line, t.pos.column))
            .collect();
        for (line, col) in sites {
            let documented = (line.saturating_sub(2)..=line).any(|l| comment_lines.contains(&l));
            if !documented {
                self.emit(
                    "D4.2",
                    line,
                    col,
                    "this assembly has no accompanying comment; the one part of the code a compiler cannot explain is the part that most needs explaining",
                );
            }
        }
    }

    /// C++ casts: the named forms say what they mean and are greppable; the
    /// C-style form silently picks whichever conversion compiles.
    fn check_cpp_casts(&mut self) {
        let n = self.code.len();
        let mut hits = Vec::new();

        for i in 0..n {
            let t = self.tok(i);
            let (line, col) = self.pos_of(i);
            match t {
                "reinterpret_cast" => hits.push((
                    "8.2.2",
                    line,
                    col,
                    "`reinterpret_cast` reinterprets a bit pattern as an unrelated type. Nothing \
                     checks that the target type's invariants hold, and on a strict-aliasing \
                     compiler the result may be optimised on assumptions that are now false."
                        .to_string(),
                )),
                // 8.2.3 names the *removal* of const qualification, and this
                // fired on the token. `const_cast<const S &>(s)` adds it, which
                // the guideline permits, so the finding cited a rule the code
                // does not break — and in a conformance argument that costs a
                // deviation written for a guideline nobody violated.
                //
                // The target type is the discriminator this engine can see: a
                // cast whose target is const-qualified is not stripping const
                // from the top level. The residual gap is real and much rarer
                // than the false positive it removes —
                // `const_cast<const int *>(p)` where `p` is `const int *const`
                // strips the pointer's own const behind a const-qualified target
                // — and closing it needs the source type, which this engine does
                // not have.
                "const_cast" if !const_qualified_target(self, i) => hits.push((
                    "8.2.3",
                    line,
                    col,
                    "`const_cast` removes a guarantee the rest of the program is relying on. If \
                     the underlying object really is const, writing through the result is \
                     undefined behaviour."
                        .to_string(),
                )),
                // A C-style cast: `(` type-ish `)` immediately before a value.
                "(" => {
                    if let Some(close) = cstruct::matching(self.src, &self.code, i, "(", ")")
                        && is_c_style_cast(self, i, close) {
                            let inner = Span::new(
                                self.code[i + 1].span.start,
                                self.code[close - 1].span.end,
                            )
                            .slice(self.src);
                            hits.push((
                                "8.2.1",
                                line,
                                col,
                                format!(
                                    "`({inner})` is a C-style cast: it silently selects between \
                                     `static_cast`, `const_cast` and `reinterpret_cast`, so the \
                                     reader cannot tell which conversion is happening, and a \
                                     search for dangerous casts will not find it."
                                ),
                            ));
                        }
                }
                _ => {}
            }
        }
        for (rule, line, col, msg) in hits {
            self.emit(rule, line, col, msg);
        }
    }

    /// `<cstring>`'s functions take a length the caller must get right, with no
    /// way for the callee to check it.
    fn check_cpp_library_use(&mut self) {
        let n = self.code.len();
        let hits: Vec<(u32, u32, String)> = (0..n)
            .filter(|i| {
                self.code[*i].kind == CTokenKind::Identifier
                    && *i + 1 < n
                    && self.tok(*i + 1) == "("
                    && CSTRING_FUNCTIONS.contains(&self.tok(*i))
            })
            .map(|i| {
                let (line, col) = self.pos_of(i);
                (line, col, self.tok(i).to_string())
            })
            .collect();

        for (line, col, name) in hits {
            self.emit(
                "24.5.1",
                line,
                col,
                format!(
                    "`{name}` takes a size the caller must compute correctly and cannot verify. \
                     `std::string`, `std::string_view` and `std::span` carry their own extent."
                ),
            );
        }
    }

    // --- metrics ----------------------------------------------------------

    /// Structural metrics are emitted as `Info` findings rather than hidden in a
    /// side channel, so they show up in the same report, the same SARIF, and the
    /// same GUI list as everything else.
    fn emit_metrics(&mut self) {
        let fns: Vec<(String, u32, u32, u32, u32, usize)> = self
            .st
            .functions
            .iter()
            .map(|f| (f.name.clone(), f.pos.line, f.pos.column, f.cyclomatic, f.max_nesting, f.statements))
            .collect();

        for (name, line, col, complexity, nesting, statements) in fns {
            if complexity > 15 {
                self.advise(
                    "SDA-C-COMPLEXITY",
                    "function has high cyclomatic complexity",
                    line,
                    col,
                    format!("`{name}` has cyclomatic complexity {complexity} across {statements} statements — that is {complexity} independent paths, which is also the lower bound on the tests needed to cover it"),
                    Severity::Low,
                );
            }
            if nesting > 5 {
                self.advise(
                    "SDA-C-NESTING",
                    "function is deeply nested",
                    line,
                    col,
                    format!("`{name}` nests {nesting} levels deep; the innermost statement's preconditions are the conjunction of {nesting} separate decisions"),
                    Severity::Info,
                );
            }
        }
    }
}

// --- free helpers ----------------------------------------------------------

/// Type keywords that make a parenthesised group look like a type name.
const TYPE_KEYWORDS: &[&str] = &[
    "int", "char", "short", "long", "unsigned", "signed", "float", "double", "void", "bool",
    "const", "volatile", "struct", "class", "enum", "union", "wchar_t", "char8_t", "char16_t",
    "char32_t", "size_t", "auto",
];

/// Whether `( ... )` at `open..close` is a C-style cast rather than a call
/// argument list or a grouped subexpression.
///
/// Conservative by construction: three independent conditions must all hold, so
/// the common shapes that merely look similar — `f(a)`, `if (x)`, `sizeof(int)`,
/// `(a + b) * c` — are each excluded by a different one.
/// Whether the target type of a named cast at `at` is const-qualified.
///
/// `const_cast<const S &>(s)` adds const; `const_cast<S &>(s)` may remove it.
/// MISRA C++ 8.2.3 names only the removal, so the two must be told apart, and
/// the target type between the angle brackets is the part this engine can read
/// without type information.
///
/// Angle-bracket depth is tracked so a nested template argument does not end the
/// scan early. A `>>` is lexed as one token in some positions, so both are
/// counted.
fn const_qualified_target(cx: &Cx<'_>, at: usize) -> bool {
    if !cx.tok(at + 1).starts_with('<') {
        return false;
    }
    let mut depth = 0i32;
    let mut i = at + 1;
    while i < cx.code.len() {
        match cx.tok(i) {
            "<" => depth += 1,
            ">" => {
                depth -= 1;
                if depth == 0 {
                    return false;
                }
            }
            ">>" => {
                depth -= 2;
                if depth <= 0 {
                    return false;
                }
            }
            "const" => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

fn is_c_style_cast(cx: &Cx<'_>, open: usize, close: usize) -> bool {
    if close <= open + 1 {
        return false; // `()` is never a cast
    }

    // 1. What precedes it must not make this a call or a continuation.
    if open > 0 {
        let prev = cx.code[open - 1];
        let prev_text = prev.text(cx.src);
        if matches!(prev.kind, CTokenKind::Identifier | CTokenKind::Number)
            || matches!(prev_text, ")" | "]" | ">")
        {
            return false;
        }
        // Operators and clauses whose parentheses may legitimately contain a
        // *type*, which is the only reason to exclude them here: `sizeof(int)`
        // is not a cast, and step 2 cannot tell the difference.
        //
        // `return` used to be on this list and does not belong. Its parentheses
        // hold an expression, so `return (x);` is already rejected by step 2 —
        // while `return (int)v;` is a C-style cast that this rule exists to
        // find, and excluding the keyword meant it never reached the type check.
        // Found by clang-tidy's `google-readability-casting`, which reported the
        // cast this engine read clean.
        if matches!(
            prev_text,
            "sizeof" | "catch" | "alignof" | "decltype" | "typeof" | "noexcept"
                | "static_assert" | "_Static_assert"
        ) {
            return false;
        }
    }

    // 2. The contents must read as a type, and must actually name one — an
    //    identifier alone is a grouped variable, not a cast.
    let mut has_type_keyword = false;
    let mut has_pointer_declarator = false;
    for k in (open + 1)..close {
        let s = cx.code[k].text(cx.src);
        let tok = cx.code[k];
        if TYPE_KEYWORDS.contains(&s) {
            has_type_keyword = true;
            continue;
        }
        if matches!(s, "*" | "&" | "::" | "<" | ">" | "[" | "]" | ",") {
            if s == "*" || s == "&" {
                has_pointer_declarator = true;
            }
            continue;
        }
        if tok.kind == CTokenKind::Identifier {
            continue; // a user-defined type name
        }
        return false; // anything else means this is an expression
    }
    if !has_type_keyword && !has_pointer_declarator {
        return false;
    }

    // 3. What follows must begin an operand for the cast to apply to.
    let Some(next) = cx.code.get(close + 1) else {
        return false;
    };
    let next_text = next.text(cx.src);
    matches!(next.kind, CTokenKind::Identifier | CTokenKind::Number | CTokenKind::String)
        || matches!(next_text, "(" | "&" | "*" | "-" | "+" | "~" | "!" | "this")
}

/// Identifiers followed by `(` in a `#define`'s text, past its name and
/// parameters and outside its literals. A member call is not the library name.
fn calls_in_macro_body(body: &str, function_like: bool) -> Vec<&str> {
    let start = if function_like {
        body.find(')').map_or(body.len(), |p| p + 1)
    } else {
        body.find(|c: char| !c.is_alphanumeric() && c != '_').unwrap_or(body.len())
    };
    let b = body.as_bytes();
    let mut out = Vec::new();
    let mut i = start;
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            i += 1;
            while i < b.len() && b[i] != c {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i += 1;
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let from = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let before = body[start..from].trim_end();
            let member = before.ends_with('.') || before.ends_with("->");
            if !member && body[i..].trim_start().starts_with('(') {
                out.push(&body[from..i]);
            }
        } else {
            i += 1;
        }
    }
    out
}

fn banned_message(name: &str, rule: &str) -> String {
    let why = match rule {
        "21.3" => "dynamic allocation can fail at any point and fragments over time",
        "21.4" => "non-local jumps skip every cleanup path between here and the target",
        "21.5" => "signal handlers run concurrently with everything and may only touch a tiny set of operations",
        "21.6" => "standard I/O pulls in buffering, locale and allocation that a freestanding target cannot afford",
        "21.7" => "these conversions cannot report failure — an unparseable string is indistinguishable from zero",
        "21.8" => "terminating the process leaves hardware in whatever state it was in",
        "21.9" => "the comparison callback makes the ordering unverifiable and the complexity unbounded",
        "21.10" => "time and date facilities are implementation-defined and often not present at all",
        "21.12" => "floating-point exception state is global and interacts badly with optimisation",
        "21.21" => "this hands a string to a shell, which is a command-injection sink",
        "21.24" => "the standard generator is not suitable where randomness matters and is not reproducible where it does not",
        _ => "this facility is not permitted in this profile",
    };
    format!("`{name}` is not permitted: {why}")
}

/// What is wrong with a parameter list, if anything.
///
/// MISRA 8.2 asks for prototype form *with named parameters*, and the two
/// failures read differently to whoever has to fix them.
fn prototype_fault(params: &str, reads_lone_words: bool) -> Option<String> {
    let text = params.trim();
    if text.is_empty() {
        return Some(
            "declares no prototype; write `(void)` so a call with arguments is an error rather \
             than undefined behaviour"
                .to_string(),
        );
    }
    if text == "void" {
        return None;
    }
    // Variadic and old-style declarators are not this rule's business.
    if text.contains("...") {
        return None;
    }
    for param in text.split(',') {
        let p = param.trim();
        if p.is_empty() {
            continue;
        }
        // A parameter this analyzer cannot read as C is not judged.
        //
        // A `.h` in a C++ project is read as C on purpose — that is what lets
        // this run on code that does not build — but reporting C++ as malformed
        // C is a different thing. `SPI::DRDY drdy_gpio = {}`,
        // `decltype(&C::instantiate)` and `const char (&name)[N]` are all named
        // parameters, in a language this pass is not reading.
        if p.contains("::") || p.contains('&') || p.contains('=') || p.contains('<') {
            continue;
        }
        // Nor one whose own parentheses this split cannot honour. A
        // function-pointer parameter — `void (*callback)(void)` — is named, and
        // splitting the list on commas tears it in half besides.
        if p.contains('(') || p.contains(')') {
            continue;
        }
        // The name is the last word, once array brackets are out of the way:
        // `char c[static 1]` is named `c`, and `int buf[]` is named `buf`.
        let stripped = without_brackets(p);
        let ends_in_name = stripped
            .trim_end()
            .rsplit(|c: char| !(c.is_alphanumeric() || c == '_'))
            .next()
            .is_some_and(|w| !w.is_empty() && !TYPE_WORDS.contains(&w));
        // What remains once the qualifiers are gone is the type, and possibly a
        // name after it. One word left is a typedef name with no parameter name
        // after it, and `struct X` / `union X` / `enum X` is a tag with no name.
        let core: Vec<&str> = stripped
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty() && !matches!(*w, "const" | "volatile" | "restrict" | "_Atomic"))
            .collect();
        // Nothing here expands macros, so a lone word is read as a typedef name
        // only on a declarator that looks like a function and only when the word
        // could be a type: not a number (`aligned_data(4);`), and not a macro's
        // spelling (`int f(VOID);`, `int f(PARAMS);`).
        let typedef_only = reads_lone_words
            && core.len() == 1
            && !core[0].starts_with(|c: char| c.is_ascii_digit())
            && !looks_like_macro(core[0]);
        let tag_only = core.len() == 2 && matches!(core[0], "struct" | "union" | "enum");
        if !ends_in_name || typedef_only || tag_only {
            return Some(format!(
                "has an unnamed parameter (`{p}`); a prototype must name every parameter, or \
                 nothing says what it is for"
            ));
        }
    }
    None
}

/// The naming conventions that mark a word as a macro: all capitals, or the
/// implementation's leading double underscore. Only a convention, so a typedef
/// spelled `UINT8` is not read as a type by whoever asks this.
fn looks_like_macro(word: &str) -> bool {
    word.starts_with("__")
        || (word.bytes().any(|b| b.is_ascii_uppercase())
            && !word.bytes().any(|b| b.is_ascii_lowercase()))
}

/// `char c[static 1]` -> `char c`. Array bounds are not the parameter's name.
fn without_brackets(param: &str) -> String {
    let mut out = String::with_capacity(param.len());
    let mut depth = 0u32;
    for c in param.chars() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Words that may end a parameter without being its name.
const TYPE_WORDS: &[&str] = &[
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool",
    "bool", "const", "volatile", "restrict", "static", "inline", "_Atomic", "struct", "union",
    "enum", "size_t", "ptrdiff_t",
];

/// Words that make a return type decidably not `void` when they appear in it.
const BASIC_RETURN_WORDS: &[&str] = &[
    "int", "char", "short", "long", "float", "double", "signed", "unsigned", "_Bool", "bool",
    "struct", "union", "enum",
];

/// The value of an integer constant written as a single literal, or `None` when
/// the text is not one.
///
/// Decimal, octal, hexadecimal and binary, with any of the integer suffixes. A
/// float, a character constant, a digit-separated number and anything else this
/// does not read as an integer give `None`, so a caller comparing against a value
/// is never told a guess.
fn integer_literal_value(text: &str) -> Option<u128> {
    let mut digits = text.to_ascii_lowercase();
    while digits.ends_with(['u', 'l']) {
        digits.pop();
    }
    let hex = digits.starts_with("0x");
    if !hex && digits.ends_with("wb") {
        digits.truncate(digits.len() - 2);
    }
    let (body, radix) = if let Some(h) = digits.strip_prefix("0x") {
        (h.to_string(), 16)
    } else if let Some(b) = digits.strip_prefix("0b") {
        (b.to_string(), 2)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (digits[1..].to_string(), 8)
    } else {
        (digits.clone(), 10)
    };
    if body.is_empty() || !body.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u128::from_str_radix(&body, radix).ok()
}

/// The first 31 characters, which is the guaranteed-significant length for
/// **external** identifiers in C99 and later.
///
/// C23 §5.2.4.1 and its predecessors give two limits, and they are not the same
/// number: 31 significant initial characters in an external identifier, 63 in an
/// internal identifier or a macro name. The external limit is lower because it
/// is the linker's, not the compiler's.
fn significant(name: &str) -> String {
    name.chars().take(31).collect()
}

/// The first 63 characters, the guaranteed-significant length for a **macro
/// name** or an internal identifier.
///
/// MISRA 5.4 and 5.5 are about macro names, so 63 is theirs; 5.1 is about
/// external identifiers and keeps 31. Both used 31 until cppcheck's MISRA addon
/// declined to report two thirty-two-character macro names this engine called
/// indistinct — it uses 63 for anything past C89. Reading the translation limits
/// settled it: this engine was over-reporting, which on a guideline about naming
/// means a false positive on code that conforms.
fn significant_macro(name: &str) -> String {
    name.chars().take(63).collect()
}

/// Whether `prev` — the token immediately before a name that is followed by
/// `(` — makes that name a *declaration* rather than a call.
///
/// The `21.*` guidelines are about *using* a library facility. Declaring
/// something with the same name is not using it, and the case that matters is
/// ordinary C++:
///
/// ```cpp
/// struct Bus { void signal(int); };
/// ```
///
/// `signal` sits in call position — an identifier followed by `(` — so the check
/// reported a `<csignal>` violation against a class that merely has a method of
/// that name. This toolkit analyses headers standalone by design, so a header
/// declaring such a class was reported with no call anywhere in the file.
///
/// Two adjacent identifiers cannot be a call in C or C++; they are a declarator
/// after a type. That is the whole test, plus the declaration-specifier keywords
/// that can stand in for the type.
///
/// `*` and `&` are deliberately **not** here. `void *malloc(...)` is a
/// declaration, but `*get_ptr()` is a call, and mistaking the second for the
/// first would lose a real finding. Declaring a library name yourself is rare;
/// calling through a returned pointer is not.
fn precedes_a_declarator(prev: &str, dialect: Dialect) -> bool {
    const SPECIFIERS: &[&str] = &[
        "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "bool",
        "_Bool", "_Complex", "const", "volatile", "restrict", "static", "extern", "inline",
        "register", "auto", "struct", "union", "enum", "typedef", "virtual", "explicit",
        "constexpr", "consteval", "friend", "mutable", "thread_local", "_Atomic", "_Noreturn",
    ];
    if SPECIFIERS.contains(&prev) {
        return true;
    }
    // A user-defined type name: `size_t strlen(const char *);`.
    //
    // Keywords are excluded, and the first version of this did not exclude them:
    // `return` is identifier-shaped, so `return system(cmd);` read as a
    // declaration and a real 21.21 went silent. cppcheck caught it on
    // `vgwrap.c` within a minute of the change — which is what the second
    // implementation is for, and is the direction that matters, since a missing
    // finding on a `native` rule is offered as evidence of conformance.
    if is_keyword(prev, dialect) {
        return false;
    }
    let mut chars = prev.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_keyword(name: &str, dialect: Dialect) -> bool {
    sda_syntax::clex::keywords(dialect).contains(&name)
}

fn first_line(s: &str) -> String {
    let line = s.trim().lines().next().unwrap_or("").trim();
    // Cut at a character, not a byte: slicing at byte 57 inside a multi-byte
    // character panicked and took the whole scan with it.
    if line.len() > 60 {
        format!("{}...", line.chars().take(57).collect::<String>())
    } else {
        line.to_string()
    }
}

/// Whether a comment body looks like disabled code rather than prose.
///
/// Two distinct shapes have to be told apart, and both are common:
///
/// * `/* result = compute(key); */` — code someone commented out instead of
///   deleting, which is what the guideline is about;
/// * a documentation block that *contains* a usage example, which every
///   documented header has, and which is not commented-out code at all.
///
/// The discriminator is proportion. Disabled code is code all the way through;
/// documentation is mostly prose with a few code-shaped lines in it. Scanning
/// this project's own C shim, the whole-comment heuristic flagged the header's
/// documentation block because it shows how to call the API.
fn looks_like_code(body: &str) -> bool {
    let lines: Vec<&str> = body
        .lines()
        .map(|l| l.trim().trim_start_matches('*').trim())
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return false;
    }

    let code_lines = lines.iter().filter(|l| line_looks_like_code(l)).count();
    // A long block is documentation unless nearly all of it is code; a short one
    // is judged on the same proportion, which for a single line means "is it code".
    let proportion = code_lines as f32 / lines.len() as f32;
    lines.len() <= 12 && proportion >= 0.6
}

/// Whether one line, stripped of comment decoration, reads as a statement.
fn line_looks_like_code(line: &str) -> bool {
    let t = line.trim();
    if t.len() < 4 {
        return false;
    }
    let ends_like_statement = t.ends_with(';') || t.ends_with('{') || t.ends_with('}');
    let has_call = t.contains('(') && t.contains(')');
    let has_assignment = t.contains('=') && !t.contains("==");
    let has_keyword = ["if ", "for ", "while ", "return", "else", "switch"]
        .iter()
        .any(|k| t.contains(k));

    (ends_like_statement && (has_call || has_assignment || has_keyword))
        || (t.contains(';') && has_call && has_keyword)
}

/// MISRA C Rule 4.1: an octal or hex escape must be terminated by the end of the
/// literal or by the start of another escape, otherwise how many digits it
/// consumes depends on what follows.
fn unterminated_escape(literal: &str) -> Option<String> {
    let b = literal.as_bytes();
    let mut i = 0usize;
    while i + 1 < b.len() {
        if b[i] != b'\\' {
            i += 1;
            continue;
        }
        // `\\` is an escaped backslash, not the start of a numeric escape.
        if b[i + 1] == b'\\' {
            i += 2;
            continue;
        }
        if b[i + 1] == b'x' || b[i + 1] == b'X' {
            let mut j = i + 2;
            while j < b.len() && b[j].is_ascii_hexdigit() {
                j += 1;
            }
            // A hex escape consumes digits greedily, so anything hex-ish after it
            // silently joins it.
            if j < b.len() && b[j] != b'"' && b[j] != b'\'' && b[j] != b'\\' {
                return Some(format!(
                    "hexadecimal escape in {literal} is not terminated — it consumes hex digits greedily, so the following character changes the value"
                ));
            }
            i = j;
            continue;
        }
        if b[i + 1].is_ascii_digit() && b[i + 1] < b'8' {
            let mut j = i + 1;
            let mut digits = 0;
            while j < b.len() && b[j].is_ascii_digit() && b[j] < b'8' && digits < 3 {
                j += 1;
                digits += 1;
            }
            // Any digit following an octal escape is the ambiguous case. A
            // reader has to know that the escape stops at three digits to see
            // where it ends, and at fewer than three the compiler's own rule is
            // "take digits until one is not octal" — so `"\128"` is `\12` then
            // `'8'`, which almost nobody reads correctly at a glance.
            if j < b.len() && b[j].is_ascii_digit() {
                let _ = digits;
                return Some(format!(
                    "octal escape in {literal} is not terminated — the digit that follows may or may not be part of it"
                ));
            }
            i = j;
            continue;
        }
        i += 2;
    }
    None
}

/// Blank out string and character literals, and comments, preserving length so
/// byte offsets into the original still line up.
///
/// A macro parameter's name appearing inside a literal is not a use of the
/// parameter — the preprocessor does not substitute into literals. Without this,
/// `#define CHECK(index, len) DO((index) < (len), "index outside container")`
/// was reported as using `index` unparenthesized, because the word occurs in the
/// message. That shape is common enough that the rule was unusable without it.
fn mask_literals(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            q @ (b'"' | b'\'') => {
                out.push(' ');
                i += 1;
                while i < bytes.len() && bytes[i] != q {
                    // An escape consumes the next byte, whatever it is.
                    let step = if bytes[i] == b'\\' { 2 } else { 1 };
                    for _ in 0..step.min(bytes.len() - i) {
                        out.push(' ');
                        i += 1;
                    }
                }
                if i < bytes.len() {
                    out.push(' ');
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                    out.push(' ');
                    i += 1;
                }
                for _ in 0..2.min(bytes.len() - i) {
                    out.push(' ');
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out.push(' ');
                    i += 1;
                }
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

/// A function-like macro parameter used in the body without surrounding
/// parentheses (MISRA C Rule 20.7).
/// True when a macro parameter names the type of a compound literal, `(T){...}`,
/// or is used as `(T *)`, which no expression can be: a function cannot take a type.
///
/// A control statement has the same shape, so `if (p) {` is ruled out by the word
/// before the parenthesis, and `...` by accepting identifiers only: it would
/// otherwise match `catch (...) {`.
fn parameter_is_a_type(body: &str) -> bool {
    let Some(open) = body.find('(') else { return false };
    let Some(close) = body[open..].find(')').map(|c| c + open) else { return false };
    let masked = mask_literals(&body[close + 1..]);
    let replacement = masked.as_str();
    let wraps = |rest: &str, p: &str| {
        rest.trim_start()
            .strip_prefix(p)
            .and_then(|r| r.trim_start().strip_prefix(')'))
            .is_some_and(|r| r.trim_start().starts_with('{'))
    };
    let points_to = |rest: &str, p: &str| {
        rest.trim_start().strip_prefix(p).is_some_and(|r| {
            let r = r.trim_start();
            let after = r.trim_start_matches(|c: char| c == '*' || c.is_whitespace());
            after.len() < r.len() && r.starts_with('*') && after.starts_with(')')
        })
    };
    body[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty() && p.bytes().all(is_word_byte))
        .any(|p| {
            replacement.match_indices('(').any(|(at, _)| {
                if points_to(&replacement[at + 1..], p) {
                    return true;
                }
                let word = replacement[..at]
                    .trim_end()
                    .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .next();
                !matches!(word, Some("if" | "while" | "for" | "switch" | "catch"))
                    && wraps(&replacement[at + 1..], p)
            })
        })
}

fn unparenthesized_parameter(body: &str) -> Option<String> {
    let open = body.find('(')?;
    let close = body[open..].find(')')? + open;
    let params: Vec<&str> = body[open + 1..close]
        .split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty() && *p != "..." && p.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .collect();
    // Literals are masked, not removed, so offsets still align with the source.
    let masked = mask_literals(&body[close + 1..]);
    let replacement = masked.as_str();

    for p in params {
        // Find each use of the parameter as a whole word and check its neighbours.
        let bytes = replacement.as_bytes();
        let mut idx = 0usize;
        while let Some(found) = replacement[idx..].find(p) {
            let at = idx + found;
            let end = at + p.len();
            let before_ok = at == 0 || !is_word_byte(bytes[at - 1]);
            let after_ok = end >= bytes.len() || !is_word_byte(bytes[end]);
            if before_ok && after_ok {
                let prev = replacement[..at].trim_end().chars().last();
                let next = replacement[end..].trim_start().chars().next();
                // Wrapped as `(p)` is fine; so is a lone parameter forming the
                // entire replacement, and so is `#p` / `##p`.
                let wrapped = prev == Some('(') && next == Some(')');
                let stringized = prev == Some('#');
                if !wrapped && !stringized && (next.is_some() || prev.is_some()) {
                    return Some(p.to_string());
                }
            }
            idx = end.max(idx + 1);
        }
    }
    None
}

fn is_word_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

/// A macro's replacement list as far as `#` and `##` are concerned: literals and
/// comments blanked, since a `#` in `"#1 release"` is not an operator, and the
/// digraphs `%:` and `%:%:` spelled as the operators they are.
fn macro_operators(body: &str) -> String {
    mask_literals(body).replace("%:%:", "##").replace("%:", "#")
}

/// `#a ## b` — the evaluation order of adjacent `#` and `##` is unspecified.
fn pastes_adjacent_to_stringize(body: &str) -> bool {
    let cleaned = body.replace(' ', "");
    cleaned.contains("#") && cleaned.contains("##") && {
        // A `#x` immediately followed by `##`.
        let bytes = cleaned.as_bytes();
        (0..bytes.len().saturating_sub(1)).any(|i| {
            bytes[i] == b'#'
                && bytes.get(i + 1).is_some_and(|c| is_word_byte(*c))
                && cleaned[i + 1..].find("##").is_some_and(|j| {
                    cleaned[i + 1..i + 1 + j].chars().all(|c| c.is_alphanumeric() || c == '_')
                })
        })
    }
}

/// For each function that is recursive, the strongly connected component it
/// belongs to, numbered. A function is recursive when it is in a component of
/// more than one, or calls itself.
///
/// Tarjan's algorithm, iteratively. The depth-first search this replaced
/// recursed once per call edge, so a long call chain in a scanned file
/// overflowed the stack, and was run afresh from every function, which made the
/// chain cubic. It also returned any cycle *reachable* from a function and
/// reported it against that function, so `f` calling a self-recursive `g` read
/// as "`f` calls itself". Found by a security audit.
fn recursive_components(graph: &BTreeMap<String, BTreeSet<String>>) -> BTreeMap<&str, usize> {
    let names: Vec<&str> = graph.keys().map(String::as_str).collect();
    let id: BTreeMap<&str, usize> = names.iter().enumerate().map(|(i, n)| (*n, i)).collect();
    let edges: Vec<Vec<usize>> = graph
        .values()
        .map(|callees| callees.iter().filter_map(|c| id.get(c.as_str()).copied()).collect())
        .collect();

    const UNSEEN: usize = usize::MAX;
    let n = names.len();
    let (mut index, mut low, mut on_stack) = (vec![UNSEEN; n], vec![0; n], vec![false; n]);
    let (mut stack, mut next_index) = (Vec::new(), 0);
    let mut out = BTreeMap::new();
    let mut components = 0;

    for root in 0..n {
        if index[root] != UNSEEN {
            continue;
        }
        // Each frame is a node and how many of its edges have been followed.
        let mut frames = vec![(root, 0usize)];
        index[root] = next_index;
        low[root] = next_index;
        next_index += 1;
        stack.push(root);
        on_stack[root] = true;

        while let Some(&mut (v, ref mut edge)) = frames.last_mut() {
            if let Some(&w) = edges[v].get(*edge) {
                *edge += 1;
                if index[w] == UNSEEN {
                    index[w] = next_index;
                    low[w] = next_index;
                    next_index += 1;
                    stack.push(w);
                    on_stack[w] = true;
                    frames.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(index[w]);
                }
                continue;
            }
            frames.pop();
            if let Some(&(parent, _)) = frames.last() {
                low[parent] = low[parent].min(low[v]);
            }
            if low[v] == index[v] {
                let mut members = Vec::new();
                while let Some(w) = stack.pop() {
                    on_stack[w] = false;
                    members.push(w);
                    if w == v {
                        break;
                    }
                }
                if members.len() > 1 || edges[v].contains(&v) {
                    for m in members {
                        out.insert(names[m], components);
                    }
                    components += 1;
                }
            }
        }
    }
    out
}

/// The shortest call path from `start` back to itself, staying inside its
/// component, or `None` when `start` is not recursive. A self-call is reported
/// as the function alone.
fn cycle_through(
    graph: &BTreeMap<String, BTreeSet<String>>,
    component: &BTreeMap<&str, usize>,
    start: &str,
) -> Option<Vec<String>> {
    let own = *component.get(start)?;
    let callees = |f: &str| {
        graph
            .get(f)
            .into_iter()
            .flatten()
            .filter(move |c| component.get(c.as_str()) == Some(&own))
    };
    if callees(start).any(|c| c == start) {
        return Some(vec![start.to_string()]);
    }
    let mut came_from: BTreeMap<&str, &str> = BTreeMap::new();
    let mut queue = std::collections::VecDeque::from([start]);
    while let Some(f) = queue.pop_front() {
        for c in callees(f) {
            if c == start {
                let mut path = vec![start.to_string()];
                let mut at = f;
                while at != start {
                    path.push(at.to_string());
                    at = came_from[at];
                }
                path[1..].reverse();
                path.push(start.to_string());
                return Some(path);
            }
            if !came_from.contains_key(c.as_str()) {
                came_from.insert(c, f);
                queue.push_back(c);
            }
        }
    }
    None
}

/// The guideline numbers this checker actually implements.
///
/// [`crate::checks`] holds the authoritative list and a test asserts it agrees
/// with the catalogue, so a guideline can never be marked `native` without a
/// check behind it.
pub fn implemented_rules() -> &'static [CheckId] {
    IMPLEMENTED_C
}

