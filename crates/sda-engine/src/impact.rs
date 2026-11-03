//! Which files mention the symbols a given file defines.
//!
//! The question repowise calls blast radius, and the one a reviewer actually
//! asks: *I am about to change this file — what else is downstream of it?*
//!
//! # This is a lower bound, and that is the whole of the design
//!
//! The reach is found by matching identifier tokens against the external names
//! the file defines. That finds every caller that names the function. It does
//! not find:
//!
//! * a call through a function pointer, where the name appears once at the
//!   assignment and never at the call;
//! * a name assembled by the preprocessor — `CONCAT(prefix, _init)()` mentions
//!   neither `prefix_init` nor anything else this can see;
//! * a linker alias, a weak symbol, or anything resolved by `dlsym`;
//! * C++ overloads and templates, which is why this is C only for now.
//!
//! Every one of those omissions removes a file from the answer. **So the answer
//! is a floor: at least these files are affected, and possibly more.**
//!
//! That direction matters more here than in most places. A blast radius that
//! over-reports wastes a reviewer's afternoon. One that under-reports tells them
//! a change is contained when it is not, and "change it safely" is exactly the
//! promise such a tool is bought to make. This one refuses to make it: the
//! caveat is not a footnote on the output, it is the first thing printed, and
//! `Impact::floor_caveat` exists so no caller can render the list without it.
//!
//! # Why not resolve properly
//!
//! Because resolving properly needs a compile database and a real front end, and
//! this toolkit runs on code that does not build — that is the point of it. When
//! a database *is* present, `ext.clang-tidy` and `ext.codeql` are the providers
//! that answer this question with types behind them, and they are already wired.
//! This is the answer available with nothing but the source, offered as what it
//! is.

use sda_core::Exclusion;
use sda_syntax::clex::{CTokenKind, Dialect, lex};
use sda_syntax::cstruct;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// What one file reaches.
#[derive(Clone, Debug, Default)]
pub struct Impact {
    /// External-linkage names the subject file defines.
    pub symbols: Vec<String>,
    /// Other files that mention them, and which ones they mention.
    pub referenced_by: BTreeMap<String, Vec<String>>,
    /// Files that could not be read, so their references are unknown.
    pub unreadable: Vec<String>,
    /// How many files were actually searched.
    ///
    /// Published because `referenced_by` being empty has two causes that look
    /// identical from outside: nothing names these symbols, and nothing was
    /// looked at. The first is a result; the second is a result about the tool.
    pub searched: usize,
    /// Set when the subject is not something this can analyse at all.
    pub unsupported: Option<String>,
}

impl Impact {
    /// The sentence that must accompany any rendering of this.
    ///
    /// A method rather than a comment in the CLI, so that a second caller — the
    /// MCP surface is the obvious one — cannot render the list without it and
    /// leave an agent believing the set is closed.
    pub fn floor_caveat(&self) -> Exclusion {
        Exclusion {
            provider: "sda.impact".into(),
            reason: format!(
                "{} file(s) name one of these symbols directly. That is a floor, not the set: a \
                 call through a function pointer, a name the preprocessor assembles, a linker \
                 alias or a `dlsym` lookup reaches this code without ever spelling its name, and \
                 none of them appear above. Read it as `at least these`, never as `only these`",
                self.referenced_by.len()
            ),
        }
    }

    /// The reason this answered nothing, when it answered nothing.
    ///
    /// `referenced_by` empty is ambiguous and the ambiguity is dangerous in one
    /// direction: a reader takes "no other file names any of them" as *nothing
    /// depends on this*. It has to be possible to tell that from *nothing was
    /// examined*, which is a statement about the tool and not about the code.
    ///
    /// Measured on the feature's own first version: pointed at a Rust file in a
    /// tree with no C in it, it printed `No other file names any of them` while
    /// a caller two files away called the function by name. Zero files had been
    /// searched. An inability to check, presented as a clean check, in a feature
    /// built to refuse exactly that.
    pub fn nothing_searched_notice(&self) -> Option<Exclusion> {
        if let Some(why) = &self.unsupported {
            return Some(Exclusion {
                provider: "sda.impact".into(),
                reason: format!(
                    "{why}. No file was searched, so the empty result below is a fact about \
                     this tool rather than about the code"
                ),
            });
        }
        if self.searched == 0 {
            return Some(Exclusion {
                provider: "sda.impact".into(),
                reason: "no file was searched: this reads C translation units and the tree \
                         holds none beside the subject. The empty result is a fact about this \
                         tool rather than about the code"
                    .into(),
            });
        }
        None
    }

    /// A second caveat, only when something could not be read.
    pub fn unreadable_notice(&self) -> Option<Exclusion> {
        if self.unreadable.is_empty() {
            return None;
        }
        Some(Exclusion {
            provider: "sda.impact".into(),
            reason: format!(
                "{} file(s) could not be read and were not searched, so a reference in any of \
                 them is missing from this answer, starting with `{}`",
                self.unreadable.len(),
                self.unreadable[0]
            ),
        })
    }
}

/// Find which of `files` mention the external symbols defined by `subject`.
///
/// `subject` and `files` are absolute; the returned keys are whatever
/// `relative` maps them to, so the caller decides how paths are shown.
pub fn of_file(
    subject: &Path,
    files: &[std::path::PathBuf],
    relative: &dyn Fn(&Path) -> String,
) -> Impact {
    let mut out = Impact::default();

    // The subject's language, before anything is parsed.
    //
    // `analyze_c` will happily run over a `.rs` file and pull plausible-looking
    // names out of it — it found `compute` in `pub fn compute(x: i32) -> i32`,
    // which is the worst possible outcome: a confident answer assembled by a
    // parser reading a language it does not know.
    if !subject.extension().is_some_and(|e| e.eq_ignore_ascii_case("c")) {
        // Two refusals, because they have two different reasons and a reader
        // acts on the reason.
        //
        // A header is C. Saying "this reads C only" of a `.h` and then blaming
        // C++ templates is an explanation of something else, offered with the
        // confidence of one that fits — and "change this header, what breaks?"
        // is the likeliest question anyone brings here.
        let header = subject
            .extension()
            .is_some_and(|e| matches!(e.to_string_lossy().to_ascii_lowercase().as_str(),
                "h" | "hpp" | "hh" | "hxx"));
        out.unsupported = Some(if header {
            format!(
                "`{}` is a header, and this reads the file that *defines* a symbol rather than \
                 one that declares it — `CFunction` records a body, and a declaration has none. \
                 Ask about the `.c` that defines these symbols instead. Asking about the header \
                 directly is a real gap rather than a design decision",
                relative(subject)
            )
        } else {
            format!(
                "`{}` is not a C translation unit, and this reads C only — C++ overloads and \
                 templates, and Rust's modules and traits, need a front end rather than a lexer",
                relative(subject)
            )
        });
        return out;
    }

    let Ok(src) = std::fs::read_to_string(subject) else {
        out.unreadable.push(relative(subject));
        return out;
    };

    // The names this file offers to the rest of the program. Internal linkage is
    // excluded because a `static` function cannot be reached from another file
    // however many times its name appears there — that name is a different
    // function, which is the very confusion MISRA 5.9 exists about.
    let lexed = lex(&src, Dialect::C23);
    let st = cstruct::analyze_c(&src, &lexed);
    let defined: BTreeSet<String> = st
        .functions
        .iter()
        .filter(|f| !f.internal_linkage)
        .map(|f| f.name.clone())
        .chain(st.objects.iter().filter(|o| !o.internal_linkage).map(|o| o.name.clone()))
        .collect();

    out.symbols = defined.iter().cloned().collect();
    if defined.is_empty() {
        return out;
    }

    for path in files {
        if path == subject {
            continue;
        }
        out.searched += 1;
        let Ok(other) = std::fs::read_to_string(path) else {
            out.unreadable.push(relative(path));
            continue;
        };

        // Identifier tokens only. A name inside a comment or a string literal is
        // not a reference, and counting one would put files in the answer that a
        // reviewer then has to rule out by hand — which teaches them to distrust
        // the whole list.
        let lexed = lex(&other, Dialect::C23);
        let mut hit: BTreeSet<&str> = BTreeSet::new();
        for t in &lexed.tokens {
            if t.kind != CTokenKind::Identifier {
                continue;
            }
            let text = t.text(&other);
            if let Some(name) = defined.get(text) {
                hit.insert(name.as_str());
            }
        }

        if !hit.is_empty() {
            out.referenced_by
                .insert(relative(path), hit.into_iter().map(str::to_string).collect());
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sda-impact-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    fn rel(dir: &Path) -> impl Fn(&Path) -> String + '_ {
        move |p: &Path| p.strip_prefix(dir).unwrap_or(p).to_string_lossy().replace('\\', "/")
    }

    #[test]
    fn a_caller_that_names_the_function_is_found() {
        let dir = scratch("names");
        std::fs::write(dir.join("lib.c"), "int compute(int x) { return x + 1; }\n").unwrap();
        std::fs::write(dir.join("app.c"), "int main(void) { return compute(2); }\n").unwrap();
        std::fs::write(dir.join("other.c"), "int unrelated(void) { return 0; }\n").unwrap();

        let files = vec![dir.join("lib.c"), dir.join("app.c"), dir.join("other.c")];
        let i = of_file(&dir.join("lib.c"), &files, &rel(&dir));

        assert!(i.symbols.contains(&"compute".to_string()));
        assert_eq!(i.referenced_by.keys().collect::<Vec<_>>(), vec!["app.c"]);
        assert!(i.referenced_by["app.c"].contains(&"compute".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `static` function is not reachable from elsewhere, whatever the name.
    #[test]
    fn an_internal_name_is_not_offered_to_other_files() {
        let dir = scratch("static");
        std::fs::write(dir.join("lib.c"), "static int helper(int x) { return x; }\n").unwrap();
        std::fs::write(dir.join("app.c"), "int helper(int x) { return x - 1; }\n").unwrap();

        let files = vec![dir.join("lib.c"), dir.join("app.c")];
        let i = of_file(&dir.join("lib.c"), &files, &rel(&dir));

        assert!(
            !i.symbols.contains(&"helper".to_string()),
            "a `static` name is a different function in another file, not the same one reached"
        );
        assert!(i.referenced_by.is_empty(), "{:?}", i.referenced_by);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A mention in a comment or a string is not a reference.
    #[test]
    fn a_name_in_prose_is_not_a_caller() {
        let dir = scratch("prose");
        std::fs::write(dir.join("lib.c"), "int compute(int x) { return x; }\n").unwrap();
        std::fs::write(
            dir.join("doc.c"),
            "/* compute is documented here */\nconst char *s = \"compute\";\n",
        )
        .unwrap();

        let files = vec![dir.join("lib.c"), dir.join("doc.c")];
        let i = of_file(&dir.join("lib.c"), &files, &rel(&dir));

        assert!(
            i.referenced_by.is_empty(),
            "a file a reviewer then has to rule out by hand teaches them to distrust the \
             list: {:?}",
            i.referenced_by
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A subject this cannot read is refused rather than guessed at.
    ///
    /// The first version ran `analyze_c` over whatever it was given. On a Rust
    /// file it found `compute` in `pub fn compute(x: i32) -> i32` — a plausible
    /// answer assembled by a parser reading a language it does not know — then
    /// searched the C files, of which there were none, and reported that no file
    /// names it. A caller two files away called it by name.
    #[test]
    fn a_subject_that_is_not_c_is_refused_rather_than_parsed_anyway() {
        let dir = scratch("rust");
        std::fs::write(dir.join("lib.rs"), "pub fn compute(x: i32) -> i32 { x + 1 }
").unwrap();
        std::fs::write(dir.join("app.rs"), "use probe::compute;
pub fn go() { compute(2); }
")
            .unwrap();

        let files = vec![dir.join("lib.rs"), dir.join("app.rs")];
        let i = of_file(&dir.join("lib.rs"), &files, &rel(&dir));

        assert!(i.symbols.is_empty(), "nothing is claimed about a language it cannot read");
        assert_eq!(i.searched, 0);
        let n = i.nothing_searched_notice().expect("and the refusal is reportable");
        assert!(n.reason.contains("not a C translation unit"), "{}", n.reason);
        assert!(
            n.reason.contains("fact about this tool rather than about the code"),
            "the direction of the statement is the point: {}",
            n.reason
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A header is refused for the reason that is true of a header.
    ///
    /// "Change this header, what breaks?" is the likeliest question anyone
    /// brings here, and the first refusal answered it by blaming C++ templates
    /// and Rust traits — an explanation of something else, delivered with the
    /// confidence of one that fits. A `.h` file is C.
    ///
    /// The refusal itself is right: `CFunction` records a body and a declaration
    /// has none, so a declaration-only header yields no symbols and a search
    /// built on it would find nothing while looking like it had looked.
    #[test]
    fn a_header_is_refused_for_a_reason_that_is_true_of_headers() {
        let dir = scratch("header");
        std::fs::write(dir.join("lib.h"), "int compute(int x);
").unwrap();
        std::fs::write(dir.join("app.c"), "#include \"lib.h\"
int main(void){return compute(1);}
")
            .unwrap();

        let files = vec![dir.join("lib.h"), dir.join("app.c")];
        let i = of_file(&dir.join("lib.h"), &files, &rel(&dir));

        let why = i.nothing_searched_notice().expect("a refusal is reportable");
        assert!(
            why.reason.contains("is a header"),
            "the reason has to be the one that applies: {}",
            why.reason
        );
        assert!(
            !why.reason.contains("C++ overloads"),
            "a header is C, and blaming another language explains nothing: {}",
            why.reason
        );
        assert!(
            why.reason.contains("Ask about the `.c`"),
            "and a refusal that names what to do instead costs nothing to write: {}",
            why.reason
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nothing to search is not the same as nothing found.
    #[test]
    fn a_tree_with_nothing_to_search_says_so_rather_than_reporting_none() {
        let dir = scratch("alone");
        std::fs::write(dir.join("lib.c"), "int compute(int x) { return x; }
").unwrap();

        let files = vec![dir.join("lib.c")];
        let i = of_file(&dir.join("lib.c"), &files, &rel(&dir));

        assert!(i.referenced_by.is_empty());
        assert_eq!(i.searched, 0, "the subject is skipped, so nothing was examined");
        assert!(
            i.nothing_searched_notice().is_some(),
            "`no other file names any of them` would read as `nothing depends on this`"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// And a real search says nothing of the kind.
    #[test]
    fn a_real_search_reports_no_such_caveat() {
        let dir = scratch("searched");
        std::fs::write(dir.join("lib.c"), "int compute(int x) { return x; }
").unwrap();
        std::fs::write(dir.join("app.c"), "int main(void) { return compute(1); }
").unwrap();

        let files = vec![dir.join("lib.c"), dir.join("app.c")];
        let i = of_file(&dir.join("lib.c"), &files, &rel(&dir));

        assert_eq!(i.searched, 1);
        assert!(
            i.nothing_searched_notice().is_none(),
            "a caveat that appears on every run is one people learn to skip"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The floor is stated, and the number in it is the number shown.
    #[test]
    fn the_caveat_says_at_least_rather_than_only() {
        let dir = scratch("caveat");
        std::fs::write(dir.join("lib.c"), "int compute(int x) { return x; }\n").unwrap();
        std::fs::write(dir.join("app.c"), "int main(void) { return compute(1); }\n").unwrap();

        let files = vec![dir.join("lib.c"), dir.join("app.c")];
        let i = of_file(&dir.join("lib.c"), &files, &rel(&dir));

        let c = i.floor_caveat();
        assert_eq!(c.provider.as_str(), "sda.impact");
        assert!(c.reason.contains("1 file(s)"), "{}", c.reason);
        assert!(
            c.reason.contains("never as `only these`"),
            "the direction of the error is the point: under-reporting tells a reviewer a \
             change is contained when it is not: {}",
            c.reason
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
