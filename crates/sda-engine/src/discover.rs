//! Turning a directory into an analysis [`Target`].

use sda_core::{Exclusion, Language, Target, TargetFile};
use std::path::Path;
use walkdir::WalkDir;

/// Directories skipped by default. Analyzing a vendored dependency tree or a
/// build output directory wastes time and buries the findings that matter.
const SKIP_DIRS: &[&str] = &[
    ".git", ".hg", ".svn", "node_modules", "target", "build", "out", "dist", ".venv", "venv",
    "__pycache__", ".cache", "cmake-build-debug", "cmake-build-release", ".idea", ".vs",
    "vendor", "third_party", "external",
];

/// Options for discovery.
#[derive(Clone, Debug)]
pub struct DiscoveryOptions {
    pub max_depth: usize,
    /// Files larger than this are recorded but not analyzed; a 50 MB generated
    /// source is not something a lexer should be pointed at by accident.
    pub max_file_bytes: u64,
    pub include_hidden: bool,
    /// Extra directory names to skip.
    pub skip: Vec<String>,
    /// When set, only these languages are collected.
    pub languages: Vec<Language>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        DiscoveryOptions {
            max_depth: 64,
            max_file_bytes: 8 * 1024 * 1024,
            include_hidden: false,
            skip: Vec::new(),
            languages: Vec::new(),
        }
    }
}

impl DiscoveryOptions {
    pub fn only(mut self, langs: Vec<Language>) -> Self {
        self.languages = langs;
        self
    }
    fn skips(&self, name: &str) -> bool {
        SKIP_DIRS.contains(&name) || self.skip.iter().any(|s| s == name)
    }
}

/// Walk `root` and build a [`Target`].
pub fn discover(root: impl AsRef<Path>, opts: &DiscoveryOptions) -> Target {
    let root = root.as_ref();
    let mut files = Vec::new();

    let walker = WalkDir::new(root)
        .max_depth(opts.max_depth)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            if e.file_type().is_dir() && opts.skips(&name) {
                return false;
            }
            if !opts.include_hidden && name.starts_with('.') && name != "." {
                // The root itself may legitimately be a dotted path.
                return e.depth() == 0;
            }
            true
        });

    for entry in walker.flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path().to_path_buf();
        let language = Language::from_path(&path);
        if language == Language::Unknown {
            continue;
        }
        if !opts.languages.is_empty() && !opts.languages.contains(&language) {
            continue;
        }
        let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if bytes > opts.max_file_bytes && language != Language::ModelArtifact {
            continue;
        }
        files.push(TargetFile { path, language, bytes });
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));

    let mut target = Target::new(root).with_files(files);
    // Not just the root: CMake and Ninja write the database into the build
    // directory, which is where `sda build compile-commands` leaves it. Looking
    // only at the root meant a scan silently ran type-aware tools without the
    // database the toolkit had just generated and reported as present.
    target.compile_commands = sda_core::find_compile_commands(root);
    target
}

/// Remove out-of-scope files from a target, reporting what each rule removed.
///
/// **Filtering happens here, not on the findings.** Filtering afterwards would
/// still run every analyzer over excluded source — slower, but worse, it lets a
/// coverage figure or a correlation verdict be computed over files the report
/// then claims it did not examine. An analyzer must never see a file the report
/// says was out of scope.
///
/// Returns one [`Exclusion`] per rule, each stating **the number of files it
/// removed**, including zero. The count is not decoration: `tests/ excluded`
/// invites the reader to assume the directory was empty, and `14 files excluded`
/// cannot be misread. A rule that removed nothing is reported as stale rather
/// than quietly kept, because a scope file drifts out of date silently otherwise.
///
/// This function and the notice it returns exist in the same commit on purpose.
/// A scope declaration's whole job is to make findings not appear, which is the
/// shape of every defect in the failure-mode table; it is only safe while what
/// it removed is impossible to miss.
///
/// # What the paths are relative to, and why it is not the scan root
///
/// `anchor` is **the directory the declaration governs** — the parent of the
/// `.sda/` it was loaded from — and rule paths are matched against paths
/// relative to it. It used to be `target.root`, which is the directory the user
/// happened to type, and the two differ the moment anyone scans a subdirectory:
/// `.sda/` is found by searching *upward*, so `sda scan tools/valgrind-wsl`
/// loads the repository's declaration and then compares its `tools/...` rules
/// against paths beginning `three-sins/`. Nothing matched, every rule reported
/// itself as possibly stale, and the files it names were analysed anyway.
///
/// Anchoring at the declaration makes a scope rule mean the same thing however
/// the scan was invoked, which is what a reader assumes when they write one.
/// A file outside the anchor is left **in** scope: the declaration does not
/// govern it, and over-reporting is the recoverable direction.
pub fn apply_scope(
    target: &mut Target,
    scope: &sda_rules::ScopeRegister,
    anchor: &Path,
) -> Vec<Exclusion> {
    if scope.is_empty() {
        return Vec::new();
    }
    let anchor = anchor.to_path_buf();
    let mut removed: Vec<usize> = vec![0; scope.rules().len()];

    target.files.retain(|f| {
        // No fallback to the full path. A file this declaration does not govern
        // must not be matched against its rules at all — a rule reading `tools`
        // would otherwise exclude any file whose absolute path passes through a
        // directory of that name, in someone else's tree.
        let Ok(rel) = f.path.strip_prefix(&anchor) else { return true };
        let rel = rel.to_string_lossy().to_string();
        match scope.rules().iter().position(|r| r.matches(&rel)) {
            Some(i) => {
                removed[i] += 1;
                false
            }
            None => true,
        }
    });

    let root = target.root.clone();
    scope
        .rules()
        .iter()
        .zip(removed)
        .map(|(rule, n)| Exclusion {
            provider: "sda.scope".into(),
            reason: match n {
                0 => zero_match_reason(rule, &anchor, &root),
                1 => format!(
                    "1 file under `{}` is outside the declared analysis scope ({} — {})",
                    rule.path, rule.reason, rule.approver
                ),
                n => format!(
                    "{n} files under `{}` are outside the declared analysis scope ({} — {})",
                    rule.path, rule.reason, rule.approver
                ),
            },
        })
        .collect()
}

/// Why a rule removed nothing — which is three different situations, and calling
/// all of them "stale" is the shape of failure this codebase keeps having.
///
/// Once a declaration is anchored at the project rather than at the scan root,
/// most of its rules legitimately do not apply to any given scan: `sda scan
/// crates` in this repository loads a declaration whose rules all name `tools`.
/// Reporting that as "it may be stale" on every run trains a reader to skip past
/// the one message that matters — a rule naming a directory that no longer
/// exists.
fn zero_match_reason(rule: &sda_rules::ScopeRule, anchor: &Path, root: &Path) -> String {
    let named = anchor.join(rule.path.replace('\\', "/"));
    let cite = format!("({} — {})", rule.reason, rule.approver);
    if !named.exists() {
        format!(
            "`{}` names nothing in the project, so the rule excluded nothing; \
             it may be stale {cite}",
            rule.path
        )
    } else if !named.starts_with(root) {
        format!(
            "`{}` is out of scope but lies outside this scan of {}, so nothing was \
             excluded here {cite}",
            rule.path,
            root.display()
        )
    } else {
        format!(
            "`{}` is out of scope and was scanned, but discovery found no analyzable \
             file in it {cite}",
            rule.path
        )
    }
}

/// A one-line inventory of what was found, printed before analysis so a user
/// notices immediately if discovery picked up the wrong tree.
pub fn inventory(target: &Target) -> String {
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for f in &target.files {
        *counts.entry(f.language.to_string()).or_default() += 1;
    }
    let parts: Vec<String> = counts.iter().map(|(l, n)| format!("{n} {l}")).collect();
    if parts.is_empty() {
        format!("{}: no analyzable files found", target.root.display())
    } else {
        format!("{}: {}", target.root.display(), parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sda-discover-{name}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn collects_source_files_and_skips_build_output() {
        let d = scratch("basic");
        fs::create_dir_all(d.join("src")).unwrap();
        fs::create_dir_all(d.join("target/debug")).unwrap();
        fs::write(d.join("src/main.c"), "int main(void){return 0;}").unwrap();
        fs::write(d.join("src/lib.rs"), "pub fn f() {}").unwrap();
        fs::write(d.join("target/debug/generated.c"), "int x;").unwrap();
        fs::write(d.join("README.md"), "# hi").unwrap();

        let t = discover(&d, &DiscoveryOptions::default());
        let names: Vec<String> =
            t.files.iter().map(|f| f.path.file_name().unwrap().to_string_lossy().into()).collect();
        assert!(names.contains(&"main.c".to_string()));
        assert!(names.contains(&"lib.rs".to_string()));
        assert!(!names.contains(&"generated.c".to_string()), "build output must be skipped");
        assert_eq!(t.languages(), vec![Language::C, Language::Rust, Language::Other("md".into())]);

        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn language_filter_narrows_the_target() {
        let d = scratch("filter");
        fs::write(d.join("a.c"), "int x;").unwrap();
        fs::write(d.join("b.rs"), "fn f() {}").unwrap();

        let t = discover(&d, &DiscoveryOptions::default().only(vec![Language::Rust]));
        assert_eq!(t.files.len(), 1);
        assert_eq!(t.files[0].language, Language::Rust);

        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn model_artifacts_are_collected_regardless_of_size_limits() {
        let d = scratch("model");
        fs::write(d.join("tiny.gguf"), vec![0u8; 64]).unwrap();
        let opts = DiscoveryOptions { max_file_bytes: 1, ..Default::default() };
        let t = discover(&d, &opts);
        assert_eq!(t.files.len(), 1, "a model is exactly what we must not skip for being large");
        assert_eq!(t.files[0].language, Language::ModelArtifact);

        fs::remove_dir_all(&d).ok();
    }

    /// `sda build compile-commands` on a CMake project leaves the database in
    /// `build/`, and `sda build detect` reports it as present — but discovery
    /// looked only at the root, so the scan that was supposed to use it got
    /// nothing.
    #[test]
    fn a_database_in_the_build_directory_is_found_too() {
        let d = std::env::temp_dir().join("sda-discover-compdb");
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("build")).unwrap();
        fs::write(d.join("a.c"), "int main(void){return 0;}\n").unwrap();
        fs::write(d.join("build").join("compile_commands.json"), "[]").unwrap();

        let t = discover(&d, &DiscoveryOptions::default());
        assert_eq!(
            t.compile_commands,
            Some(d.join("build").join("compile_commands.json")),
            "the database CMake actually writes must be discovered"
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn compile_commands_are_picked_up_when_present() {
        let d = scratch("cc");
        fs::write(d.join("compile_commands.json"), "[]").unwrap();
        fs::write(d.join("a.c"), "int x;").unwrap();
        let t = discover(&d, &DiscoveryOptions::default());
        assert!(t.compile_commands.is_some());

        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn hidden_directories_are_skipped_by_default() {
        let d = scratch("hidden");
        fs::create_dir_all(d.join(".secret")).unwrap();
        fs::write(d.join(".secret/x.c"), "int x;").unwrap();
        assert!(discover(&d, &DiscoveryOptions::default()).files.is_empty());

        fs::remove_dir_all(&d).ok();
    }

    fn scope_of(toml: &str) -> sda_rules::ScopeRegister {
        sda_rules::ScopeRegister::parse(toml).unwrap()
    }

    /// The count is the whole safety property. A banner reading "`tests/`
    /// excluded" invites the reader to assume the directory was empty.
    #[test]
    fn out_of_scope_files_are_removed_and_the_notice_states_how_many() {
        let d = scratch("scope");
        fs::create_dir_all(d.join("tests")).unwrap();
        fs::create_dir_all(d.join("src")).unwrap();
        fs::write(d.join("src/main.c"), "int main(void){return 0;}").unwrap();
        fs::write(d.join("tests/a.c"), "int a;").unwrap();
        fs::write(d.join("tests/b.c"), "int b;").unwrap();

        let mut t = discover(&d, &DiscoveryOptions::default());
        assert_eq!(t.files.len(), 3);

        let notices = apply_scope(
            &mut t,
            &scope_of(
                "[[excluded]]\npath = \"tests/\"\n\
                 reason = \"unit test harness\"\napprover = \"a.erickson\"\n",
            ),
            &d,
        );

        assert_eq!(t.files.len(), 1, "the analyzers must never see the excluded files");
        assert!(t.files[0].path.ends_with("main.c"));
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].provider.as_str(), "sda.scope");
        assert!(notices[0].reason.contains("2 files"), "got: {}", notices[0].reason);
        assert!(notices[0].reason.contains("unit test harness"), "the rationale travels with it");
        assert!(notices[0].reason.contains("a.erickson"), "and so does the approver");

        fs::remove_dir_all(&d).ok();
    }

    /// A scope file drifts out of date silently otherwise: the directory it
    /// names gets renamed and the rule goes on looking like it is doing something.
    #[test]
    fn a_rule_that_matched_nothing_is_reported_as_possibly_stale() {
        let d = scratch("scope-stale");
        fs::write(d.join("main.c"), "int main(void){return 0;}").unwrap();

        let mut t = discover(&d, &DiscoveryOptions::default());
        let notices = apply_scope(
            &mut t,
            &scope_of(
                "[[excluded]]\npath = \"tests/\"\nreason = \"harness\"\napprover = \"a\"\n",
            ),
            &d,
        );

        assert_eq!(t.files.len(), 1);
        assert_eq!(notices.len(), 1, "a rule that removed nothing must still be reported");
        assert!(notices[0].reason.contains("stale"), "got: {}", notices[0].reason);

        fs::remove_dir_all(&d).ok();
    }

    /// An empty register is the default state of every project that has never
    /// written a `scope.toml`, and it must change nothing at all.
    #[test]
    fn an_empty_scope_removes_nothing_and_says_nothing() {
        let d = scratch("scope-empty");
        fs::write(d.join("main.c"), "int x;").unwrap();
        let mut t = discover(&d, &DiscoveryOptions::default());
        let notices = apply_scope(&mut t, &sda_rules::ScopeRegister::default(), &d);
        assert_eq!(t.files.len(), 1);
        assert!(notices.is_empty(), "silence is correct when nothing was excluded");
        fs::remove_dir_all(&d).ok();
    }

    /// Matching is on the path *relative to the anchor*, never on the absolute
    /// path. The absolute path of this scratch directory contains
    /// "sda-discover-scope-abs", and a rule reading `src/` must not be confused
    /// by anything above the project.
    #[test]
    fn matching_is_relative_to_the_declaration_not_absolute() {
        let d = scratch("scope-abs");
        fs::create_dir_all(d.join("src")).unwrap();
        fs::write(d.join("src/a.c"), "int a;").unwrap();
        fs::write(d.join("b.c"), "int b;").unwrap();

        let mut t = discover(&d, &DiscoveryOptions::default());
        let notices = apply_scope(
            &mut t,
            &scope_of("[[excluded]]\npath = \"src/\"\nreason = \"r\"\napprover = \"a\"\n"),
            &d,
        );
        assert_eq!(t.files.len(), 1);
        assert!(t.files[0].path.ends_with("b.c"));
        assert!(notices[0].reason.contains("1 file "), "got: {}", notices[0].reason);

        fs::remove_dir_all(&d).ok();
    }

    /// The rule that item 20 of the handoff turns on. `.sda/` is found by
    /// searching *upward*, so scanning a subdirectory of a configured project
    /// loads the project's declaration — and before the anchor existed, matched
    /// its project-relative rules against subdirectory-relative paths. Every
    /// rule then reported itself as possibly stale and every file it named was
    /// analysed, which is a scope declaration that silently does nothing.
    #[test]
    fn a_rule_means_the_same_thing_when_a_subdirectory_is_scanned() {
        let d = scratch("scope-anchor");
        fs::create_dir_all(d.join("tools/harness")).unwrap();
        fs::write(d.join("tools/harness/a.c"), "int a;").unwrap();
        fs::write(d.join("tools/harness/b.c"), "int b;").unwrap();

        let scope = scope_of(
            "[[excluded]]
path = \"tools/harness\"
reason = \"harness\"
approver = \"a\"
",
        );

        // The project root: the case that already worked.
        let mut whole = discover(&d, &DiscoveryOptions::default());
        let notices = apply_scope(&mut whole, &scope, &d);
        assert!(whole.files.is_empty());
        assert!(notices[0].reason.contains("2 files"), "got: {}", notices[0].reason);

        // The subdirectory: the same two files, the same declaration, and it
        // must reach the same answer rather than reporting a stale rule.
        let mut part = discover(d.join("tools"), &DiscoveryOptions::default());
        assert_eq!(part.files.len(), 2, "the fixture must have something to exclude");
        let notices = apply_scope(&mut part, &scope, &d);
        assert!(part.files.is_empty(), "the declaration governs these files however they are reached");
        assert!(notices[0].reason.contains("2 files"), "got: {}", notices[0].reason);

        fs::remove_dir_all(&d).ok();
    }

    /// The other half of the anchor: a file the declaration does not govern is
    /// left in scope. Matching it against the full path would let a rule reading
    /// `tools` exclude anything whose absolute path passes through a directory
    /// of that name, somewhere above the project.
    #[test]
    fn a_file_outside_the_anchor_is_not_excluded() {
        let d = scratch("scope-outside");
        fs::create_dir_all(d.join("tools")).unwrap();
        fs::write(d.join("tools/a.c"), "int a;").unwrap();

        let mut t = discover(&d, &DiscoveryOptions::default());
        assert_eq!(t.files.len(), 1);
        // An anchor pointing somewhere else entirely: nothing is under it.
        let notices = apply_scope(
            &mut t,
            &scope_of("[[excluded]]
path = \"tools\"
reason = \"r\"
approver = \"a\"
"),
            &d.join("elsewhere"),
        );
        assert_eq!(t.files.len(), 1, "an ungoverned file stays in scope");
        assert!(notices[0].reason.contains("stale"), "got: {}", notices[0].reason);

        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn inventory_is_readable_and_honest_about_emptiness() {
        let d = scratch("inv");
        let t = discover(&d, &DiscoveryOptions::default());
        assert!(inventory(&t).contains("no analyzable files"));
        fs::remove_dir_all(&d).ok();
    }
}
