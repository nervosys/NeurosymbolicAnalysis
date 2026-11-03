//! Producing a `compile_commands.json`.
//!
//! This is the single highest-leverage thing that can be done to a C or C++
//! project for analysis purposes. Without it, every guideline needing type
//! information is unchecked — 87 of them in MISRA C:2023 — and no type-aware
//! tool can do better than guess at the build configuration.
//!
//! Two routes, and the difference between them is stated loudly wherever the
//! result is used:
//!
//! * **Generated** by the project's own build system, which knows the real
//!   include paths, macro definitions and language standard.
//! * **Synthesized** by walking the source tree and guessing, for projects whose
//!   build lives inside a vendor IDE file. Better than nothing, and clearly
//!   worse than the real thing.

use crate::system::{BuildSystem, CompdbOutput, DetectedBuild};
use crate::toolchain::Compiler;
use serde_json::json;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How a database came to exist, which determines how far its results can be trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Emitted by the project's own build system. Authoritative.
    Generated,
    /// Guessed from the source tree. Include paths and macros are approximations.
    Synthesized,
    /// Already present before we did anything.
    PreExisting,
}

impl Provenance {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provenance::Generated => "generated",
            Provenance::Synthesized => "synthesized",
            Provenance::PreExisting => "pre-existing",
        }
    }

    /// What analysis built on this database is worth.
    pub fn caveat(&self) -> &'static str {
        match self {
            Provenance::Generated | Provenance::PreExisting => {
                "compile lines came from the build system and reflect the real configuration"
            }
            Provenance::Synthesized => {
                "compile lines were GUESSED from the source tree: include paths, macro definitions \
                 and the language standard are approximations, so type-aware findings derived from \
                 them may be wrong in either direction. Generate a real database if you can"
            }
        }
    }
}

/// The outcome of asking for a compilation database.
#[derive(Clone, Debug)]
pub struct CompdbResult {
    pub path: PathBuf,
    pub provenance: Provenance,
    pub entries: usize,
    /// Source files present in the tree but absent from the database — the
    /// translation units that no semantics-level check will ever see.
    pub uncovered: Vec<PathBuf>,
    /// Total C/C++ sources found in the tree.
    pub sources: usize,
}

impl CompdbResult {
    /// Fraction of the tree the database actually covers.
    pub fn coverage(&self) -> f32 {
        if self.sources == 0 {
            return 1.0;
        }
        (self.sources - self.uncovered.len()) as f32 / self.sources as f32
    }

    /// A report an operator can act on.
    pub fn summary(&self) -> String {
        let pct = (self.coverage() * 100.0).round() as u32;
        let mut s = format!(
            "{} ({}): {} translation unit(s), covering {pct}% of the {} C/C++ source file(s) found.",
            self.path.display(),
            self.provenance.as_str(),
            self.entries,
            self.sources,
        );
        if !self.uncovered.is_empty() {
            s.push_str(&format!(
                "\n{} file(s) are absent from the database and will not be checked by any \
                 type-aware provider, starting with: {}",
                self.uncovered.len(),
                self.uncovered
                    .iter()
                    .take(5)
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        s.push_str(&format!("\nProvenance: {}.", self.provenance.caveat()));
        s
    }
}

/// What a compilation database supplied to an *analysis* actually covers.
///
/// [`CompdbResult`] answers this for a database we just produced.
/// This answers it for one handed in from outside, which is the case that was
/// never asked: `sda scan --compile-commands` checked that the file existed and
/// nothing more. A database naming files this machine does not have — built in
/// a container, on another checkout path, or under WSL, where every entry reads
/// `/mnt/c/...` while the analyzer sees `C:/...` — was accepted in silence, and
/// the run then looked exactly like one with no database at all, except that the
/// operator believed type-aware analysis had become possible.
#[derive(Clone, Debug)]
pub struct SuppliedCoverage {
    pub entries: usize,
    pub covered: usize,
    pub sources: usize,
    /// A few of the uncovered files, relative to the root, for the message.
    pub examples: Vec<String>,
}

impl SuppliedCoverage {
    /// The reason to record in `NOT CHECKED`, or `None` when nothing is missing.
    ///
    /// A database that covers everything needs no notice: the absence of one is
    /// the claim that type-aware analysis can see the whole tree.
    pub fn shortfall(&self, db_path: &Path) -> Option<String> {
        let missing = self.sources.saturating_sub(self.covered);
        if missing == 0 {
            return None;
        }
        Some(format!(
            "`{}` covers {} of {} C/C++ source file(s); the other {missing} are invisible to every type-aware provider, starting with: {}",
            db_path.display(),
            self.covered,
            self.sources,
            self.examples.join(", ")
        ))
    }
}

/// Measure a supplied database against the tree it is supposed to describe.
pub fn supplied_coverage(db_path: &Path, root: &Path) -> Result<SuppliedCoverage, String> {
    let db = crate::system::CompilationDatabase::load(db_path)?;
    let sources = source_files(root);
    let uncovered = db.missing_from(&sources);
    let examples = uncovered
        .iter()
        .take(3)
        .map(|p| p.strip_prefix(root).unwrap_or(p).display().to_string())
        .collect();
    Ok(SuppliedCoverage {
        entries: db.len(),
        covered: sources.len() - uncovered.len(),
        sources: sources.len(),
        examples,
    })
}

/// Source extensions that belong in a compilation database. Headers do not:
/// they are compiled as part of a translation unit, not on their own.
const SOURCE_EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx", "c++"];

/// Every C/C++ source file under `root`, skipping build output.
pub fn source_files(root: &Path) -> Vec<PathBuf> {
    let skip: BTreeSet<&str> = [
        ".git", "target", "build", "out", "dist", "node_modules", "cmake-build-debug",
        "cmake-build-release", "third_party", "vendor", "external",
    ]
    .into_iter()
    .collect();

    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if !skip.contains(name.as_str()) && !name.starts_with('.') {
                    stack.push(path);
                }
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if SOURCE_EXTENSIONS.contains(&ext.as_str()) {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Run the project's own generator.
pub fn generate(
    detected: &DetectedBuild,
    timeout: Duration,
) -> Result<CompdbResult, String> {
    let Some((program, args, output)) = detected.system.compile_commands_command() else {
        return Err(match detected.system.compile_commands_recipe() {
            Some(recipe) => format!(
                "`{}` cannot emit a compilation database on its own. Run this, then re-scan:\n    \
                 {recipe}",
                detected.system.as_str()
            ),
            None if detected.system == BuildSystem::Cargo => {
                "Cargo projects need no compilation database; the native Rust provider reads \
                 sources directly."
                    .into()
            }
            None => format!(
                "`{}` keeps its compile lines inside a vendor project file, so no database can be \
                 generated from it. Use `--synthesize` to approximate one from the source tree, \
                 accepting that include paths and macros will be guesses.",
                detected.system.as_str()
            ),
        });
    };

    let outcome = crate::exec::run_command(
        &program,
        &args,
        &detected.root,
        &Default::default(),
        crate::toolchain::DiagnosticFormat::GccLike,
        timeout,
    )?;

    if !outcome.success {
        // The **tail**, not the head. A build tool states the failure first and
        // the reason afterwards: CMake prints "CMake Error at ...", then the
        // command it tried, then — several lines later — why it did not work.
        // Taking the first five lines cut the message off exactly before the
        // diagnosis, leaving a file and a line number inside CMake's own
        // sources, which is the least useful true thing available. Met on a real
        // project: the report named CMakeTestCCompiler.cmake:65 and stopped.
        let lines: Vec<&str> = outcome.stderr.lines().filter(|l| !l.trim().is_empty()).collect();
        const KEEP: usize = 20;
        let shown = lines[lines.len().saturating_sub(KEEP)..].join("\n");
        let elided = match lines.len().saturating_sub(KEEP) {
            0 => String::new(),
            n => format!("\n  ({n} earlier line(s) not shown)"),
        };
        // The toolchain being present but not on the path is the normal state of
        // a Windows machine, and it is not visible in what CMake prints.
        let hint = match crate::system::vcvars_hint() {
            Some(h) => format!("\n\n{h}."),
            None => String::new(),
        };
        return Err(format!("`{}` failed:{elided}\n{shown}{hint}", outcome.command));
    }

    let path = match output {
        CompdbOutput::Stdout => {
            let path = detected.root.join("compile_commands.json");
            // A checkout can commit `compile_commands.json` as a link to anywhere.
            sda_core::safe_write::write_refusing_symlinks(&path, &outcome.stdout)
                .map_err(|e| format!("could not write {}: {e}", path.display()))?;
            path
        }
        CompdbOutput::File => crate::system::find_compile_commands(&detected.root).ok_or_else(
            || {
                format!(
                    "`{}` reported success but no compile_commands.json appeared. \
                     `CMAKE_EXPORT_COMPILE_COMMANDS` is honoured only by the Makefile and Ninja \
                     generators and ignored in silence by every other one, so this is what a \
                     Visual Studio or Xcode generator does — check which generator the build \
                     directory was configured with",
                    outcome.command
                )
            },
        )?,
    };

    assess(&path, &detected.root, Provenance::Generated)
}

/// Build an approximate database by walking the source tree.
///
/// For Keil, IAR and anything else whose build lives in a vendor file. The
/// result is explicitly marked [`Provenance::Synthesized`] so nothing downstream
/// can mistake a guess for the real configuration.
pub fn synthesize(
    root: &Path,
    compiler: Option<&Compiler>,
    extra_flags: &[String],
) -> Result<CompdbResult, String> {
    let sources = source_files(root);
    if sources.is_empty() {
        return Err(format!("no C or C++ source files found under {}", root.display()));
    }

    let cc = compiler
        .map(|c| c.path.to_string_lossy().to_string())
        .unwrap_or_else(|| "cc".to_string());

    // Every directory containing a header is a plausible include root. Crude,
    // and far better than an empty include path, which makes every `#include`
    // unresolvable and every type unknown.
    let include_dirs = header_directories(root);

    let entries: Vec<serde_json::Value> = sources
        .iter()
        .map(|src| {
            let is_cpp = src
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e != "c");
            let mut argv = vec![cc.clone()];
            argv.push(if is_cpp { "-std=c++23".into() } else { "-std=c23".into() });
            for dir in &include_dirs {
                argv.push(format!("-I{}", dir.display()));
            }
            argv.extend(extra_flags.iter().cloned());
            argv.push("-c".into());
            argv.push(src.to_string_lossy().to_string());

            json!({
                "directory": root.to_string_lossy(),
                "file": src.to_string_lossy(),
                "arguments": argv,
            })
        })
        .collect();

    let path = root.join("compile_commands.json");
    sda_core::safe_write::write_refusing_symlinks(
        &path,
        serde_json::to_string_pretty(&entries).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("could not write {}: {e}", path.display()))?;

    assess(&path, root, Provenance::Synthesized)
}

/// Directories containing headers, deduplicated, capped so a pathological tree
/// cannot produce a command line no compiler will accept.
fn header_directories(root: &Path) -> Vec<PathBuf> {
    let mut dirs = BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if !name.starts_with('.') && name != "target" && name != "build" {
                    stack.push(path);
                }
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("h" | "hpp" | "hh" | "hxx")
            ) {
                dirs.insert(dir.clone());
            }
        }
    }
    dirs.into_iter().take(64).collect()
}

/// Read a database back and measure what it covers.
pub fn assess(path: &Path, root: &Path, provenance: Provenance) -> Result<CompdbResult, String> {
    let db = crate::system::CompilationDatabase::load(path)?;
    let sources = source_files(root);
    let uncovered = db.missing_from(&sources);
    Ok(CompdbResult {
        path: path.to_path_buf(),
        provenance,
        entries: db.len(),
        uncovered,
        sources: sources.len(),
    })
}

/// Produce a database however possible: use one that exists, generate one, or —
/// only when asked — synthesize one.
pub fn ensure(
    detected: &DetectedBuild,
    compiler: Option<&Compiler>,
    allow_synthesis: bool,
    timeout: Duration,
) -> Result<CompdbResult, String> {
    if let Some(existing) = crate::system::find_compile_commands(&detected.root) {
        return assess(&existing, &detected.root, Provenance::PreExisting);
    }
    match generate(detected, timeout) {
        Ok(result) => Ok(result),
        Err(e) if allow_synthesis => synthesize(&detected.root, compiler, &[])
            .map_err(|se| format!("generation failed ({e}); synthesis also failed: {se}")),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sda-compdb-{name}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn detected(system: BuildSystem, root: &Path) -> DetectedBuild {
        DetectedBuild {
            system,
            marker: root.join(system.marker()),
            root: root.to_path_buf(),
            compile_commands: None,
        }
    }

    #[test]
    fn finds_sources_but_not_headers_or_build_output() {
        let d = scratch("sources");
        fs::create_dir_all(d.join("src")).unwrap();
        fs::create_dir_all(d.join("build")).unwrap();
        fs::write(d.join("src/a.c"), "int a;").unwrap();
        fs::write(d.join("src/b.cpp"), "int b;").unwrap();
        fs::write(d.join("src/c.h"), "int c;").unwrap();
        fs::write(d.join("build/generated.c"), "int g;").unwrap();

        let found = source_files(&d);
        assert_eq!(found.len(), 2, "headers and build output are not translation units");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn synthesis_produces_a_usable_database_and_marks_it_as_a_guess() {
        let d = scratch("synth");
        fs::create_dir_all(d.join("src")).unwrap();
        fs::create_dir_all(d.join("include")).unwrap();
        fs::write(d.join("src/main.c"), "int main(void){return 0;}").unwrap();
        fs::write(d.join("include/api.h"), "int f(void);").unwrap();

        let r = synthesize(&d, None, &[]).unwrap();
        assert_eq!(r.provenance, Provenance::Synthesized);
        assert_eq!(r.entries, 1);
        assert!(r.uncovered.is_empty());

        // The include directory was discovered and the standard was set.
        let db = crate::system::CompilationDatabase::load(&r.path).unwrap();
        let entry = db.for_file(Path::new("src/main.c")).unwrap();
        assert_eq!(entry.standard().as_deref(), Some("c23"));
        assert!(entry.includes().iter().any(|i| i.contains("include")));

        assert!(r.summary().contains("GUESSED"), "the guess must be stated: {}", r.summary());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn cpp_sources_get_the_cpp_standard() {
        let d = scratch("synth-cpp");
        fs::write(d.join("main.cpp"), "int main(){}").unwrap();
        let r = synthesize(&d, None, &[]).unwrap();
        let db = crate::system::CompilationDatabase::load(&r.path).unwrap();
        assert_eq!(db.entries[0].standard().as_deref(), Some("c++23"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn synthesis_refuses_when_there_is_nothing_to_describe() {
        let d = scratch("synth-empty");
        assert!(synthesize(&d, None, &[]).unwrap_err().contains("no C or C++ source"));
        fs::remove_dir_all(&d).ok();
    }

    /// A database from another machine covers nothing, and must say so.
    ///
    /// The paths here are what WSL writes for a Windows tree. Nothing resolves,
    /// so every source is uncovered — and before `supplied_coverage` existed,
    /// `sda scan --compile-commands` reported none of it, because it checked
    /// only that the file was there.
    #[test]
    fn a_database_from_elsewhere_covers_nothing_and_says_so() {
        let d = scratch("supplied");
        fs::write(d.join("a.c"), "int a;").unwrap();
        fs::write(d.join("b.c"), "int b;").unwrap();
        let db = d.join("compile_commands.json");
        fs::write(
            &db,
            r#"[{"directory":"/mnt/c/elsewhere","file":"/mnt/c/elsewhere/a.c","command":"cc -c a.c"},
                {"directory":"/mnt/c/elsewhere","file":"/mnt/c/elsewhere/b.c","command":"cc -c b.c"}]"#,
        )
        .unwrap();

        let c = supplied_coverage(&db, &d).expect("a readable database");
        assert_eq!((c.entries, c.covered, c.sources), (2, 0, 2));
        let why = c.shortfall(&db).expect("a database covering nothing is a shortfall");
        assert!(why.contains("covers 0 of 2"), "{why}");
        assert!(why.contains("invisible to every type-aware provider"), "{why}");
    }

    /// And one that covers the tree says nothing, because there is nothing to say.
    #[test]
    fn a_database_that_covers_the_tree_raises_no_notice() {
        let d = scratch("supplied-full");
        fs::write(d.join("a.c"), "int a;").unwrap();
        let db = d.join("compile_commands.json");
        let dir = d.display().to_string().replace('\\', "/");
        fs::write(
            &db,
            format!(r#"[{{"directory":"{dir}","file":"{dir}/a.c","command":"cc -c a.c"}}]"#),
        )
        .unwrap();

        let c = supplied_coverage(&db, &d).expect("a readable database");
        assert_eq!((c.covered, c.sources), (1, 1));
        assert!(c.shortfall(&db).is_none(), "nothing is missing, so nothing is reported");
    }

    /// A database that cannot be read is not a database that covers everything.
    #[test]
    fn an_unreadable_database_is_an_error_not_a_silence() {
        let d = scratch("supplied-bad");
        let db = d.join("compile_commands.json");
        fs::write(&db, "{ this is not a database }").unwrap();
        assert!(supplied_coverage(&db, &d).is_err());
    }

    #[test]
    fn a_compile_line_belongs_to_one_file() {
        let db = crate::system::CompilationDatabase::parse(
            r#"[
                {"directory": "/proj/build", "file": "../src/a.c", "command": "cc a"},
                {"directory": "/proj/src", "file": "bar.c", "command": "cc bar"},
                {"directory": "/proj/tests", "file": "util.c", "command": "cc tests"},
                {"directory": "/proj/src", "file": "/proj/src/util.c", "command": "cc src"}
            ]"#,
        )
        .unwrap();
        assert!(db.for_file(Path::new("/proj/src/a.c")).is_some(), "relative to its directory");
        assert!(db.for_file(Path::new("/proj/other/foobar.c")).is_none(), "a different file");
        assert!(db.for_file(Path::new("/proj/mysrc/a.c")).is_none(), "a different directory");
        let exact = db.for_file(Path::new("/proj/src/util.c")).unwrap();
        assert_eq!(exact.command.as_deref(), Some("cc src"), "the exact entry, not the first");
    }

    #[test]
    fn coverage_reports_the_files_no_type_aware_check_will_see() {
        let d = scratch("coverage");
        fs::write(d.join("covered.c"), "int a;").unwrap();
        fs::write(d.join("missing.c"), "int b;").unwrap();
        let db = format!(
            r#"[{{"directory":"{}","file":"{}","command":"cc -c covered.c"}}]"#,
            d.display().to_string().replace('\\', "/"),
            d.join("covered.c").display().to_string().replace('\\', "/")
        );
        let path = d.join("compile_commands.json");
        fs::write(&path, db).unwrap();

        let r = assess(&path, &d, Provenance::PreExisting).unwrap();
        assert_eq!(r.entries, 1);
        assert_eq!(r.uncovered.len(), 1);
        assert!((r.coverage() - 0.5).abs() < 0.01);
        assert!(r.summary().contains("50%"));
        assert!(r.summary().contains("will not be checked"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_existing_database_is_used_rather_than_regenerated() {
        let d = scratch("existing");
        fs::write(d.join("a.c"), "int a;").unwrap();
        fs::write(
            d.join("compile_commands.json"),
            format!(
                r#"[{{"directory":".","file":"{}","command":"cc -c a.c"}}]"#,
                d.join("a.c").display().to_string().replace('\\', "/")
            ),
        )
        .unwrap();

        let r = ensure(&detected(BuildSystem::CMake, &d), None, false, Duration::from_secs(5))
            .unwrap();
        assert_eq!(r.provenance, Provenance::PreExisting);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_vendor_ide_project_explains_itself_and_offers_synthesis() {
        let d = scratch("keil");
        fs::write(d.join("a.c"), "int a;").unwrap();
        let err = generate(&detected(BuildSystem::Keil, &d), Duration::from_secs(5)).unwrap_err();
        assert!(err.contains("vendor project file"));
        assert!(err.contains("--synthesize"));

        // ...and with synthesis allowed, it produces one anyway.
        let r = ensure(&detected(BuildSystem::Keil, &d), None, true, Duration::from_secs(5))
            .unwrap();
        assert_eq!(r.provenance, Provenance::Synthesized);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_cargo_project_is_told_it_needs_no_database() {
        let d = scratch("cargo");
        let err = generate(&detected(BuildSystem::Cargo, &d), Duration::from_secs(5)).unwrap_err();
        assert!(err.contains("need no compilation database"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn systems_needing_an_external_tool_print_the_recipe() {
        let d = scratch("make");
        let err = generate(&detected(BuildSystem::Make, &d), Duration::from_secs(5)).unwrap_err();
        assert!(err.contains("bear"), "the recipe must be shown: {err}");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn provenance_governs_how_far_results_can_be_trusted() {
        assert!(Provenance::Generated.caveat().contains("real configuration"));
        assert!(Provenance::Synthesized.caveat().contains("GUESSED"));
    }
}
