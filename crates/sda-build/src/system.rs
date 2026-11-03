//! Build-system detection and driving.
//!
//! The toolkit needs three things from whatever build system a project uses:
//! a way to configure it, a way to build it, and — most valuable — a
//! `compile_commands.json` describing how each translation unit is actually
//! compiled. That last file is the universal interchange format for analysis
//! tooling, and generating one is often the single highest-leverage thing to do
//! to a project.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A build system the toolkit can recognise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuildSystem {
    Cargo,
    CMake,
    Meson,
    Ninja,
    Make,
    Bazel,
    MsBuild,
    /// Zephyr's `west`, which wraps CMake.
    West,
    /// PlatformIO, which wraps SCons.
    PlatformIo,
    Scons,
    Xmake,
    /// Keil uVision project.
    Keil,
    /// IAR Embedded Workbench project.
    IarEw,
}

/// A CMake generator that actually honours `CMAKE_EXPORT_COMPILE_COMMANDS`.
///
/// CMake supports that variable for the **Makefile and Ninja generators only**,
/// and ignores it silently everywhere else. The default generator on Windows is
/// Visual Studio, so leaving the choice to CMake meant the one command this
/// module exists to run configured the project, reported success, and produced
/// nothing — while `next_step` printed that same command to the user as the fix
/// for their unchecked guidelines.
///
/// Ninja first because it is the fastest and the most widely present where
/// anyone has thought about this; then the platform's make. `NMake Makefiles` is
/// the only Makefile generator that works on this class of Windows machine, and
/// it needs `cl` in the environment — see `vcvars_hint`.
pub fn cmake_generator() -> &'static str {
    if which("ninja").is_some() {
        return "Ninja";
    }
    if cfg!(windows) { "NMake Makefiles" } else { "Unix Makefiles" }
}

/// A note to add to a build failure when the toolchain is present but not on
/// the path, which on Windows is the normal state of affairs.
///
/// MSVC is never on `PATH` until `vcvars64.bat` has run, so CMake finds `cl.exe`
/// by its own search, fails its compiler test, and prints a wall of text whose
/// cause is not in the first few lines. Concluding "no C toolchain" from a bare
/// `PATH` is wrong, and has been concluded more than once on this machine.
pub fn vcvars_hint() -> Option<&'static str> {
    if cfg!(windows) && which("cl").is_none() {
        Some(
            "`cl` is not on PATH. MSVC never is until `vcvars64.bat` has run, and CMake's \
             Makefile generators need it in the environment — run the build from a developer \
             shell, or import that environment first",
        )
    } else {
        None
    }
}

/// Whether a program resolves on `PATH`.
fn which(program: &str) -> Option<std::path::PathBuf> {
    let exts: &[&str] = if cfg!(windows) { &[".exe", ".bat", ".cmd", ""] } else { &[""] };
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for ext in exts {
            let candidate = dir.join(format!("{program}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

impl BuildSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            BuildSystem::Cargo => "cargo",
            BuildSystem::CMake => "cmake",
            BuildSystem::Meson => "meson",
            BuildSystem::Ninja => "ninja",
            BuildSystem::Make => "make",
            BuildSystem::Bazel => "bazel",
            BuildSystem::MsBuild => "msbuild",
            BuildSystem::West => "west",
            BuildSystem::PlatformIo => "platformio",
            BuildSystem::Scons => "scons",
            BuildSystem::Xmake => "xmake",
            BuildSystem::Keil => "keil-uvision",
            BuildSystem::IarEw => "iar-embedded-workbench",
        }
    }

    /// The marker file that identifies this build system.
    pub fn marker(&self) -> &'static str {
        match self {
            BuildSystem::Cargo => "Cargo.toml",
            BuildSystem::CMake => "CMakeLists.txt",
            BuildSystem::Meson => "meson.build",
            BuildSystem::Ninja => "build.ninja",
            BuildSystem::Make => "Makefile",
            BuildSystem::Bazel => "WORKSPACE",
            BuildSystem::MsBuild => ".sln",
            BuildSystem::West => "west.yml",
            BuildSystem::PlatformIo => "platformio.ini",
            BuildSystem::Scons => "SConstruct",
            BuildSystem::Xmake => "xmake.lua",
            BuildSystem::Keil => ".uvprojx",
            BuildSystem::IarEw => ".ewp",
        }
    }

    /// Whether this build system can emit a `compile_commands.json`, and how.
    ///
    /// The `None` cases are the ones that hurt: a Keil or IAR project has the
    /// compile commands inside a vendor XML file, and extracting them is a
    /// separate job. Saying so is better than pretending the analysis is
    /// complete without them.
    pub fn compile_commands_recipe(&self) -> Option<String> {
        match self {
            BuildSystem::CMake => Some(format!(
                "cmake -S . -B build -G \"{}\" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                cmake_generator()
            )),
            BuildSystem::Meson => Some("meson setup build   # writes build/compile_commands.json".into()),
            BuildSystem::Ninja => Some("ninja -t compdb > compile_commands.json".into()),
            BuildSystem::Make => Some("bear -- make        # or `compiledb make`".into()),
            BuildSystem::Bazel => Some("bazel run @hedron_compile_commands//:refresh_all".into()),
            BuildSystem::West => Some("west build -- -DCMAKE_EXPORT_COMPILE_COMMANDS=ON".into()),
            BuildSystem::PlatformIo => Some("pio run -t compiledb".into()),
            BuildSystem::Scons => Some("bear -- scons".into()),
            BuildSystem::Xmake => Some("xmake project -k compile_commands".into()),
            // Cargo does not use compile_commands.json; the native Rust
            // provider does not need one.
            BuildSystem::Cargo => None,
            BuildSystem::MsBuild | BuildSystem::Keil | BuildSystem::IarEw => None,
        }
    }

    /// The command that generates a compilation database, when one can be run
    /// directly. `None` means either no database is needed (Cargo) or producing
    /// one requires a tool we will not silently assume is installed.
    ///
    /// The third element says whether the database arrives on stdout rather
    /// than being written to a file, which changes how the caller captures it.
    pub fn compile_commands_command(&self) -> Option<(String, Vec<String>, CompdbOutput)> {
        let owned = |p: &str, a: &[&str], o| {
            Some((p.to_string(), a.iter().map(|s| s.to_string()).collect(), o))
        };
        match self {
            // The generator is **named**, and that is not tidiness.
            // `CMAKE_EXPORT_COMPILE_COMMANDS` is supported only by the Makefile
            // and Ninja generators; every other generator ignores it in silence.
            // On a default Windows install the default generator is Visual
            // Studio, so this recipe configured the project, printed
            // "Generating done", exited 0 and wrote no database at all — and
            // `next_step` printed the same command to the user as the way to fix
            // their unchecked semantics guidelines. Verified against CMake 4.4
            // and "Visual Studio 18 2026": configure succeeds, the file does not
            // appear.
            BuildSystem::CMake => Some((
                "cmake".to_string(),
                vec![
                    "-S".into(),
                    ".".into(),
                    "-B".into(),
                    "build".into(),
                    "-G".into(),
                    cmake_generator().to_string(),
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON".into(),
                ],
                CompdbOutput::File,
            )),
            BuildSystem::Meson => owned("meson", &["setup", "build"], CompdbOutput::File),
            BuildSystem::Ninja => owned("ninja", &["-t", "compdb"], CompdbOutput::Stdout),
            BuildSystem::West => owned(
                "west",
                &["build", "--", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
                CompdbOutput::File,
            ),
            BuildSystem::PlatformIo => owned("pio", &["run", "-t", "compiledb"], CompdbOutput::File),
            BuildSystem::Xmake => {
                owned("xmake", &["project", "-k", "compile_commands"], CompdbOutput::File)
            }
            // Make, SCons and Bazel need `bear` or a Bazel extension; Cargo
            // needs nothing; the IDE projects keep their compile lines inside a
            // vendor file. Each is reported by `compile_commands_recipe`.
            _ => None,
        }
    }

    /// The diagnostic format this build system's output is in, when the build
    /// system dictates it rather than the compiler.
    ///
    /// Cargo is the case that matters: it drives rustc, so the probed C compiler
    /// on `PATH` says nothing about what its output looks like. Deriving the
    /// format from the compiler instead made `sda swe` report zero errors for a
    /// Rust project that does not compile — a clean result for a broken build,
    /// which is the worst kind of wrong answer this toolkit can give.
    pub fn diagnostic_format(&self) -> Option<crate::toolchain::DiagnosticFormat> {
        match self {
            BuildSystem::Cargo => Some(crate::toolchain::DiagnosticFormat::RustcJson),
            _ => None,
        }
    }

    /// The command that builds the project, as a program and arguments.
    pub fn build_command(&self) -> Option<(&'static str, Vec<&'static str>)> {
        match self {
            // `--message-format=json` is what makes the diagnostics parseable;
            // without it cargo prints prose that no format understands.
            BuildSystem::Cargo => Some(("cargo", vec!["build", "--message-format=json"])),
            BuildSystem::CMake => Some(("cmake", vec!["--build", "build"])),
            BuildSystem::Meson => Some(("meson", vec!["compile", "-C", "build"])),
            BuildSystem::Ninja => Some(("ninja", vec![])),
            BuildSystem::Make => Some(("make", vec![])),
            BuildSystem::Bazel => Some(("bazel", vec!["build", "//..."])),
            BuildSystem::MsBuild => Some(("msbuild", vec![])),
            BuildSystem::West => Some(("west", vec!["build"])),
            BuildSystem::PlatformIo => Some(("pio", vec!["run"])),
            BuildSystem::Scons => Some(("scons", vec![])),
            BuildSystem::Xmake => Some(("xmake", vec![])),
            BuildSystem::Keil | BuildSystem::IarEw => None,
        }
    }

    /// The command that runs the project's tests, when it has a standard one.
    pub fn test_command(&self) -> Option<(&'static str, Vec<&'static str>)> {
        match self {
            BuildSystem::Cargo => Some(("cargo", vec!["test"])),
            BuildSystem::CMake => Some(("ctest", vec!["--test-dir", "build", "--output-on-failure"])),
            BuildSystem::Meson => Some(("meson", vec!["test", "-C", "build"])),
            BuildSystem::Bazel => Some(("bazel", vec!["test", "//..."])),
            BuildSystem::Make => Some(("make", vec!["test"])),
            _ => None,
        }
    }

    fn all() -> &'static [BuildSystem] {
        use BuildSystem::*;
        // Ordered by specificity: `west` and `platformio` projects also contain
        // a CMakeLists.txt, and reporting the wrapper is more useful than
        // reporting what it wraps.
        &[
            West, PlatformIo, Cargo, Bazel, Meson, CMake, Xmake, Scons, Ninja, Make, MsBuild,
            Keil, IarEw,
        ]
    }
}

/// Where a compilation-database generator puts its output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompdbOutput {
    /// Written into the build tree, to be discovered afterwards.
    File,
    /// Printed to stdout, to be captured by the caller.
    Stdout,
}

/// A build system found in a project, with what was learned about it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectedBuild {
    pub system: BuildSystem,
    /// The marker file that identified it.
    pub marker: PathBuf,
    pub root: PathBuf,
    /// Existing `compile_commands.json`, if the project already has one.
    pub compile_commands: Option<PathBuf>,
}

impl DetectedBuild {
    /// What the operator should do next to make this project analyzable.
    pub fn next_step(&self) -> String {
        if self.compile_commands.is_some() {
            return format!(
                "`{}` is configured and a compile_commands.json is present; semantics-level checks \
                 can run against real compile lines.",
                self.system.as_str()
            );
        }
        match self.system.compile_commands_recipe() {
            Some(cmd) => format!(
                "No compile_commands.json. Generate one with:\n    {cmd}\nWithout it, guidelines \
                 needing type information cannot be checked and will be reported as unchecked.",
            ),
            None if self.system == BuildSystem::Cargo => {
                "Cargo projects need no compile_commands.json; the native Rust provider reads \
                 sources directly."
                    .into()
            }
            None => format!(
                "`{}` keeps its compile lines inside a vendor project file, so no \
                 compile_commands.json can be generated automatically. Export the build log and \
                 convert it, or supply compile lines manually; until then, semantics-level \
                 guidelines are unchecked.",
                self.system.as_str()
            ),
        }
    }
}

/// Detect every build system present at `root`.
pub fn detect(root: impl AsRef<Path>) -> Vec<DetectedBuild> {
    let root = root.as_ref();
    let mut found = Vec::new();

    for system in BuildSystem::all() {
        let marker = system.marker();
        let hit = if marker.starts_with('.') {
            // An extension marker: look for any file with it.
            std::fs::read_dir(root).ok().and_then(|entries| {
                entries
                    .flatten()
                    .map(|e| e.path())
                    .find(|p| p.extension().map(|e| format!(".{}", e.to_string_lossy())) == Some(marker.to_string()))
            })
        } else {
            let p = root.join(marker);
            p.exists().then_some(p)
        };

        if let Some(marker_path) = hit {
            found.push(DetectedBuild {
                system: *system,
                marker: marker_path,
                root: root.to_path_buf(),
                compile_commands: find_compile_commands(root),
            });
        }
    }
    found
}

/// Look for a `compile_commands.json` in the usual places.
///
/// Re-exported from `sda-core` so analysis discovery and the build system agree
/// on where a database can live; they did not, and a scan missed one that
/// `sda build detect` had just reported as present.
pub use sda_core::find_compile_commands;

// --- compile_commands.json -------------------------------------------------

/// One entry of a compilation database.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompileCommand {
    pub directory: String,
    pub file: String,
    /// Either `command` (a shell string) or `arguments` (a list) is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

/// A path with forward slashes, `.` and `..` resolved, and a lower-case drive letter.
fn normal_path(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    let rooted = slashed.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in slashed.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|p| *p != "..") => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    let joined = parts.join("/");
    let joined = match joined.as_bytes() {
        [drive, b':', ..] => format!("{}{}", drive.to_ascii_lowercase() as char, &joined[1..]),
        _ => joined,
    };
    if rooted { format!("/{joined}") } else { joined }
}

impl CompileCommand {
    /// The entry's file as a normal path, joined to `directory` when relative.
    fn resolved_file(&self) -> String {
        let file = self.file.replace('\\', "/");
        let absolute = file.starts_with('/') || file.as_bytes().get(1) == Some(&b':');
        if absolute || self.directory.is_empty() {
            normal_path(&file)
        } else {
            normal_path(&format!("{}/{file}", self.directory))
        }
    }

    /// The argument vector, however the entry spelled it.
    pub fn argv(&self) -> Vec<String> {
        if let Some(args) = &self.arguments {
            return args.clone();
        }
        self.command.as_deref().map(split_command).unwrap_or_default()
    }

    /// The compiler this translation unit is built with.
    pub fn compiler(&self) -> Option<String> {
        self.argv().first().cloned()
    }

    /// Include directories, as written.
    pub fn includes(&self) -> Vec<String> {
        let argv = self.argv();
        let mut out = Vec::new();
        let mut i = 0;
        while i < argv.len() {
            let a = &argv[i];
            if a == "-I" || a == "-isystem" || a == "/I" {
                if let Some(next) = argv.get(i + 1) {
                    out.push(next.clone());
                }
                i += 2;
                continue;
            }
            if let Some(rest) = a.strip_prefix("-I") {
                out.push(rest.to_string());
            } else if let Some(rest) = a.strip_prefix("/I") {
                out.push(rest.to_string());
            }
            i += 1;
        }
        out
    }

    /// Macro definitions, as `(name, value)` pairs.
    pub fn defines(&self) -> Vec<(String, Option<String>)> {
        let argv = self.argv();
        let mut out = Vec::new();
        let mut i = 0;
        while i < argv.len() {
            let a = &argv[i];
            let body = if a == "-D" || a == "/D" {
                i += 1;
                argv.get(i).cloned()
            } else {
                a.strip_prefix("-D").or_else(|| a.strip_prefix("/D")).map(|s| s.to_string())
            };
            if let Some(b) = body {
                match b.split_once('=') {
                    Some((k, v)) => out.push((k.to_string(), Some(v.to_string()))),
                    None => out.push((b, None)),
                }
            }
            i += 1;
        }
        out
    }

    /// The language standard requested, e.g. `c23` or `c++23`.
    pub fn standard(&self) -> Option<String> {
        for a in self.argv() {
            if let Some(rest) = a.strip_prefix("-std=") {
                return Some(rest.to_string());
            }
            if let Some(rest) = a.strip_prefix("/std:") {
                return Some(rest.to_string());
            }
        }
        None
    }
}

/// A parsed compilation database.
#[derive(Clone, Debug, Default)]
pub struct CompilationDatabase {
    pub entries: Vec<CompileCommand>,
}

impl CompilationDatabase {
    pub fn parse(json: &str) -> Result<CompilationDatabase, String> {
        let entries: Vec<CompileCommand> =
            serde_json::from_str(json).map_err(|e| format!("compile_commands.json is not valid: {e}"))?;
        Ok(CompilationDatabase { entries })
    }

    pub fn load(path: &Path) -> Result<CompilationDatabase, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read {}: {e}", path.display()))?;
        CompilationDatabase::parse(&text)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    ///
    /// An exact path wins over a suffix, and a suffix must start at a path
    /// component: `bar.c` is not a compile line for `foobar.c`. A relative `file`
    /// is relative to the entry's `directory`, as the format says.
    pub fn for_file(&self, path: &Path) -> Option<&CompileCommand> {
        let want = normal_path(&path.to_string_lossy());
        let resolved: Vec<String> = self.entries.iter().map(CompileCommand::resolved_file).collect();
        let at = resolved.iter().position(|have| *have == want).or_else(|| {
            resolved.iter().position(|have| {
                have.ends_with(&format!("/{want}")) || want.ends_with(&format!("/{have}"))
            })
        })?;
        self.entries.get(at)
    }

    /// Distinct compilers used across the database. More than one is worth
    /// knowing about: a project built with two toolchains has two sets of
    /// implementation-defined behaviour to document.
    pub fn compilers(&self) -> Vec<String> {
        let mut v: Vec<String> = self.entries.iter().filter_map(|e| e.compiler()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Source files that appear in the tree but not in the database — the
    /// translation units no semantics-level check will ever see.
    pub fn missing_from(&self, files: &[PathBuf]) -> Vec<PathBuf> {
        files.iter().filter(|f| self.for_file(f).is_none()).cloned().collect()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.entries).unwrap_or_else(|_| "[]".into())
    }
}

/// Split a shell-style command string, honouring quotes.
fn split_command(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for c in s.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if quote != Some('\'') => escaped = true,
            '"' | '\'' if quote.is_none() => quote = Some(c),
            c if Some(c) == quote => quote = None,
            c if c.is_whitespace() && quote.is_none() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// `CMAKE_EXPORT_COMPILE_COMMANDS` is honoured by the Makefile and Ninja
    /// generators and ignored **in silence** by every other one. Leaving the
    /// choice to CMake means the Visual Studio generator on Windows, which is
    /// why `sda build compile-commands` configured llama.cpp, printed
    /// "Generating done", exited 0 and produced no database at all.
    #[test]
    fn the_cmake_generator_is_one_that_honours_the_export_flag() {
        let g = cmake_generator();
        assert!(
            matches!(g, "Ninja" | "NMake Makefiles" | "Unix Makefiles"),
            "`{g}` is not a generator that exports a compilation database"
        );
        assert!(!g.starts_with("Visual Studio"), "the failure this exists to prevent");
    }

    /// The advice and the action must describe the same command.
    ///
    /// `next_step` prints `compile_commands_recipe` to the user as the way to
    /// fix their unchecked guidelines; `compdb::generate` runs
    /// `compile_commands_command`. They are separate code and they drifted:
    /// after the generator was added to one, a user following the other would
    /// still have run the command that produces nothing.
    #[test]
    fn the_recipe_and_the_command_agree_about_cmake() {
        let recipe = BuildSystem::CMake.compile_commands_recipe().expect("cmake has a recipe");
        let (program, args, _) =
            BuildSystem::CMake.compile_commands_command().expect("and a command");

        assert!(recipe.starts_with(&program), "the recipe must name the program it runs");
        for token in ["-G", cmake_generator(), "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"] {
            assert!(recipe.contains(token), "the recipe omits `{token}`: {recipe}");
            assert!(
                args.iter().any(|a| a == token),
                "the command omits `{token}`: {args:?}"
            );
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sda-build-{name}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn detects_cmake_and_reports_how_to_get_compile_commands() {
        let d = scratch("cmake");
        fs::write(d.join("CMakeLists.txt"), "project(x)").unwrap();
        let found = detect(&d);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].system, BuildSystem::CMake);
        assert!(found[0].next_step().contains("CMAKE_EXPORT_COMPILE_COMMANDS"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_zephyr_project_reports_west_before_the_cmake_it_wraps() {
        let d = scratch("west");
        fs::write(d.join("west.yml"), "manifest:").unwrap();
        fs::write(d.join("CMakeLists.txt"), "project(x)").unwrap();
        let found = detect(&d);
        assert_eq!(found[0].system, BuildSystem::West, "the wrapper is the useful answer");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn vendor_ide_projects_are_detected_and_their_limits_stated() {
        let d = scratch("keil");
        fs::write(d.join("firmware.uvprojx"), "<Project/>").unwrap();
        let found = detect(&d);
        assert_eq!(found[0].system, BuildSystem::Keil);
        assert!(found[0].next_step().contains("unchecked"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_existing_compile_commands_changes_the_advice() {
        let d = scratch("cc-present");
        fs::write(d.join("CMakeLists.txt"), "project(x)").unwrap();
        fs::write(d.join("compile_commands.json"), "[]").unwrap();
        let found = detect(&d);
        assert!(found[0].compile_commands.is_some());
        assert!(found[0].next_step().contains("can run against real compile lines"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn parses_both_command_and_arguments_forms() {
        let db = CompilationDatabase::parse(
            r#"[
              {"directory":"/b","file":"a.c","command":"gcc -I/inc -DDEBUG=1 -std=c23 -c a.c"},
              {"directory":"/b","file":"b.c","arguments":["clang","-Iinc2","-DNDEBUG","-c","b.c"]}
            ]"#,
        )
        .unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db.entries[0].compiler(), Some("gcc".to_string()));
        assert_eq!(db.entries[0].includes(), vec!["/inc"]);
        assert_eq!(db.entries[0].standard(), Some("c23".to_string()));
        assert_eq!(db.entries[1].compiler(), Some("clang".to_string()));
        assert_eq!(db.entries[1].includes(), vec!["inc2"]);
    }

    #[test]
    fn extracts_defines_with_and_without_values() {
        let db = CompilationDatabase::parse(
            r#"[{"directory":"/b","file":"a.c","command":"gcc -DDEBUG=1 -DNDEBUG -D VERSION=3 -c a.c"}]"#,
        )
        .unwrap();
        let d = db.entries[0].defines();
        assert!(d.contains(&("DEBUG".into(), Some("1".into()))));
        assert!(d.contains(&("NDEBUG".into(), None)));
        assert!(d.contains(&("VERSION".into(), Some("3".into()))), "separated -D form: {d:?}");
    }

    #[test]
    fn quoted_paths_survive_command_splitting() {
        let argv = split_command(r#"gcc -I"C:/Program Files/inc" -c a.c"#);
        assert_eq!(argv[1], "-IC:/Program Files/inc");
        assert_eq!(argv.len(), 4);
    }

    #[test]
    fn lookup_tolerates_absolute_and_relative_paths() {
        let db = CompilationDatabase::parse(
            r#"[{"directory":"/proj","file":"/proj/src/a.c","command":"gcc -c a.c"}]"#,
        )
        .unwrap();
        assert!(db.for_file(Path::new("src/a.c")).is_some());
        assert!(db.for_file(Path::new("/proj/src/a.c")).is_some());
        assert!(db.for_file(Path::new("src/other.c")).is_none());
    }

    #[test]
    fn files_absent_from_the_database_are_reported() {
        let db = CompilationDatabase::parse(
            r#"[{"directory":"/p","file":"/p/a.c","command":"gcc -c a.c"}]"#,
        )
        .unwrap();
        let missing = db.missing_from(&[PathBuf::from("/p/a.c"), PathBuf::from("/p/b.c")]);
        assert_eq!(missing, vec![PathBuf::from("/p/b.c")]);
    }

    #[test]
    fn multiple_compilers_in_one_database_are_surfaced() {
        let db = CompilationDatabase::parse(
            r#"[
              {"directory":"/b","file":"a.c","command":"arm-none-eabi-gcc -c a.c"},
              {"directory":"/b","file":"b.c","command":"gcc -c b.c"}
            ]"#,
        )
        .unwrap();
        assert_eq!(db.compilers().len(), 2);
    }

    #[test]
    fn malformed_databases_produce_a_readable_error() {
        assert!(CompilationDatabase::parse("not json").unwrap_err().contains("not valid"));
    }

    #[test]
    fn every_build_system_states_whether_it_can_be_driven() {
        for s in BuildSystem::all() {
            // Either we can build it or we explain why not; no silent gaps.
            let drivable = s.build_command().is_some();
            let vendor_ide = matches!(s, BuildSystem::Keil | BuildSystem::IarEw);
            assert_eq!(drivable, !vendor_ide, "{s:?}");
        }
    }
}
