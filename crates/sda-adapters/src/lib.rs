//! Adapters for industry-standard analysis tools.
//!
//! These implement the same [`Analyzer`] trait as the native engines, so from
//! the orchestrator's point of view there is no difference — except that they
//! are [`ProviderOrigin::External`], and the default [`SelectionPolicy`] leaves
//! them out until the operator opts in.
//!
//! That default is a deliberate product decision, not a limitation. A first run
//! on a new machine should produce real results, not a list of things to install;
//! and a compliance run should be reproducible, which it is not if it depends on
//! whichever version of a tool happens to be on `PATH`. Teams whose process
//! mandates a specific checker enable it explicitly, and the report records that
//! they did.
//!
//! Each adapter is responsible for three things, and the third is the one that
//! matters: run the tool, parse its output into [`Finding`]s, and report
//! honestly when it is not installed or its output could not be understood.

#![forbid(unsafe_code)]

use sda_core::{
    Analyzer, AnalyzerKind, Availability, Capability, Confidence, Evidence, Finding, Language,
    Location, ProviderInfo, ProviderOrigin, RunOptions, Severity, Target, TaxonomyRef,
};
use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

pub mod parse;

pub use parse::{
    VerusRun, parse_clippy_json, parse_cppcheck_xml, parse_sarif, parse_verus,
    parse_verus_findings,
};

/// How an adapter turns a tool's output into findings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    /// SARIF 2.1.0, which several modern tools emit natively.
    Sarif,
    /// Cppcheck's XML version 2.
    CppcheckXml,
    /// `cargo clippy --message-format=json`.
    ClippyJson,
    /// GCC-style `file:line:col: level: message`.
    GccLike,
    /// ModelScan's own JSON, which `--reporting-format json` emits.
    ///
    /// **Not SARIF**, which is what the spec used to declare. ModelScan reports
    /// an `issues` array of `{description, operator, module, source, scanner,
    /// severity}` with no `runs` key anywhere, so the SARIF parser rejected it
    /// outright — the adapter could not have read a single real result.
    ///
    /// The parser and its fixture **have** since been checked against the real
    /// tool: `tests/fixtures/ext.modelscan.txt` was captured from modelscan
    /// 0.8.8 via `-o`, with only the local temp path edited out. This comment
    /// used to say the opposite, and left standing it was the worst kind of
    /// stale note — one that tells a reader a real fixture is a reconstruction,
    /// about the single fact this codebase most needs to state accurately.
    ModelScanJson,
    /// Miri's rustc-style diagnostics, as the interpreter writes them to stderr.
    ///
    /// The spec used to declare [`OutputFormat::ClippyJson`] on stdout. It could
    /// not have reported a single real Miri finding, and the fixture that agreed
    /// with it was a reconstruction. See [`parse::parse_miri`].
    MiriText,
    /// Valgrind's `==pid==` text, as Memcheck writes it to stderr.
    ///
    /// This is its own format and nothing like the others: a description line
    /// followed by indented `at`/`by` stack frames carrying `(file:line)`. The
    /// adapter used to declare [`OutputFormat::GccLike`] for it, which matches
    /// not one line Valgrind emits, so a run reporting an invalid write and a
    /// definite leak yielded zero findings.
    ValgrindText,
    /// Verus's `--output-json` stdout **and** its stderr, read together.
    ///
    /// The only format here that needs two streams, and it needs them because
    /// neither is a result on its own: the JSON carries the counts and a
    /// `func-details` map whose `failed_proof_notes` is empty even for the
    /// function that failed, while the names and locations exist only in the
    /// rustc-style diagnostics on stderr. Verus also exits 0 on a failed proof,
    /// so nothing about the process says anything either.
    VerusJson,
}

/// Which of a tool's streams carries the output worth parsing.
///
/// This was a `bool` until a tool needed both. Verus writes its counts and its
/// `success` flag to stdout as JSON and the *names and locations* of the
/// obligations that failed to stderr as text, and neither stream alone is a
/// result: the JSON records that something failed and never which thing, and the
/// diagnostics carry no totals. An adapter forced to pick one would either
/// report failures it could not locate or locations with no idea how many were
/// missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OutputChannel {
    #[default]
    Stdout,
    Stderr,
    /// Both, parsed together. Only meaningful for a format that knows what to do
    /// with two streams; every other format reads stdout and ignores the rest.
    Both,
}

/// The declarative description of an external tool adapter.
///
/// Adding a tool is data, not code: give it an id, an executable, the arguments
/// that make it emit a machine-readable format, and how to read that format.
#[derive(Clone, Debug)]
pub struct AdapterSpec {
    pub id: &'static str,
    pub name: &'static str,
    pub executable: &'static str,
    /// Arguments, with `{target}` replaced by the analysis root and
    /// `{compile_commands}` by the compilation database path.
    pub args: &'static [&'static str],
    /// The arguments that make the tool state its version, used to probe for it.
    ///
    /// Not always `--version`: an adapter whose executable is a driver — `cargo
    /// clippy`, `cargo miri` — has to probe the *subcommand*, because the driver
    /// is installed either way. Probing `cargo --version` reported Miri as
    /// installed on a machine where `cargo miri` exits 1 with "the 'miri'
    /// component ... is not available", which is an inability to check dressed
    /// up as a clean check.
    pub version_args: &'static [&'static str],
    /// The per-project configuration file this tool reads, if it has one.
    ///
    /// Only meaningful together with [`AdapterSpec::args_without_config`].
    pub config_file: Option<&'static str>,
    /// Arguments supplied *only* when the project does not carry
    /// [`AdapterSpec::config_file`].
    ///
    /// This exists because a tool that will not run without configuration is,
    /// out of the box, a tool that produces nothing — and the README's stance is
    /// that a first run should produce real results rather than a list of things
    /// to set up. `clang-tidy` is the case in point: it has no built-in default
    /// check set at all, so with no `.clang-tidy` anywhere it exits with "no
    /// checks enabled" and analyses not one line.
    ///
    /// These are withheld when the project *does* supply a configuration file,
    /// because they would not replace it — `clang-tidy` appends `--checks` to
    /// the file's `Checks` key — so injecting a default would quietly widen a
    /// check set the project had deliberately narrowed.
    pub args_without_config: &'static [&'static str],
    pub kind: AnalyzerKind,
    pub languages: &'static [Language],
    pub capabilities: &'static [Capability],
    pub format: OutputFormat,
    /// Whether the tool needs a compilation database to be meaningful.
    pub needs_compile_commands: bool,
    pub requires_build: bool,
    /// Which stream carries the output worth parsing.
    pub channel: OutputChannel,
    pub description: &'static str,
}

/// An external tool, wrapped as a provider.
pub struct ExternalAdapter {
    spec: AdapterSpec,
    /// Overrides the executable, for a tool installed under a different name.
    pub executable_override: Option<String>,
    pub timeout: Duration,
    /// What the last run said it could not check, awaiting collection by
    /// [`Analyzer::take_notices`]. Behind a lock because `analyze` takes `&self`
    /// — a provider is shared behind an `Arc` and may be asked to run more than
    /// once.
    notices: std::sync::Mutex<Vec<sda_core::Exclusion>>,
}

impl ExternalAdapter {
    pub fn new(spec: AdapterSpec) -> Self {
        ExternalAdapter {
            spec,
            executable_override: None,
            timeout: Duration::from_secs(600),
            notices: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn with_executable(mut self, exe: impl Into<String>) -> Self {
        self.executable_override = Some(exe.into());
        self
    }

    fn executable(&self) -> String {
        self.executable_override.clone().unwrap_or_else(|| self.spec.executable.to_string())
    }

    /// Build the command, routing batch wrappers through the shell.
    ///
    /// Windows cannot execute a `.bat` or `.cmd` directly — `CreateProcess`
    /// needs an image, and since the fix for CVE-2024-24576 Rust refuses to
    /// paper over it. That matters here because a great many analysis tools ship
    /// on Windows as exactly such a wrapper (`pio.bat`, `west.cmd`, anything
    /// installed by npm or pip). Without this, pointing the toolkit at one
    /// produced an empty result and a confusing parse error rather than findings.
    fn command(&self) -> Command {
        let exe = self.executable();
        let is_batch = exe.to_ascii_lowercase().ends_with(".bat")
            || exe.to_ascii_lowercase().ends_with(".cmd");
        if cfg!(windows) && is_batch {
            let mut cmd = Command::new("cmd");
            cmd.arg("/C").arg(exe);
            cmd
        } else {
            Command::new(exe)
        }
    }

    /// Whether the project supplies this tool's own configuration file.
    ///
    /// The search matches what the tool actually does rather than what is
    /// convenient to check: `clang-tidy` walks upward from *each source file* to
    /// the filesystem root, so looking only in the project root would miss a
    /// configuration the tool is genuinely going to read, and we would inject a
    /// default on top of it.
    ///
    /// A project with a configuration for some files and not others counts as
    /// configured. That is the conservative reading — the alternative is to
    /// broaden a check set someone wrote on purpose — and the files with no
    /// configuration are not silently dropped: the tool's own exit status
    /// carries them into the "produced no findings, so this establishes
    /// nothing" path below.
    fn project_supplies_config(&self, target: &Target) -> bool {
        let Some(name) = self.spec.config_file else { return false };
        let files = target.files_in(self.spec.languages);
        let mut starts: Vec<&std::path::Path> =
            files.iter().filter_map(|f| f.path.parent()).collect();
        starts.push(&target.root);
        starts.iter().any(|dir| dir.ancestors().any(|a| a.join(name).is_file()))
    }

    /// Expand the spec's argument template against a target.
    ///
    /// Placeholders:
    /// * `{target}` — the project root, for tools that walk a tree themselves.
    /// * `{files}` — the target's source files in this tool's languages,
    ///   expanded to one argument each, for tools that demand source paths.
    /// * `{compile_commands}` — the database file itself.
    /// * `{compile_commands_dir}` — the directory containing it, which is what
    ///   every clang tool's `-p` actually wants.
    /// * `{artifact}` — the built binary, for a tool that *runs* the program
    ///   rather than reading it.
    ///
    /// `{compile_commands}` and `{compile_commands_dir}` are separate because
    /// conflating them broke `clang-tidy` silently: it was handed the `.json`
    /// path as `-p` and the project *root* as its source argument, so it printed
    /// its usage message and analysed nothing at all.
    ///
    /// `{artifact}` exists for the same class of reason. Valgrind's template
    /// ended in `{target}`, so the adapter ran `valgrind --leak-check=full
    /// <project directory>` — asking it to execute a directory. There was no
    /// placeholder that named the binary, so no way to write the template
    /// correctly.
    /// Whether this tool writes its report to a file we name, rather than to a
    /// stream we capture. Inferred from the template rather than declared in a
    /// separate flag, which could disagree with it.
    fn writes_to_a_file(&self) -> bool {
        self.spec.args.iter().any(|a| a.contains("{output}"))
    }

    /// Where such a tool should write. Named for the provider and the process so
    /// two concurrent runs cannot read each other's report.
    fn output_path(&self) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "sda-{}-{}.out",
            self.spec.id.replace('.', "-"),
            std::process::id()
        ))
    }

    /// Args with the output path filled in from [`Self::output_path`]. Only the
    /// tests need this shorthand; `analyze` names the path itself, because it
    /// has to read the same file back afterwards.
    #[cfg(test)]
    fn args_for(&self, target: &Target) -> Vec<String> {
        self.args_for_with_output(target, &self.output_path().to_string_lossy())
    }

    fn args_for_with_output(&self, target: &Target, output: &str) -> Vec<String> {
        let files = target
            .files_in(self.spec.languages)
            .iter()
            .map(|f| f.path.to_string_lossy().to_string())
            .collect();
        self.args_with_files(target, output, files)
    }

    fn args_with_files(&self, target: &Target, output: &str, files: Vec<String>) -> Vec<String> {
        // Absolute, because the child is spawned with `current_dir(&target.root)`
        // and `{target}` was substituted with the root *as the user typed it*. So
        // `sda scan crates --with ext.cppcheck` ran cppcheck from inside `crates`
        // and told it to analyze `crates` — that is, `crates/crates`, which does
        // not exist. Every `{target}` adapter was broken for a relative path,
        // which is the ordinary way to invoke the CLI; the earlier real-tool runs
        // all happened to pass an absolute path or `.`, so nothing noticed.
        //
        // `std::path::absolute` rather than `canonicalize`, which on Windows
        // returns an extended-length `\\?\C:\...` path that several of these
        // tools mishandle.
        let root = std::path::absolute(&target.root)
            .unwrap_or_else(|_| target.root.clone())
            .to_string_lossy()
            .to_string();
        let artifact = target
            .artifact
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // The crate manifest, for cargo subcommands that take `--manifest-path`
        // rather than a directory. Pointing one at the analysis root instead
        // makes it walk upward and analyse whatever crate it lands in, which may
        // not be the crate under analysis at all.
        let manifest = target.root.join("Cargo.toml").to_string_lossy().into_owned();        let cc = target
            .compile_commands
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let cc_dir = target
            .compile_commands
            .as_ref()
            .and_then(|p| p.parent())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut files = files;
        let mut out = Vec::new();
        // Ahead of the template, so a positional `{files}` expansion stays last
        // and a project template can still override by repeating the flag.
        if !self.spec.args_without_config.is_empty() && !self.project_supplies_config(target) {
            out.extend(self.spec.args_without_config.iter().map(|a| a.to_string()));
        }
        for a in self.spec.args {
            if *a == "{files}" {
                out.append(&mut files);
                continue;
            }
            out.push(
                a.replace("{target}", &root)
                    .replace("{compile_commands_dir}", &cc_dir)
                    .replace("{compile_commands}", &cc)
                    .replace("{artifact}", &artifact)
                    .replace("{manifest}", &manifest)
                    .replace("{output}", output),
            );
        }
        out
    }

    /// The files a compilation database has a compile line for.
    ///
    /// The report already calls the rest invisible to type-aware tools, and it was
    /// right: clang-tidy guessed their flags from a neighbour, and on PX4 most of
    /// them stopped at a missing header and left a partial parse reading as
    /// findings. A header is seen through the files that include it.
    ///
    /// A database that cannot be read, or that names none of these files, changes
    /// nothing, so the tool meets the problem and says what it is.
    fn described_by_the_database(&self, target: &Target, files: Vec<String>) -> Vec<String> {
        let Some(db) = target
            .compile_commands
            .as_ref()
            .and_then(|p| sda_build::CompilationDatabase::load(p).ok())
        else {
            return files;
        };
        let total = files.len();
        let (kept, left): (Vec<String>, Vec<String>) = files
            .into_iter()
            .partition(|f| db.for_file(std::path::Path::new(f)).is_some());
        if kept.is_empty() {
            return left;
        }
        if !left.is_empty() {
            self.notices.lock().unwrap_or_else(|e| e.into_inner()).push(sda_core::Exclusion {
                provider: self.spec.id.into(),
                reason: format!(
                    "`{}` ran on the {} of {total} files the compilation database describes; the \
                     other {} have no compile line, so they were not run",
                    self.executable(),
                    kept.len(),
                    left.len(),
                ),
            });
        }
        kept
    }

    /// Run a `{files}` tool once per source file, on every core.
    ///
    /// clang-tidy 19.1.7 segfaults on at least four files of PX4, and in one
    /// process over 5,120 files the first of those cost the rest. One process per
    /// file is what `run-clang-tidy` does: a crash costs that file, which is named
    /// under NOT CHECKED, and the other files keep their findings.
    ///
    /// [`ExternalAdapter::timeout`] bounds the whole run. Files it does not reach
    /// are counted the same way.
    fn analyze_each_file(
        &self,
        target: &Target,
        opts: &RunOptions,
        files: Vec<String>,
    ) -> sda_core::Result<Vec<Finding>> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        const SLOT: &str = "{file}";
        let exe = self.executable();
        // Once, because finding the project's configuration walks every file.
        let template = self.args_with_files(target, "", vec![SLOT.to_string()]);
        let deadline = std::time::Instant::now() + self.timeout;
        let next = AtomicUsize::new(0);

        let run_one = |file: &str| -> Result<(Vec<Finding>, Option<String>), String> {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err("not reached before the time limit".into());
            }
            let mut cmd = self.command();
            cmd.args(template.iter().map(|a| if a == SLOT { file } else { a.as_str() }))
                .current_dir(&target.root);
            let out = run_with_timeout(cmd, left).map_err(|e| match e {
                RunFailure::Spawn(e) => format!("could not run `{exe}`: {e}"),
                RunFailure::TimedOut => "stopped at the time limit".to_string(),
            })?;
            let text = String::from_utf8_lossy(&out.stdout);
            let findings = parse_output_channels(&text, "", self.spec.format, self.spec.id)?;
            let exit = out.status.code().map_or("a signal".to_string(), |c| c.to_string());
            let said = String::from_utf8_lossy(&out.stderr)
                .lines()
                .find(|l| !l.trim().is_empty())
                .map(|l| format!(": {l}"))
                .unwrap_or_default();
            if died_on_a_signal(&out.status) {
                return Ok((findings, Some(format!("crashed with {exit}{said}"))));
            }
            if findings.is_empty() && !out.status.success() {
                return Err(format!("exited with {exit}{said}"));
            }
            // What it printed before stopping is real, and the file is not done.
            if findings.iter().any(|f| f.rule.as_str().contains("clang-diagnostic-error")) {
                return Ok((findings, Some("did not compile".to_string())));
            }
            Ok((findings, None))
        };

        let workers = std::thread::available_parallelism().map_or(1, |n| n.get()).min(files.len());
        let mut outcomes: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    s.spawn(|| {
                        let mut done = Vec::new();
                        while let Some(file) = files.get(next.fetch_add(1, Ordering::Relaxed)) {
                            done.push((file.as_str(), run_one(file)));
                        }
                        done
                    })
                })
                .collect();
            handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
        });
        // Finish order depends on the machine; a report must not.
        outcomes.sort_by_key(|(file, _)| *file);

        let mut findings = Vec::new();
        let mut failed: Vec<(&str, String)> = Vec::new();
        // A worker that panicked took its results with it, and a file in neither
        // list would read as checked.
        for file in &files {
            if outcomes.binary_search_by_key(&file.as_str(), |(f, _)| *f).is_err() {
                failed.push((file, "lost when its worker panicked".to_string()));
            }
        }
        for (file, outcome) in outcomes {
            match outcome {
                Ok((mut found, problem)) => {
                    findings.append(&mut found);
                    if let Some(problem) = problem {
                        failed.push((file, problem));
                    }
                }
                Err(problem) => failed.push((file, problem)),
            }
        }

        if failed.len() >= files.len() {
            let (file, problem) = &failed[0];
            return Err(sda_core::Error::ProviderFailed {
                provider: self.spec.id.into(),
                reason: format!(
                    "`{exe}` finished none of {} file(s), so this run establishes nothing about \
                     what it checks; {file} {problem}",
                    files.len()
                ),
            });
        }
        if !failed.is_empty() {
            // The crashes first, since a compile error is usually a file the
            // database does not describe, and a crash is the tool's own.
            failed.sort_by_key(|(_, p)| !p.starts_with("crashed"));
            // By how each starts, because the rest of the text can be the tool's
            // own stderr, and one failure counted twice would underflow below.
            let count = |word: &str| failed.iter().filter(|(_, p)| p.starts_with(word)).count();
            let crashed = count("crashed");
            let timed_out = count("not reached") + count("stopped");
            let uncompiled = count("did not compile");
            let listed: Vec<String> =
                failed.iter().take(5).map(|(f, p)| format!("{f} {p}")).collect();
            self.notices.lock().unwrap_or_else(|e| e.into_inner()).push(sda_core::Exclusion {
                provider: self.spec.id.into(),
                reason: format!(
                    "`{exe}` finished {} of {} files, and the other {} were not fully checked \
                     ({crashed} crashed, {timed_out} ran out of time, {uncompiled} did not \
                     compile, {} exited with an error): \
                     {}{}",
                    files.len() - failed.len(),
                    files.len(),
                    failed.len(),
                    failed.len() - crashed - timed_out - uncompiled,
                    listed.join("; "),
                    if failed.len() > listed.len() { "; and more" } else { "" },
                ),
            });
        }
        self.settle(&mut findings, opts);
        Ok(findings)
    }

    /// Take out what the tool said about the analysis, and what the run disabled.
    fn settle(&self, findings: &mut Vec<Finding>, opts: &RunOptions) {
        // Before the disabled-rule filter, and before anything counts these as
        // results: a statement about the analysis is not a finding about the
        // code, and it belongs in the section a clean summary cannot hide.
        let taken = take_self_reported_limitations(findings);
        if !taken.is_empty() {
            self.notices.lock().unwrap_or_else(|e| e.into_inner()).extend(taken);
        }
        findings.retain(|f| !opts.disabled_rules.iter().any(|r| f.rule.as_str().contains(r)));
    }
}

/// Whether a process was killed rather than exiting: no code on Unix, an NTSTATUS
/// such as `0xC0000005` on Windows, which reads as a negative `i32`.
fn died_on_a_signal(status: &std::process::ExitStatus) -> bool {
    !status.success() && status.code().is_none_or(|c| c < 0)
}

/// Mark findings as what they are: observations from a tool that ran the program.
///
/// Split out of `ExternalAdapter::analyze` so the two callers cannot drift. The
/// second caller is a test that replays a captured Memcheck run through
/// `run::analyze`; re-deriving this there would have tested the test's idea of
/// how external dynamic evidence is shaped, and this exact seam is where that
/// went wrong twice already — see the comment at the call site.
pub fn as_runtime_evidence(findings: &mut [Finding]) {
    for f in findings {
        f.phase = sda_core::AnalysisPhase::Dynamic;
        let kind = f
            .taxonomy
            .iter()
            .filter(|t| t.scheme == sda_core::Taxonomy::Cwe)
            .filter_map(|t| t.id.trim_start_matches("CWE-").parse::<u32>().ok())
            .find_map(sda_core::RuntimeEventKind::from_cwe)
            .unwrap_or(sda_core::RuntimeEventKind::SanitizerReport);
        let mut event = sda_core::RuntimeEvent::new(kind, f.message.clone());
        event.location = Some(f.location.clone());
        f.evidence.push(Evidence::Runtime { event });
    }
}

/// Why a child process did not produce output.
#[derive(Debug)]
enum RunFailure {
    Spawn(std::io::Error),
    TimedOut,
}

/// `Command::output()` with a deadline.
///
/// `ExternalAdapter::timeout` existed, defaulted to ten minutes, was public, and
/// **was never used**: `analyze` called `.output()`, which waits forever. A field
/// whose whole purpose is to bound a hung tool, doing nothing, is the shape of
/// defect this repository keeps a table of — and it stayed invisible because
/// every adapter run until now was over a handful of files. It surfaced on the
/// first real one: clang-tidy over 184 files of llama.cpp, well past ten
/// minutes, with nothing able to stop it.
///
/// The pipes are drained on their own threads rather than after waiting. A
/// child that fills its stdout pipe blocks until someone reads it, so polling
/// `try_wait` while holding an unread pipe deadlocks against exactly the tools
/// this is for — cppcheck emits megabytes of XML on a real tree.
fn run_with_timeout(
    mut cmd: Command,
    timeout: Duration,
) -> Result<std::process::Output, RunFailure> {
    use std::io::Read;
    use std::process::Stdio;

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null());
    let mut child = cmd.spawn().map_err(RunFailure::Spawn)?;

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = stdout.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = stderr.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    // The readers are **not** joined here, and that is the whole
                    // difference between a timeout and a slower way to wait for
                    // the tool. Killing the child does not necessarily close the
                    // pipes: on Windows a `.bat` wrapper is `cmd /C`, and killing
                    // `cmd` leaves the grandchild holding the write end — so a
                    // reader still blocks until the tool finishes on its own.
                    // The first version of this joined them, reported `TimedOut`
                    // after 59.6 seconds against a 0.4-second deadline, and was
                    // caught by the test below rather than by reasoning.
                    //
                    // The output is being discarded, so the threads are left to
                    // end when the pipes eventually close. This repository ships
                    // exactly such a wrapper: `tools/valgrind-wsl/valgrind-wsl.bat`.
                    drop(out_thread);
                    drop(err_thread);
                    return Err(RunFailure::TimedOut);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(RunFailure::Spawn(e)),
        }
    };

    Ok(std::process::Output {
        status,
        stdout: out_thread.join().unwrap_or_default(),
        stderr: err_thread.join().unwrap_or_default(),
    })
}

/// Rule ids with which a tool reports on **its own analysis** rather than on the
/// code it was given.
///
/// One entry per `(provider, rule)`. Kept as data rather than a predicate so
/// adding a tool means adding rows, and so this list is greppable when a run
/// produces a category nobody expected.
const SELF_REPORTED_LIMITATIONS: &[(&str, &str)] = &[
    // Cppcheck says these on a tree it was handed without a build. Each is the
    // tool telling you it worked with less than it wanted.
    ("ext.cppcheck", "missingInclude"),
    ("ext.cppcheck", "missingIncludeSystem"),
    ("ext.cppcheck", "toomanyconfigs"),
    ("ext.cppcheck", "normalCheckLevelMaxBranches"),
    ("ext.cppcheck", "checkLevelNormal"),
    ("ext.cppcheck", "checkersReport"),
    ("ext.cppcheck", "unmatchedSuppression"),
];

/// Move a tool's statements about its own coverage out of the findings and into
/// the *NOT CHECKED* section, aggregated.
///
/// # Why this is not filtering
///
/// It is the opposite. Cppcheck over 184 files of real C++ produced 1,453
/// findings, and 321 of them — 22% — were `missingIncludeSystem`,
/// `missingInclude`, `toomanyconfigs` and `normalCheckLevelMaxBranches`: the
/// tool saying it could not resolve 288 includes and had analysed 12 of 17
/// preprocessor configurations in one file. It was right, and it mattered: those
/// results were produced with incomplete information.
///
/// As findings they achieved the reverse of what they say. They are
/// `information` severity, so the natural first move on a report that size —
/// filter to `medium` and above — discards them, and what remains reads as a
/// completed analysis. Meanwhile `NOT CHECKED`, the section this repository
/// built precisely so that an inability to check cannot be mistaken for a clean
/// check, said nothing at all, because nothing had told it.
///
/// So each kind becomes one notice that names how many there were and quotes the
/// first, and cannot be filtered away by severity. Nothing is discarded: what
/// changes is which half of the report carries it.
fn take_self_reported_limitations(findings: &mut Vec<Finding>) -> Vec<sda_core::Exclusion> {
    let is_limitation = |f: &Finding| {
        SELF_REPORTED_LIMITATIONS
            .iter()
            .any(|(p, r)| f.provider.as_str() == *p && f.rule.as_str() == *r)
    };

    // Grouped by (provider, rule) and in first-seen order, so the notice a
    // reader meets first is the one the tool said first.
    let mut order: Vec<(String, String)> = Vec::new();
    let mut grouped: BTreeMap<(String, String), Vec<Finding>> = BTreeMap::new();
    let mut kept = Vec::with_capacity(findings.len());
    for f in std::mem::take(findings) {
        if is_limitation(&f) {
            let key = (f.provider.to_string(), f.rule.to_string());
            if !grouped.contains_key(&key) {
                order.push(key.clone());
            }
            grouped.entry(key).or_default().push(f);
        } else {
            kept.push(f);
        }
    }
    *findings = kept;

    order
        .into_iter()
        .map(|key| {
            let group = &grouped[&key];
            let (provider, rule) = key;
            let first = &group[0];
            // The example carries a location because "288 includes were missing"
            // and "your include path is wrong, starting here" are the same fact
            // at different distances from being actionable.
            let example = format!(
                "{} at {}:{}",
                first.message.trim_end_matches('.'),
                first.location.file.display(),
                first.location.line
            );
            let reason = match group.len() {
                1 => format!(
                    "`{rule}`: {example}. This is the tool describing its own analysis, not a \
                     defect in the code, and it means the results above were produced with less \
                     information than the tool wanted"
                ),
                n => format!(
                    "`{rule}` × {n}: the tool reported this {n} times, describing its own \
                     analysis rather than a defect in the code — the results above were produced \
                     with less information than it wanted. First of them: {example}"
                ),
            };
            sda_core::Exclusion { provider: provider.into(), reason }
        })
        .collect()
}

impl Analyzer for ExternalAdapter {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: self.spec.id.into(),
            name: self.spec.name.into(),
            origin: ProviderOrigin::External,
            kind: self.spec.kind,
            languages: self.spec.languages.to_vec(),
            capabilities: self.spec.capabilities.to_vec(),
            description: self.spec.description.into(),
            executable: Some(self.executable()),
            url: sda_ontology::Ontology::load().get(self.spec.id).and_then(|t| t.url.clone()),
            requires_build: self.spec.requires_build,
        }
    }

    /// Drained, not read: a second collection must not repeat the first run's
    /// story, and a provider asked to run twice reports what the second run
    /// found rather than both.
    fn take_notices(&self) -> Vec<sda_core::Exclusion> {
        // `unwrap_or_else(into_inner)` rather than `expect`, and not to satisfy
        // the self-scan: a poisoned lock means some other thread panicked while
        // holding it, and the notices are still perfectly readable. Aborting
        // here would discard the report's account of what could not be checked
        // because something unrelated went wrong — the exact trade this
        // repository exists to refuse.
        let mut held = self.notices.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *held)
    }

    fn available(&self) -> Availability {
        let exe = self.executable();
        // Asking a tool to state its version is the closest thing to a universal
        // "are you there?" across this population — but it has to be asked of
        // the thing that does the work. For a cargo subcommand that is `cargo
        // miri --version`, not `cargo --version`.
        //
        // The name in the message is what was actually probed, so "not found"
        // never names a thing that is in fact present.
        let probed = match self.spec.version_args.split_last() {
            Some((_, [])) | None => exe.clone(),
            Some((_, sub)) => format!("{exe} {}", sub.join(" ")),
        };
        match self.command().args(self.spec.version_args).output() {
            Ok(out) if out.status.success() || !out.stdout.is_empty() => {
                if self.spec.needs_compile_commands {
                    Availability::Degraded {
                        reason: format!(
                            "`{exe}` is installed, but without a compile_commands.json it analyses \
                             a guess at the build configuration rather than the real one"
                        ),
                    }
                } else {
                    Availability::Available
                }
            }
            Ok(_) | Err(_) => {
                let cover = self
                    .spec
                    .capabilities
                    .first()
                    .map(|c| c.as_str())
                    .unwrap_or("this ground");
                // A missing cargo subcommand is a missing *component*, not a
                // missing tool: `cargo` is right there on PATH, and saying it is
                // not sends the reader to install something they already have.
                if probed != exe {
                    Availability::unavailable(format!(
                        "`{probed}` did not run: `{exe}` is on PATH but the subcommand is not \
                         installed. Add the component, or leave this provider disabled — the \
                         native engines already cover {cover}"
                    ))
                } else {
                    Availability::unavailable(format!(
                        "`{exe}` was not found on PATH. Install it, or pass an explicit path, or \
                         leave this provider disabled — the native engines already cover {cover}"
                    ))
                }
            }
        }
    }

    fn analyze(&self, target: &Target, opts: &RunOptions) -> sda_core::Result<Vec<Finding>> {
        let exe = self.executable();
        // A tool that runs the program needs the program. Substituting an empty
        // string for `{artifact}` would hand the tool a stray bare argument and
        // let it fail in its own words, which is a worse explanation than this
        // one.
        if self.spec.args.iter().any(|a| a.contains("{artifact}")) && target.artifact.is_none() {
            return Err(sda_core::Error::ProviderUnavailable {
                provider: self.spec.id.into(),
                reason: "this tool executes the program under analysis, and no built artifact was \
                         supplied; pass `--artifact <path>` and re-run"
                    .into(),
            });
        }
        if self.spec.needs_compile_commands && target.compile_commands.is_none() {
            return Err(sda_core::Error::ProviderUnavailable {
                provider: self.spec.id.into(),
                reason: "this tool needs a compile_commands.json to resolve types; generate one \
                         with `sda build compile-commands` and re-run"
                    .into(),
            });
        }

        if self.spec.args.contains(&"{files}") {
            // Absolute, for the reason `{target}` is: the child runs inside the
            // root, so `sda scan src` asked for `src/src/...` and PX4 lost every file.
            let files: Vec<String> = target
                .files_in(self.spec.languages)
                .iter()
                .map(|f| {
                    let path = std::path::absolute(&f.path).unwrap_or_else(|_| f.path.clone());
                    path.to_string_lossy().to_string()
                })
                .collect();
            let files = self.described_by_the_database(target, files);
            if !files.is_empty() {
                return self.analyze_each_file(target, opts, files);
            }
        }

        // A tool that reports into a file we name gets a fresh one: a stale
        // report left by an earlier run would be read as this run's result,
        // which is the worst possible version of this failure.
        let report_path = self.output_path();
        if self.writes_to_a_file() {
            let _ = std::fs::remove_file(&report_path);
        }

        let args = self.args_for_with_output(target, &report_path.to_string_lossy());
        let mut cmd = self.command();
        cmd.args(&args).current_dir(&target.root);
        let out = run_with_timeout(cmd, self.timeout).map_err(|e| match e {
            RunFailure::Spawn(e) => sda_core::Error::ProviderFailed {
                provider: self.spec.id.into(),
                reason: format!("could not run `{exe}`: {e}"),
            },
            // Not a clean result and not "no findings": a tool that was stopped
            // mid-analysis has checked an unknown fraction of the target, and
            // saying so is the only honest thing available.
            RunFailure::TimedOut => sda_core::Error::ProviderFailed {
                provider: self.spec.id.into(),
                reason: format!(
                    "`{exe}` did not finish within {}s and was stopped, so it checked an unknown \
                     part of this target and this run establishes nothing about what it covers. \
                     Narrow the scan, or raise the limit if the tool is simply slow here",
                    self.timeout.as_secs()
                ),
            },
        })?;

        let text = if self.writes_to_a_file() {
            // ModelScan renders its JSON through `rich`, which hard-wraps at the
            // terminal width *even when redirected* and breaks lines in the
            // middle of string literals — so its stdout is not merely noisy, it
            // is invalid JSON that no amount of prefix-skipping recovers. Its
            // `-o` report is clean. Any tool with the same habit belongs here.
            let text = std::fs::read_to_string(&report_path).map_err(|e| {
                // The tool's own words, not only ours. A missing report means the
                // tool declined to write one, and it almost always said why on
                // stderr — while this message named the file and our io error,
                // which describe our side of a failure that happened on theirs.
                // It cost a real diagnosis: CodeQL was reporting a database path
                // it could not find, and the report said only "could not be read".
                let tail: Vec<String> = String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(str::to_string)
                    .collect();
                let said = match tail.len() {
                    0 => " and said nothing on stderr".to_string(),
                    n => format!(" and said: {}", tail[n.saturating_sub(3)..].join("; ")),
                };
                sda_core::Error::ProviderFailed {
                    provider: self.spec.id.into(),
                    reason: format!(
                        "`{exe}` was asked to write its report to {} and it could not be read \
                         ({e}); the tool exited with {}{said}. This run establishes nothing \
                         about what it checks",
                        report_path.display(),
                        out.status
                            .code()
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "a signal".into()),
                    ),
                }
            })?;
            let _ = std::fs::remove_file(&report_path);
            // An empty report file is *not* an empty report. Every JSON parser
            // here returns "no findings" for empty input, so a tool that created
            // the file and then died before writing it would be indistinguishable
            // from a clean scan. Observed once with modelscan 0.8.8 and never
            // reproduced, which is the worst kind of bug to leave unguarded.
            if text.trim().is_empty() {
                return Err(sda_core::Error::ProviderFailed {
                    provider: self.spec.id.into(),
                    reason: format!(
                        "`{exe}` exited with {} and left an empty report at {}; an empty file is \
                         not a clean result, so this run establishes nothing about what it checks",
                        out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "a signal".into()),
                        report_path.display()
                    ),
                });
            }
            text
        } else {
            match self.spec.channel {
                OutputChannel::Stderr => String::from_utf8_lossy(&out.stderr).into_owned(),
                OutputChannel::Stdout | OutputChannel::Both => {
                    String::from_utf8_lossy(&out.stdout).into_owned()
                }
            }
        };

        // The second stream, kept apart rather than concatenated. Two formats
        // glued together are neither, and a parser handed the pair can tell
        // which of them is silent — which is the whole reason a tool needs both.
        let secondary = match self.spec.channel {
            OutputChannel::Both => String::from_utf8_lossy(&out.stderr).into_owned(),
            _ => String::new(),
        };

        let mut findings = parse_output_channels(&text, &secondary, self.spec.format, self.spec.id)
            .map_err(|reason| sda_core::Error::ProviderFailed {
                provider: self.spec.id.into(),
                reason,
            })?;

        // A finding from a tool that *executed the program* is a runtime
        // observation, and must say so. `parse::finding` cannot know — it sees
        // text, not the spec — so every external finding was born
        // `AnalysisPhase::Static`, including Valgrind's and Miri's. `run::analyze`
        // sorts findings onto the static or dynamic side of correlation by
        // exactly this field, and its own comment says the provider's declared
        // kind decides; it did not, until here. A Memcheck invalid-write was
        // therefore filed as a static suspicion, which is the one thing it
        // demonstrably is not.
        //
        // The phase turned out to be necessary and not sufficient. Correlation
        // asks `same_defect_class` whether a witness is the same *kind* of thing
        // as the static suspicion, and that reads the runtime event kind off the
        // witness's evidence — which an external finding did not have, carrying
        // only a `Note` saying which provider reported it. So the finding
        // reached the dynamic side of correlation and was then discarded as
        // unclassifiable. The class is derived from the CWE the tool itself
        // stated; where the tool stated none, the event is labelled
        // `SanitizerReport`, which claims no more than "a dynamic checking tool
        // reported this" and is what the native ASan path already uses.
        if self.spec.kind == AnalyzerKind::Dynamic {
            as_runtime_evidence(&mut findings);
        }

        self.settle(&mut findings, opts);

        // A tool that exits non-zero and yields nothing has not given a clean
        // result — it has given no result, and the two must not look the same.
        //
        // Non-zero alone is not failure: linters routinely exit non-zero
        // *because* they found something, which is why this only fires when
        // there is also nothing to show. A real run tripped it — `clang-tidy`
        // exited with "Error: no checks enabled", and the report then listed
        // every other external provider as not-enabled while saying nothing at
        // all about the one the user had explicitly asked for.
        //
        // A signal is failure whatever came out. clang-tidy 19.1.7 segfaults on
        // PX4 partway through its file list, and what it printed first would
        // otherwise pass as the whole run.
        let killed = died_on_a_signal(&out.status);
        if killed || (findings.is_empty() && !out.status.success()) {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail: String = stderr
                .lines()
                .filter(|l| !l.trim().is_empty())
                .take(3)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(sda_core::Error::ProviderFailed {
                provider: self.spec.id.into(),
                reason: format!(
                    "`{exe}` exited with {} after producing {} finding(s), so this run establishes \
                     nothing about what it checks{}",
                    out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "a signal".into()),
                    findings.len(),
                    if detail.is_empty() {
                        String::new()
                    } else {
                        format!(": {detail}")
                    }
                ),
            });
        }

        Ok(findings)
    }
}

/// Parse a tool's captured output according to the format its spec declares: its
/// primary stream, and its secondary one where the format uses both.
///
/// This is the one place a format is turned into findings, so a test can feed a
/// recorded sample of a real tool's output through exactly what the adapter
/// runs. That matters more than it sounds: `ext.valgrind` declared `GccLike`,
/// which matches nothing Memcheck emits, and shipped that way through a full
/// test suite because no test ever asked the adapter to parse Valgrind output.
/// Every spec now has a fixture behind it (`tests/every_adapter_parses.rs`).
///
/// `secondary` is empty for every single-channel format and for a two-channel
/// tool whose second stream was not captured. That is not the same as a stream
/// that was captured and was empty, and [`OutputFormat::VerusJson`] reports the
/// difference rather than treating an uncaptured stream as a clean one.
pub fn parse_output_channels(
    text: &str,
    secondary: &str,
    format: OutputFormat,
    provider: &str,
) -> Result<Vec<Finding>, String> {
    match format {
        OutputFormat::Sarif => parse::parse_sarif(text, provider),
        OutputFormat::CppcheckXml => parse::parse_cppcheck_xml(text, provider),
        OutputFormat::ClippyJson => parse::parse_clippy_json(text, provider),
        OutputFormat::GccLike => parse::parse_gcc_like(text, provider),
        OutputFormat::ValgrindText => parse::parse_valgrind(text, provider),
        OutputFormat::MiriText => parse::parse_miri(text, provider),
        OutputFormat::ModelScanJson => parse::parse_modelscan_json(text, provider),
        OutputFormat::VerusJson => parse::parse_verus_findings(text, secondary, provider),
    }
}

/// The built-in adapter specifications.
pub fn specs() -> Vec<AdapterSpec> {
    vec![
        AdapterSpec {
            id: "ext.cppcheck",
            name: "Cppcheck",
            executable: "cppcheck",
            args: &["--enable=all", "--xml", "--xml-version=2", "{target}"],
            version_args: &["--version"],
            config_file: None,
            args_without_config: &[],
            kind: AnalyzerKind::Static,
            languages: &[Language::C, Language::Cpp],
            capabilities: &[
                Capability::StyleCompliance,
                Capability::MemorySafety,
                Capability::UndefinedBehavior,
            ],
            format: OutputFormat::CppcheckXml,
            needs_compile_commands: false,
            requires_build: false,
            channel: OutputChannel::Stderr,
            description: "Cppcheck's own checks, complementing the native C engine. Its MISRA \
                          addon needs a licensed rule-text file supplied separately.",
        },
        AdapterSpec {
            id: "ext.clang-tidy",
            name: "clang-tidy",
            executable: "clang-tidy",
            // A project's `WarningsAsErrors` and a database's `-Werror` make a flag
            // clang does not know, such as GCC's `-Wlogical-op`, an error with no
            // location. PX4 exited 1 that way on 947 files it had checked cleanly,
            // so the exit status said nothing. A compile error still exits 1.
            args: &[
                "-p",
                "{compile_commands_dir}",
                "--quiet",
                "--warnings-as-errors=-*",
                "--extra-arg=-Wno-error",
                "{files}",
            ],
            version_args: &["--version"],
            config_file: Some(".clang-tidy"),
            // Bug-finding checks, not house style. `clang-analyzer-*` is the
            // path-sensitive engine — the type-aware reasoning the native C
            // engine deliberately does not attempt — and `cert-*` is kept for
            // the compliance story: its checks are aliases that add a CERT rule
            // id to a diagnostic without reporting it twice, and the parser
            // turns that id into a taxonomy reference.
            //
            // `misc-use-internal-linkage` is excluded by name. It fires on every
            // non-static function in every C file, which on a first run buries
            // the memory-safety findings this default exists to surface.
            args_without_config: &[
                "-checks=-*,clang-analyzer-*,bugprone-*,cert-*,misc-*,-misc-use-internal-linkage",
            ],
            kind: AnalyzerKind::Static,
            languages: &[Language::C, Language::Cpp],
            capabilities: &[
                Capability::StyleCompliance,
                Capability::MemorySafety,
                Capability::UndefinedBehavior,
            ],
            format: OutputFormat::GccLike,
            needs_compile_commands: true,
            requires_build: false,
            channel: OutputChannel::Stdout,
            description: "Type-aware checks that the native engine deliberately does not attempt. \
                          This is the intended route for MISRA guidelines marked `semantics`.",
        },
        AdapterSpec {
            id: "ext.clippy",
            name: "Clippy",
            executable: "cargo",
            args: &["clippy", "--message-format=json", "--all-targets"],
            version_args: &["clippy", "--version"],
            config_file: None,
            args_without_config: &[],
            kind: AnalyzerKind::Static,
            languages: &[Language::Rust],
            capabilities: &[Capability::StyleCompliance, Capability::MemorySafety],
            format: OutputFormat::ClippyJson,
            needs_compile_commands: false,
            requires_build: true,
            channel: OutputChannel::Stdout,
            description: "Rust's lint suite. The native Rust checker covers the discipline around \
                          unsafe and FFI; clippy covers idiom and correctness lints.",
        },
        AdapterSpec {
            id: "ext.semgrep",
            name: "Semgrep",
            executable: "semgrep",
            args: &["--sarif", "--quiet", "{target}"],
            version_args: &["--version"],
            config_file: None,
            args_without_config: &[],
            kind: AnalyzerKind::Static,
            languages: &[Language::C, Language::Cpp, Language::Rust, Language::Python],
            capabilities: &[Capability::StyleCompliance, Capability::TaintAnalysis],
            format: OutputFormat::Sarif,
            needs_compile_commands: false,
            requires_build: false,
            channel: OutputChannel::Stdout,
            description: "Pattern-based scanning with a large community rule set, including rules \
                          for AI/LLM application code.",
        },
        AdapterSpec {
            id: "ext.codeql",
            name: "CodeQL",
            executable: "codeql",
            // `--output={output}`, not `--output=-`. CodeQL does not read `-` as
            // stdout: it creates a **file literally named `-`** in the working
            // directory, writes the SARIF there, prints a prose coverage line
            // ("CodeQL scanned 9 out of 9 C/C++ files in this invocation...") to
            // stdout, and exits 0. So the adapter parsed that sentence as SARIF
            // and could never have produced a finding, while littering the user's
            // repository with a junk file. Verified against CodeQL 2.26.4, and it
            // is the `ext.modelscan` failure a third time: a tool's stdout is
            // whatever the tool decides, and only running it settles the question.
            //
            // `{target}` is the **database**, not the source root — CodeQL
            // analyses a database it cannot build itself, which is why this spec
            // is `requires_build: true`. No query is named because a bare
            // `database analyze` runs the language's default suite; the run this
            // was checked against loaded 61 C/C++ queries.
            args: &["database", "analyze", "--format=sarif-latest", "--output={output}", "{target}"],
            version_args: &["--version"],
            config_file: None,
            args_without_config: &[],
            kind: AnalyzerKind::Static,
            languages: &[Language::C, Language::Cpp, Language::Rust, Language::Python],
            capabilities: &[Capability::TaintAnalysis, Capability::MemorySafety],
            format: OutputFormat::Sarif,
            needs_compile_commands: false,
            requires_build: true,
            channel: OutputChannel::Stdout,
            description: "Interprocedural dataflow over a pre-built database. Expensive to \
                          produce, strong on taint reaching a sink.",
        },
        AdapterSpec {
            id: "ext.modelscan",
            name: "ModelScan",
            executable: "modelscan",
            // `-o` rather than stdout: ModelScan prints its JSON through `rich`,
            // which hard-wraps at 80 columns even when redirected and breaks
            // lines inside string literals, so its stdout is invalid JSON. It
            // also prefixes two lines of progress chatter. The `-o` report is
            // clean. Verified against modelscan 0.8.8, not against the docs.
            args: &["-p", "{target}", "--reporting-format", "json", "-o", "{output}"],
            version_args: &["--version"],
            config_file: None,
            args_without_config: &[],
            kind: AnalyzerKind::Static,
            languages: &[Language::ModelArtifact],
            capabilities: &[Capability::ModelArtifactScan],
            format: OutputFormat::ModelScanJson,
            needs_compile_commands: false,
            requires_build: false,
            channel: OutputChannel::Stdout,
            description: "A second opinion on model serialization formats, alongside the native \
                          artifact scanner.",
        },
        AdapterSpec {
            id: "ext.valgrind",
            name: "Valgrind (memcheck)",
            executable: "valgrind",
            // `{artifact}`, not `{target}`: Valgrind executes a program. The
            // template used to end in the project *directory*, so the adapter
            // asked Valgrind to run a folder.
            args: &["--leak-check=full", "--error-exitcode=1", "{artifact}"],
            version_args: &["--version"],
            config_file: None,
            args_without_config: &[],
            kind: AnalyzerKind::Dynamic,
            languages: &[Language::C, Language::Cpp, Language::Rust],
            capabilities: &[Capability::MemorySafety],
            format: OutputFormat::ValgrindText,
            needs_compile_commands: false,
            requires_build: true,
            channel: OutputChannel::Stderr,
            description: "Memory error detection with no rebuild required, at roughly 20x \
                          slowdown. The fallback when the target cannot be rebuilt with sanitizers. \
                          Build with `-g`: without debug info Valgrind names no source line, and \
                          there is nowhere to put a finding.",
        },
        AdapterSpec {
            id: "ext.miri",
            name: "Miri",
            executable: "cargo",
            // `+nightly` is not a preference, it is the only place Miri exists:
            // it is a nightly-only component, so `cargo miri` on a stable default
            // toolchain fails the availability probe with "the subcommand is not
            // installed" — which is true, and reads as "install miri" when the
            // component is already installed on the toolchain that can run it.
            // Driven against a machine in exactly that state. rustup requires the
            // `+toolchain` to come first, and on a cargo that is not
            // rustup-managed it fails the probe, which is the right answer there
            // too: no rustup, no miri.
            args: &["+nightly", "miri", "test", "--message-format=json"],
            version_args: &["+nightly", "miri", "--version"],
            config_file: None,
            args_without_config: &[],
            kind: AnalyzerKind::Dynamic,
            languages: &[Language::Rust],
            capabilities: &[Capability::UndefinedBehavior, Capability::MemorySafety],
            format: OutputFormat::MiriText,
            needs_compile_commands: false,
            requires_build: true,
            // Miri's UB report is written at *run* time by the interpreter, in
            // prose, on stderr. `--message-format=json` is kept because it makes
            // cargo's build chatter machine-readable and out of the way, but the
            // findings were never in it: a real run over a stacked-borrows
            // violation writes `"success":true` to stdout and the violation to
            // stderr.
            channel: OutputChannel::Stderr,
            description: "Detects undefined behaviour in unsafe Rust by interpreting MIR. The \
                          right answer to every `UNSAFE.*` finding the native checker raises.",
        },
        AdapterSpec {
            id: "ext.verus",
            name: "Verus",
            executable: "cargo",
            // `cargo verus verify` is the crate-level entry point, the same
            // shape as `cargo clippy` and `cargo miri`. Everything after `--`
            // goes to `verus` itself.
            args: &["verus", "verify", "--manifest-path", "{manifest}", "--", "--output-json"],
            // Probe the subcommand, not the driver — `cargo --version` succeeds
            // on every machine with cargo and would report Verus as installed on
            // one where it is not. `cargo verus` has no `--version`, so `--help`
            // is what actually distinguishes present from absent.
            version_args: &["verus", "--help"],
            config_file: None,
            args_without_config: &[],
            kind: AnalyzerKind::Static,
            languages: &[Language::Rust],
            capabilities: &[
                Capability::DeductiveProof,
                Capability::FormalVerification,
                Capability::MemorySafety,
            ],
            format: OutputFormat::VerusJson,
            needs_compile_commands: false,
            requires_build: true,
            // The one adapter that needs both streams: the JSON counts what
            // failed and the diagnostics name it.
            channel: OutputChannel::Both,
            description: "Proves the pre/postconditions and invariants written in the source, \
                          with an SMT solver. LIMIT: an unspecified crate verifies vacuously — \
                          nothing is checked that nobody wrote down — so a clean result is only \
                          as strong as the specification behind it.",
        },
    ]
}

/// Build adapters for every known external tool.
pub fn all_adapters() -> Vec<std::sync::Arc<dyn Analyzer>> {
    specs()
        .into_iter()
        .map(|s| std::sync::Arc::new(ExternalAdapter::new(s)) as std::sync::Arc<dyn Analyzer>)
        .collect()
}

/// Register every adapter into an existing registry.
pub fn register_all(registry: &mut sda_core::Registry) {
    register_with_paths(registry, &BTreeMap::new());
}

/// Register every adapter, overriding executable paths for the ones named.
///
/// Real projects do not have their tools on `PATH` under bare names: they have
/// `/opt/cppcheck-2.13/bin/cppcheck`, or a vendored toolchain, or two versions
/// side by side with only one of them approved. Without a way to say which, the
/// whole external-provider story stops at "install it globally first".
pub fn register_with_paths(
    registry: &mut sda_core::Registry,
    paths: &BTreeMap<String, String>,
) {
    register_configured(registry, paths, None)
}

/// As [`register_with_paths`], with a wall-clock limit for each tool.
///
/// `None` keeps [`ExternalAdapter`]'s default. A tool handed a real project can
/// legitimately want a long time — clang-tidy over 184 files of llama.cpp took
/// 24 minutes of CPU in one invocation — and a limit that fires on ordinary work
/// is worse than none, because the honest "it was stopped, so this establishes
/// nothing" is then the normal outcome and people learn to ignore it.
pub fn register_configured(
    registry: &mut sda_core::Registry,
    paths: &BTreeMap<String, String>,
    timeout: Option<Duration>,
) {
    for spec in specs() {
        let mut adapter = ExternalAdapter::new(spec.clone());
        if let Some(path) = paths.get(spec.id) {
            adapter = adapter.with_executable(path.clone());
        }
        if let Some(t) = timeout {
            adapter.timeout = t;
        }
        registry.register(std::sync::Arc::new(adapter));
    }
}

/// Which adapters are actually installed on this machine, and why the others
/// are not. Surfaced by `sda tools status`, so an operator can see at a glance
/// what enabling external tools would actually add.
pub fn availability_report() -> BTreeMap<String, Availability> {
    all_adapters().into_iter().map(|a| (a.info().id.to_string(), a.available())).collect()
}

/// Attach a taxonomy reference to a finding when a tool's rule id encodes one.
pub(crate) fn infer_taxonomy(rule: &str) -> Vec<TaxonomyRef> {
    let mut v = Vec::new();
    let upper = rule.to_ascii_uppercase();
    if let Some(rest) = upper.strip_prefix("CWE-")
        && let Some(n) = rest.split(|c: char| !c.is_ascii_digit()).next().and_then(|s| s.parse().ok())
        {
            v.push(TaxonomyRef::cwe(n));
        }
    if upper.contains("MISRA") {
        // Cite the scheme without inventing a rule number we did not parse.
        v.push(TaxonomyRef::new(sda_core::Taxonomy::MisraC2023, rule.to_string()));
    }
    v
}

/// Build a finding from a parsed external diagnostic.
///
/// The location is passed whole rather than as `file, line, column` so that a
/// parser whose tool *does* state an end position can bracket the construct
/// with [`Location::spanning`]. SARIF regions and rustc's JSON spans both carry
/// one; taking three scalars meant the parsers had nowhere to put it and it was
/// dropped on the floor for every external finding.
pub(crate) fn finding(
    provider: &str,
    rule: &str,
    message: &str,
    severity: Severity,
    location: Location,
) -> Finding {
    let mut f = Finding::new(provider, rule, first_sentence(message), severity, location)
        .message(message.to_string())
        // An external tool's confidence is its own; we do not upgrade it, and we
        // do not pretend to have verified it.
        .confidence(Confidence::Medium)
        .evidence(Evidence::note(format!("reported by external provider `{provider}`")));
    for t in infer_taxonomy(rule) {
        f = f.taxonomy(t);
    }
    f
}

fn first_sentence(s: &str) -> String {
    let t = s.trim();
    match t.find(". ") {
        Some(i) if i < 120 => t[..i].to_string(),
        _ if t.len() > 120 => format!("{}…", &t[..117.min(t.len())]),
        _ => t.to_string(),
    }
}

#[cfg(test)]
mod tests {

    /// `{target}` must survive being handed to a child whose working directory is
    /// already the target.
    ///
    /// The adapter spawns with `current_dir(&target.root)`, and `{target}` used to
    /// be the root exactly as the user typed it. So `sda scan crates` ran the tool
    /// from inside `crates` and asked it to analyze `crates` — `crates/crates`.
    /// Every `{target}` adapter was broken for a relative path, which is the
    /// ordinary way to invoke the CLI.
    #[test]
    fn a_relative_scan_path_is_made_absolute_before_substitution() {
        let spec = specs().into_iter().find(|s| s.id == "ext.cppcheck").unwrap();
        let adapter = ExternalAdapter::new(spec);
        let target = Target::new(std::path::Path::new("crates"));

        let args = adapter.args_for(&target);
        let substituted = args.last().expect("`{target}` is the final argument");
        assert!(
            std::path::Path::new(substituted).is_absolute(),
            "`{substituted}` is relative, and the child's cwd is the target itself"
        );
        assert!(
            substituted.replace('\\', "/").ends_with("/crates"),
            "and it must still name the same directory: {substituted}"
        );
    }

    /// Windows `canonicalize` returns `\?\C:\...`, which several of these tools
    /// mishandle; `std::path::absolute` does not.
    #[test]
    fn the_absolute_form_is_not_an_extended_length_path() {
        let spec = specs().into_iter().find(|s| s.id == "ext.cppcheck").unwrap();
        let args = ExternalAdapter::new(spec).args_for(&Target::new(std::path::Path::new(".")));
        assert!(
            !args.last().unwrap().starts_with(r"\\?\"),
            "{:?}",
            args.last()
        );
    }
    use super::*;
    use sda_core::{Registry, SelectionPolicy, TargetFile};

    #[test]
    fn every_adapter_id_exists_in_the_ontology() {
        let o = sda_ontology::Ontology::load();
        for s in specs() {
            assert!(o.get(s.id).is_some(), "adapter `{}` is not in the ontology", s.id);
            assert!(!o.get(s.id).unwrap().is_native(), "`{}` must be external", s.id);
        }
    }

    #[test]
    fn adapters_are_external_and_excluded_by_default() {
        let mut r = Registry::new();
        register_all(&mut r);
        assert!(r.describe().iter().all(|p| p.origin == ProviderOrigin::External));

        let (chosen, excluded) = r.select(&SelectionPolicy::default());
        assert!(chosen.is_empty(), "the default policy is native-only");
        assert!(excluded.iter().all(|e| e.reason.contains("native-first")));
    }

    #[test]
    fn an_adapter_can_be_enabled_individually() {
        let mut r = Registry::new();
        register_all(&mut r);
        let policy = SelectionPolicy::default().enable("ext.cppcheck");
        let (_, excluded) = r.select(&policy);
        // cppcheck is admitted by policy; whether it is *available* depends on
        // the machine, so it may still be excluded — but not for policy reasons.
        assert!(
            !excluded.iter().any(|e| e.provider.as_str() == "ext.cppcheck"
                && e.reason.contains("native-first"))
        );
    }

    /// `sda tools status` reported `ext.miri — installed` on a machine where
    /// `cargo miri` exits 1 with "the 'miri' component ... is not available".
    /// The probe ran `cargo --version`, and cargo is of course installed — so an
    /// adapter that could not run at all was listed as ready, which is the whole
    /// point of the availability report inverted.
    #[test]
    fn a_cargo_subcommand_is_probed_as_the_subcommand_not_as_cargo() {
        for id in ["ext.clippy", "ext.miri"] {
            let spec = specs().into_iter().find(|s| s.id == id).unwrap();
            assert_eq!(spec.executable, "cargo");
            assert_eq!(
                spec.version_args.first().copied(),
                spec.args.first().copied(),
                "{id}: the probe must name the same subcommand the run does"
            );
        }
    }

    /// A missing cargo subcommand is a missing component, not a missing cargo.
    /// Telling someone to install a tool that is already on their PATH sends
    /// them to fix the wrong thing.
    #[test]
    fn a_missing_subcommand_says_so_rather_than_blaming_the_driver() {
        let spec = specs().into_iter().find(|s| s.id == "ext.miri").unwrap();
        // Cargo itself, with a subcommand it does not have — the same shape as
        // the real failure, and cargo is by definition present here.
        let a = ExternalAdapter::new(AdapterSpec {
            version_args: &["definitely-not-a-subcommand-xyz", "--version"],
            ..spec
        });

        match a.available() {
            Availability::Unavailable { reason } => {
                assert!(reason.contains("the subcommand is not installed"), "got: {reason}");
                assert!(!reason.contains("was not found on PATH"), "got: {reason}");
            }
            other => panic!("expected unavailable, got {other:?}"),
        }
    }

    /// Valgrind's template ended in `{target}`, the project *directory*, so the
    /// adapter asked Valgrind to execute a folder. No placeholder named the
    /// binary, so the template could not be written correctly at all.
    #[test]
    fn a_tool_that_runs_the_program_is_given_the_artifact_not_the_directory() {
        let spec = specs().into_iter().find(|s| s.id == "ext.valgrind").unwrap();
        assert!(
            spec.args.iter().any(|a| a.contains("{artifact}")),
            "valgrind must be pointed at the binary: {:?}",
            spec.args
        );
        assert!(
            !spec.args.iter().any(|a| a.contains("{target}")),
            "and not at the project root: {:?}",
            spec.args
        );

        let a = ExternalAdapter::new(spec);
        let mut target = Target::new("/proj");
        target.artifact = Some("/proj/build/a.out".into());
        assert!(
            a.args_for(&target).contains(&"/proj/build/a.out".to_string()),
            "the placeholder must expand to the artifact"
        );
    }

    /// With no artifact the placeholder would expand to an empty string and
    /// Valgrind would fail in its own words about a stray argument. Refusing up
    /// front says the thing that is actually wrong.
    #[test]
    fn a_tool_needing_an_artifact_refuses_rather_than_running_on_nothing() {
        let spec = specs().into_iter().find(|s| s.id == "ext.valgrind").unwrap();
        let err = ExternalAdapter::new(spec)
            .analyze(&Target::new("/proj"), &RunOptions::default())
            .expect_err("no artifact means no run");
        assert!(err.to_string().contains("--artifact"), "got: {err}");
    }

    #[test]
    fn a_missing_tool_explains_itself_and_points_at_the_native_cover() {
        let a = ExternalAdapter::new(specs()[0].clone()).with_executable("definitely-not-here-xyz");
        match a.available() {
            Availability::Unavailable { reason } => {
                assert!(reason.contains("not found on PATH"));
                assert!(reason.contains("native engines already cover"));
            }
            other => panic!("expected unavailable, got {other:?}"),
        }
    }

    /// `clang-tidy` has no built-in default check set. With no `.clang-tidy`
    /// anywhere above the sources it exits 1 with "no checks enabled" and
    /// analyses nothing, which made the provider useless on a first run — the
    /// one thing the README says must not happen.
    #[test]
    fn clang_tidy_gets_a_default_check_set_when_the_project_configures_none() {
        let dir = tempdir("tidy-no-config");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let mut target = Target::new(&dir).with_files(vec![TargetFile {
            path: dir.join("src").join("main.c"),
            language: Language::C,
            bytes: 10,
        }]);
        target.compile_commands = Some(dir.join("build").join("compile_commands.json"));

        let a = ExternalAdapter::new(
            specs().into_iter().find(|s| s.id == "ext.clang-tidy").unwrap(),
        );
        let args = a.args_for(&target);
        let checks = args
            .iter()
            .find(|x| x.starts_with("-checks="))
            .unwrap_or_else(|| panic!("a default check set must be supplied: {args:?}"));
        assert!(checks.contains("clang-analyzer-"), "{checks}");
        assert!(checks.contains("bugprone-"), "{checks}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The default must not be added on top of a project's own configuration:
    /// `--checks` is *appended* to the file's `Checks` key rather than replacing
    /// it, so injecting one would widen a check set that was narrowed on purpose.
    /// The file is looked for the way clang-tidy looks for it — upward from each
    /// source file — not just in the project root.
    #[test]
    fn a_project_clang_tidy_file_suppresses_the_default_even_above_the_sources() {
        let dir = tempdir("tidy-configured");
        std::fs::create_dir_all(dir.join("src").join("deep")).unwrap();
        // Deliberately at the root, while the source sits two levels below it.
        std::fs::write(dir.join(".clang-tidy"), "Checks: '-*,readability-*'\n").unwrap();

        let mut target = Target::new(&dir).with_files(vec![TargetFile {
            path: dir.join("src").join("deep").join("main.c"),
            language: Language::C,
            bytes: 10,
        }]);
        target.compile_commands = Some(dir.join("build").join("compile_commands.json"));

        let a = ExternalAdapter::new(
            specs().into_iter().find(|s| s.id == "ext.clang-tidy").unwrap(),
        );
        let args = a.args_for(&target);
        assert!(
            !args.iter().any(|x| x.starts_with("-checks=")),
            "the project's own configuration must stand alone: {args:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A tool with no configuration file of its own gets exactly its template,
    /// so the mechanism cannot leak arguments into the other eight adapters.
    #[test]
    fn adapters_without_a_config_file_are_left_alone() {
        for spec in specs().into_iter().filter(|s| s.config_file.is_none()) {
            assert!(
                spec.args_without_config.is_empty(),
                "{}: defaults without a config file to key them to would always apply",
                spec.id
            );
            let a = ExternalAdapter::new(spec.clone());
            // No files and no database, so every placeholder expands to itself
            // or to nothing: the argument count is the template's own.
            assert_eq!(
                a.args_for(&Target::new("/proj")).len(),
                spec.args.iter().filter(|a| **a != "{files}").count(),
                "{}: template gained arguments",
                spec.id
            );
        }
    }

    /// A unique directory under the system temp dir; these tests touch the real
    /// filesystem because the thing under test is a filesystem search.
    fn tempdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sda-adapters-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// `clang-tidy` was handed the compilation database's *file* path as `-p`,
    /// which wants a directory, and the project *root* as its source argument,
    /// which wants files. It printed its usage message and analysed nothing,
    /// and the report said nothing about it. Both placeholders are now distinct.
    #[test]
    fn clang_tidy_is_given_a_build_directory_and_real_source_files() {
        let spec = specs().into_iter().find(|s| s.id == "ext.clang-tidy").unwrap();
        let a = ExternalAdapter::new(spec);

        let root = std::path::Path::new("/proj");
        let db = root.join("build").join("compile_commands.json");
        let mut target = Target::new(root).with_files(vec![TargetFile {
            path: root.join("src").join("main.c"),
            language: Language::C,
            bytes: 10,
        }]);
        target.compile_commands = Some(db.clone());

        let args = a.args_for(&target);
        let p = args.iter().position(|x| x == "-p").expect("-p is passed");
        let dir = &args[p + 1];
        assert!(
            !dir.ends_with("compile_commands.json"),
            "-p takes the directory, not the database file: {dir}"
        );
        assert_eq!(dir, &db.parent().unwrap().to_string_lossy().to_string());

        assert!(
            args.iter().any(|x| x.ends_with("main.c")),
            "the source files must be passed, not the project root: {args:?}"
        );
        assert!(
            !args.iter().any(|x| *x == root.to_string_lossy()),
            "the bare root is not a source file: {args:?}"
        );
    }

    /// A tool that fails and says nothing must not be indistinguishable from a
    /// tool that ran and found nothing clean.
    #[test]
    fn a_provider_that_fails_with_no_output_is_an_error_not_a_clean_result() {
        let spec = AdapterSpec {
            id: "ext.test-fail",
            name: "failing tool",
            executable: if cfg!(windows) { "cmd" } else { "false" },
            args: if cfg!(windows) { &["/C", "exit 3"] } else { &[] },
            version_args: &["--version"],
            config_file: None,
            args_without_config: &[],
            kind: AnalyzerKind::Static,
            languages: &[Language::C],
            capabilities: &[Capability::StyleCompliance],
            format: OutputFormat::GccLike,
            needs_compile_commands: false,
            requires_build: false,
            channel: OutputChannel::Stdout,
            description: "a tool that exits non-zero and prints nothing",
        };
        let a = ExternalAdapter::new(spec);
        let err = a
            .analyze(&Target::new(std::env::temp_dir()), &RunOptions::default())
            .expect_err("a failing tool must not report success");
        let msg = err.to_string();
        assert!(msg.contains("establishes nothing"), "got: {msg}");
    }

    /// A tool that executed the program reports runtime observations, and
    /// `run::analyze` sorts findings onto the static or dynamic side of
    /// correlation by `Finding::phase` alone. Every external finding used to be
    /// born `Static`, so a Memcheck invalid-write — witnessed in a running
    /// process — was filed as a static suspicion and could never act as the
    /// runtime evidence that confirms one. Found by driving the real Valgrind
    /// end to end and reading the report's own phase counts.
    #[test]
    fn a_dynamic_tools_findings_are_dynamic_not_static() {
        let echo: &[&str] = if cfg!(windows) {
            &["/C", "echo ==1== Invalid write of size 4& echo ==1==    at 0x1: main (a.c:3)"]
        } else {
            &["-c", "printf '==1== Invalid write of size 4\\n==1==    at 0x1: main (a.c:3)\\n'"]
        };
        let spec = AdapterSpec {
            id: "ext.test-dynamic",
            name: "a tool that runs the program",
            executable: if cfg!(windows) { "cmd" } else { "sh" },
            args: echo,
            version_args: &["--version"],
            config_file: None,
            args_without_config: &[],
            kind: AnalyzerKind::Dynamic,
            languages: &[Language::C],
            capabilities: &[Capability::MemorySafety],
            format: OutputFormat::ValgrindText,
            needs_compile_commands: false,
            requires_build: false,
            channel: OutputChannel::Stdout,
            description: "emits Memcheck text",
        };
        let found = ExternalAdapter::new(spec)
            .analyze(&Target::new(std::env::temp_dir()), &RunOptions::default())
            .expect("the stub emits parseable output");
        assert!(!found.is_empty(), "the stub must produce a finding to classify");
        assert!(
            found.iter().all(|f| f.phase == sda_core::AnalysisPhase::Dynamic),
            "a tool that executes the program witnesses defects; it does not suspect them"
        );
        // The phase was the precondition; it is not sufficient. Correlation asks
        // `same_defect_class`, which reads the *runtime event kind* off the
        // witness's evidence, and an external finding carried only a
        // `Note`. So the witness returned "relatedness cannot be established"
        // and the confirmation was dropped — the phase fix moved the finding to
        // the right side of correlation and it still could not confirm anything.
        assert!(
            found.iter().all(|f| f.has_runtime_evidence()),
            "a defect witnessed in a running process must carry the runtime event, \
             or correlation cannot tell what class of thing was witnessed"
        );
        let kinds: Vec<_> = found
            .iter()
            .flat_map(|f| f.evidence.iter())
            .filter_map(|e| match e {
                Evidence::Runtime { event } => Some(event.kind),
                _ => None,
            })
            .collect();
        assert_eq!(
            kinds,
            vec![sda_core::RuntimeEventKind::MemoryError],
            "an invalid write is a memory error; the class comes from the CWE the tool stated"
        );
    }

    #[test]
    fn a_tool_needing_compile_commands_refuses_rather_than_guessing() {
        let spec = specs().into_iter().find(|s| s.id == "ext.clang-tidy").unwrap();
        let a = ExternalAdapter::new(spec);
        let target = Target::new("/proj");
        let err = a.analyze(&target, &RunOptions::default()).unwrap_err();
        assert!(err.to_string().contains("compile_commands.json"));
    }

    /// This test used to assert that `clang-tidy` receives the database's file
    /// path, which is what broke it — `-p` takes a directory. Both placeholders
    /// are checked here so the distinction cannot be lost again.
    #[test]
    fn argument_templates_substitute_the_target_and_database() {
        let mut t = Target::new("/proj");
        t.compile_commands = Some("/proj/build/compile_commands.json".into());

        let tidy = ExternalAdapter::new(
            specs().into_iter().find(|s| s.id == "ext.clang-tidy").unwrap(),
        );
        let args = tidy.args_for(&t);
        assert!(
            args.contains(&"/proj/build".to_string()),
            "`-p` must get the directory: {args:?}"
        );
        assert!(
            !args.contains(&"/proj/build/compile_commands.json".to_string()),
            "and not the database file itself: {args:?}"
        );

        // `{compile_commands}` still yields the file, for tools that want it.
        let spec = AdapterSpec {
            id: "ext.db-file",
            name: "db",
            executable: "x",
            args: &["--db", "{compile_commands}", "{target}"],
            version_args: &["--version"],
            config_file: None,
            args_without_config: &[],
            kind: AnalyzerKind::Static,
            languages: &[Language::C],
            capabilities: &[Capability::StyleCompliance],
            format: OutputFormat::GccLike,
            needs_compile_commands: true,
            requires_build: false,
            channel: OutputChannel::Stdout,
            description: "d",
        };
        let other = ExternalAdapter::new(spec).args_for(&t);
        assert!(other.contains(&"/proj/build/compile_commands.json".to_string()));
        // `{target}` is made absolute before substitution — the child's working
        // directory is the target itself, so the root as typed would resolve
        // against itself. This assertion used to be `contains("/proj")`, which
        // pinned the defective behaviour; what matters is that it still names the
        // same directory, so it is checked by suffix rather than by equality.
        let target_arg = other.last().expect("`{target}` is last");
        assert!(
            target_arg.replace('\\', "/").ends_with("/proj"),
            "{target_arg} no longer names the analysis root"
        );
        assert!(std::path::Path::new(target_arg).is_absolute(), "{target_arg}");
    }

    #[test]
    fn cwe_rule_ids_are_turned_into_cross_references() {
        let refs = infer_taxonomy("CWE-787-out-of-bounds");
        assert_eq!(refs[0].id, "CWE-787");
        assert!(infer_taxonomy("bugprone-branch-clone").is_empty());
    }

    #[test]
    fn external_findings_keep_their_own_confidence_rather_than_being_promoted() {
        let f = finding("ext.cppcheck", "nullPointer", "Null pointer dereference", Severity::High, Location::new("a.c", 3, 1));
        assert_eq!(f.confidence, Confidence::Medium);
        assert_eq!(f.provider.as_str(), "ext.cppcheck");
        assert!(f.evidence.iter().any(|e| matches!(e, Evidence::Note { text } if text.contains("external"))));
    }

    #[test]
    fn long_messages_are_summarized_into_a_usable_title() {
        let long = "a".repeat(300);
        let f = finding("p", "r", &long, Severity::Low, Location::new("a.c", 1, 1));
        assert!(f.title.len() <= 120);
        assert_eq!(f.message.len(), 300, "the full message is preserved");
    }

    /// Windows cannot exec a `.bat` directly, and many analysis tools ship as
    /// exactly that. Before this was handled, pointing the toolkit at one gave
    /// an empty result and a confusing parse error instead of findings.
    #[cfg(windows)]
    #[test]
    fn a_batch_wrapper_is_run_through_the_shell() {
        let dir = std::env::temp_dir().join("sda-adapters-batch");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bat = dir.join("tool.bat");
        std::fs::write(&bat, "@echo off\r\necho Cppcheck 2.13.0\r\n").unwrap();

        let adapter = ExternalAdapter::new(specs()[0].clone())
            .with_executable(bat.to_string_lossy().to_string());
        assert!(
            adapter.available().is_usable(),
            "a batch wrapper must be reachable: {:?}",
            adapter.available()
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_explicit_executable_path_overrides_the_default_name() {
        let adapter = ExternalAdapter::new(specs()[0].clone())
            .with_executable("/opt/cppcheck-2.13/bin/cppcheck");
        assert_eq!(
            adapter.info().executable.as_deref(),
            Some("/opt/cppcheck-2.13/bin/cppcheck"),
            "the report must name the binary that actually ran"
        );
    }

    #[test]
    fn registering_with_paths_applies_the_override() {
        let mut registry = Registry::new();
        let paths: BTreeMap<String, String> =
            [("ext.cppcheck".to_string(), "/vendor/cppcheck".to_string())].into_iter().collect();
        register_with_paths(&mut registry, &paths);

        let described = registry.describe();
        let cppcheck = described.iter().find(|p| p.id.as_str() == "ext.cppcheck").unwrap();
        assert_eq!(cppcheck.executable.as_deref(), Some("/vendor/cppcheck"));
        // Adapters without an override keep their default name.
        let clippy = described.iter().find(|p| p.id.as_str() == "ext.clippy").unwrap();
        assert_eq!(clippy.executable.as_deref(), Some("cargo"));
    }

    #[test]
    fn the_availability_report_covers_every_adapter() {
        let r = availability_report();
        assert_eq!(r.len(), specs().len());
    }

    /// A file that crashes the tool costs that file. In one process over PX4's
    /// 5,120 files, the first crash cost everything after it.
    #[test]
    fn a_crash_on_one_file_keeps_the_others_and_names_it() {
        let dir = tempdir("tidy-one-crash");
        let (name, script) = if cfg!(windows) {
            (
                "tool.bat",
                "@echo off\r\n\
                 echo %* | findstr bad.c >nul && exit /b -1073741819\r\n\
                 echo %* | findstr broken.c >nul && echo broken.c:1:1: error: gone [clang-diagnostic-error]\r\n\
                 echo good.c:1:1: warning: seen [bugprone-example]\r\n",
            )
        } else {
            (
                "tool.sh",
                "#!/bin/sh\ncase \"$*\" in *bad.c*) kill -SEGV $$;; esac\n\
                 case \"$*\" in *broken.c*) echo 'broken.c:1:1: error: gone [clang-diagnostic-error]';; esac\n\
                 echo 'good.c:1:1: warning: seen [bugprone-example]'\n",
            )
        };
        let tool = dir.join(name);
        std::fs::write(&tool, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let file = |n: &str| TargetFile { path: dir.join(n), language: Language::C, bytes: 1 };
        let mut target =
            Target::new(&dir).with_files(vec![
                file("good.c"),
                file("bad.c"),
                file("fine.c"),
                file("broken.c"),
            ]);
        target.compile_commands = Some(dir.join("compile_commands.json"));

        let adapter = ExternalAdapter::new(
            specs().into_iter().find(|s| s.id == "ext.clang-tidy").unwrap(),
        )
        .with_executable(tool.to_string_lossy());
        let found = adapter.analyze(&target, &RunOptions::default()).expect("two files finished");

        assert_eq!(found.len(), 4, "{found:?}");
        let notices = adapter.take_notices();
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].reason.contains("finished 2 of 4"), "{}", notices[0].reason);
        assert!(notices[0].reason.contains("bad.c crashed"), "{}", notices[0].reason);
        assert!(notices[0].reason.contains("broken.c did not compile"), "{}", notices[0].reason);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A file with no compile line is not handed to the tool, and the report says
    /// how many were left out. The old run of PX4 had 4,146 partial parses.
    #[test]
    fn only_files_with_a_compile_line_reach_the_tool() {
        let dir = tempdir("tidy-database");
        let (name, script) = if cfg!(windows) {
            ("tool.bat", "@echo off\r\necho %* | findstr other.c >nul && exit /b 3\r\nexit /b 0\r\n")
        } else {
            ("tool.sh", "#!/bin/sh\ncase \"$*\" in *other.c*) exit 3;; esac\n")
        };
        let tool = dir.join(name);
        std::fs::write(&tool, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let listed = dir.join("listed.c");
        let database = dir.join("compile_commands.json");
        let entry = serde_json::json!([{
            "directory": dir,
            "file": listed,
            "command": "cc -c listed.c",
        }]);
        std::fs::write(&database, entry.to_string()).unwrap();
        let file = |path: std::path::PathBuf| TargetFile { path, language: Language::C, bytes: 1 };
        let mut target =
            Target::new(&dir).with_files(vec![file(listed), file(dir.join("other.c"))]);
        target.compile_commands = Some(database);

        let adapter = ExternalAdapter::new(
            specs().into_iter().find(|s| s.id == "ext.clang-tidy").unwrap(),
        )
        .with_executable(tool.to_string_lossy());
        adapter.analyze(&target, &RunOptions::default()).expect("other.c never ran");

        let notices = adapter.take_notices();
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].reason.contains("1 of 2 files"), "{}", notices[0].reason);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The child runs inside the target, so a path relative to the scan's own
    /// directory names a file that is not there.
    #[test]
    fn each_file_reaches_the_tool_as_an_absolute_path() {
        let dir = tempdir("tidy-absolute");
        let (name, script) = if cfg!(windows) {
            ("tool.bat", "@echo off\r\necho %* 1>&2\r\nexit /b 3\r\n")
        } else {
            ("tool.sh", "#!/bin/sh\necho \"$*\" >&2\nexit 3\n")
        };
        let tool = dir.join(name);
        std::fs::write(&tool, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut target = Target::new(&dir).with_files(vec![TargetFile {
            path: std::path::PathBuf::from("relative").join("a.c"),
            language: Language::C,
            bytes: 1,
        }]);
        target.compile_commands = Some(dir.join("compile_commands.json"));

        let adapter = ExternalAdapter::new(
            specs().into_iter().find(|s| s.id == "ext.clang-tidy").unwrap(),
        )
        .with_executable(tool.to_string_lossy());
        let said = adapter.analyze(&target, &RunOptions::default()).unwrap_err().to_string();

        let expected = std::path::absolute(std::path::Path::new("relative").join("a.c")).unwrap();
        assert!(said.contains(&*expected.to_string_lossy()), "{said}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `ExternalAdapter::timeout` was a public field with a ten-minute default
    /// that **nothing read**: `analyze` called `Command::output()`, which waits
    /// forever. Every adapter run until now was over a handful of files, so a
    /// tool that would not finish had never been met. clang-tidy over 184 files
    /// of llama.cpp met it.
    ///
    /// Driven against a real child process, because the thing under test is
    /// process handling and a mock would test the mock.
    #[test]
    fn a_tool_that_will_not_finish_is_stopped_and_says_so() {
        let mut cmd = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.arg("/C").arg("ping -n 60 127.0.0.1 >nul");
            c
        } else {
            let mut c = Command::new("sleep");
            c.arg("60");
            c
        };
        cmd.stdin(std::process::Stdio::null());

        let started = std::time::Instant::now();
        let r = run_with_timeout(cmd, Duration::from_millis(400));
        let waited = started.elapsed();

        assert!(matches!(r, Err(RunFailure::TimedOut)), "the deadline must be enforced");
        assert!(
            waited < Duration::from_secs(20),
            "and enforced promptly rather than after the child finishes: waited {waited:?}"
        );
    }

    /// The other half, and the one that would make a timeout useless if it were
    /// wrong: a tool that finishes must still hand back everything it wrote. The
    /// pipes are drained on their own threads for this reason — a child that
    /// fills its stdout pipe blocks until something reads it, so polling for
    /// exit while holding an unread pipe deadlocks against exactly the tools
    /// this is for. Cppcheck emits megabytes of XML on a real tree.
    #[test]
    fn a_tool_that_finishes_keeps_every_byte_it_wrote() {
        // Enough to exceed a pipe buffer by a wide margin. The bytes are written
        // to a file and copied out, rather than generated a line at a time by
        // the shell: `cmd /C for /L ... do @echo` took **86 seconds** on an idle
        // machine against this 120-second timeout, and went over it whenever the
        // suite ran in parallel. A test that fails from load rather than from the
        // property it checks teaches people to disregard a red run, which is
        // worse than not having it. `type` and `cat` finish in milliseconds and
        // the stream through the pipe is the same size.
        let n = 200_000;
        let dir = std::env::temp_dir().join("sda-pipe-drain-test");
        std::fs::create_dir_all(&dir).expect("a temp directory");
        let file = dir.join("large.txt");
        let line = "xxxxxxxxxxxxxxxxxxxx\n";
        std::fs::write(&file, line.repeat(n / line.len())).expect("the large input");

        let mut cmd = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.arg("/C").arg("type").arg(&file);
            c
        } else {
            let mut c = Command::new("sh");
            c.arg("-c").arg(format!("cat {}", file.display()));
            c
        };
        cmd.stdin(std::process::Stdio::null());

        let out = run_with_timeout(cmd, Duration::from_secs(120)).expect("it finishes");
        let _ = std::fs::remove_file(&file);
        assert!(
            out.stdout.len() > 100_000,
            "a large stream must survive: got {} bytes",
            out.stdout.len()
        );
        assert!(out.status.success());
    }

    /// Real cppcheck 2.21.0 output, shortened: one genuine finding and three
    /// statements about the analysis itself. Over 184 files of llama.cpp the
    /// second kind outnumbered nothing — 321 of 1,453 findings — and every one
    /// was `information` severity.
    const CPPCHECK_WITH_LIMITATIONS: &str = concat!(
        "<results version=\"2\"><cppcheck version=\"2.21.0\"/><errors>",
        "<error id=\"missingIncludeSystem\" severity=\"information\" ",
        "msg=\"Include file: &lt;map&gt; not found.\" verbose=\"Include file: &lt;map&gt; not found.\">",
        "<location file=\"llama-adapter.cpp\" line=\"7\" column=\"0\"/></error>",
        "<error id=\"missingIncludeSystem\" severity=\"information\" ",
        "msg=\"Include file: &lt;set&gt; not found.\" verbose=\"Include file: &lt;set&gt; not found.\">",
        "<location file=\"llama-adapter.cpp\" line=\"8\" column=\"0\"/></error>",
        "<error id=\"toomanyconfigs\" severity=\"information\" ",
        "msg=\"Too many #ifdef configurations - cppcheck only checks 12 of 17 configurations.\" ",
        "verbose=\"Too many #ifdef configurations - cppcheck only checks 12 of 17 configurations.\">",
        "<location file=\"llama-mmap.cpp\" line=\"1\" column=\"0\"/></error>",
        "<error id=\"uninitMemberVar\" severity=\"warning\" cwe=\"457\" ",
        "msg=\"Member variable 'batch::vocab' is not initialized in the constructor.\" ",
        "verbose=\"Member variable 'batch::vocab' is not initialized in the constructor.\">",
        "<location file=\"llama-batch.cpp\" line=\"12\" column=\"21\"/></error>",
        "</errors></results>",
    );

    fn parsed_cppcheck() -> Vec<Finding> {
        parse::parse_cppcheck_xml(CPPCHECK_WITH_LIMITATIONS, "ext.cppcheck").expect("real xml")
    }

    /// The parser's job is to report everything the tool said; deciding which
    /// half of the report a statement belongs in is the adapter's. Keeping that
    /// boundary is why `every_adapter_parses.rs` is unaffected by this.
    #[test]
    fn the_parser_still_reports_every_line_the_tool_wrote() {
        assert_eq!(parsed_cppcheck().len(), 4);
    }

    #[test]
    fn a_tools_statements_about_its_own_analysis_leave_the_findings() {
        let mut findings = parsed_cppcheck();
        let notices = take_self_reported_limitations(&mut findings);

        assert_eq!(findings.len(), 1, "only the uninitialised member is a finding about the code");
        assert_eq!(findings[0].rule.as_str(), "uninitMemberVar");

        // One notice per kind, not one per occurrence: 230 lines saying the same
        // thing is not 230 pieces of news.
        assert_eq!(notices.len(), 2, "missingIncludeSystem and toomanyconfigs");
        assert!(notices.iter().all(|n| n.provider.as_str() == "ext.cppcheck"));
    }

    /// The count and the example are the whole value. "Includes were missing"
    /// invites the reader to assume it was one; "× 2, first of them at
    /// llama-adapter.cpp:7" cannot be misread, and points at where to look.
    #[test]
    fn a_notice_states_how_many_and_quotes_the_first() {
        let mut findings = parsed_cppcheck();
        let notices = take_self_reported_limitations(&mut findings);
        let includes = notices
            .iter()
            .find(|n| n.reason.contains("missingIncludeSystem"))
            .expect("the include notice");
        assert!(includes.reason.contains("2"), "got: {}", includes.reason);
        assert!(includes.reason.contains("llama-adapter.cpp:7"), "got: {}", includes.reason);

        // A single occurrence reads as one thing, not as "× 1".
        let configs = notices
            .iter()
            .find(|n| n.reason.contains("toomanyconfigs"))
            .expect("the configuration notice");
        assert!(configs.reason.contains("12 of 17"), "got: {}", configs.reason);
        assert!(!configs.reason.contains("\u{00d7} 1"), "got: {}", configs.reason);
    }

    /// The reason this moves rather than being filtered. Every one of these is
    /// `information` severity, so the first thing anyone does with a report of a
    /// thousand findings — raise the floor to `medium` — silently discards the
    /// news that the analysis ran on incomplete information. An `Exclusion`
    /// carries no severity and cannot be filtered by one.
    #[test]
    fn a_severity_filter_cannot_discard_the_news_that_analysis_was_degraded() {
        let mut findings = parsed_cppcheck();
        assert!(
            findings
                .iter()
                .filter(|f| f.rule.as_str() == "missingIncludeSystem")
                .all(|f| f.severity == Severity::Info),
            "these arrive at the severity a reader filters away"
        );

        let notices = take_self_reported_limitations(&mut findings);
        assert!(!notices.is_empty());
        // What a `--min-severity medium` reader would be left with, before and
        // after: the findings lose nothing they wanted, and the notice survives.
        let above_info: Vec<_> =
            findings.iter().filter(|f| f.severity != Severity::Info).collect();
        assert_eq!(above_info.len(), 1);
    }

    /// Draining, not reading. A provider is shared behind an `Arc` and may be
    /// asked to run twice; the second report must be about the second run.
    #[test]
    fn notices_are_taken_once() {
        let adapter = ExternalAdapter::new(specs().into_iter().find(|s| s.id == "ext.cppcheck").unwrap());
        adapter.notices.lock().unwrap().push(sda_core::Exclusion {
            provider: "ext.cppcheck".into(),
            reason: "something".into(),
        });
        assert_eq!(adapter.take_notices().len(), 1);
        assert!(adapter.take_notices().is_empty(), "a second collection repeats nothing");
    }
}
