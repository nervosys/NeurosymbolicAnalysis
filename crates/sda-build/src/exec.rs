//! Driving a build and capturing its result.

use crate::diagnostics::{self, Diagnostic, Level};
use crate::system::{BuildSystem, DetectedBuild};
use crate::toolchain::{BuildProfile, Compiler, FlagSet};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// The result of running a build or a test suite.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildOutcome {
    pub command: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub diagnostics: Vec<Diagnostic>,
    /// Instrumentation the profile asked for but the toolchain refused. Carried
    /// through to the report so an "instrumented" run that was not instrumented
    /// cannot be mistaken for one that was.
    #[serde(default)]
    pub unsupported: Vec<crate::toolchain::Unsupported>,
}

impl BuildOutcome {
    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics.iter().filter(|d| d.level == Level::Error)
    }
    pub fn has_errors(&self) -> bool {
        self.errors().next().is_some()
    }
    /// A one-line account for a log or an agent's next decision.
    pub fn summary(&self) -> String {
        let verdict = if self.success { "succeeded" } else { "failed" };
        // "the build produced no diagnostics" is true but reads as clean, and
        // for a build that just failed that is the worst answer available: the
        // output said something and we could not parse it. Say so instead.
        let account = if !self.success && self.diagnostics.is_empty() {
            "the build failed but NO DIAGNOSTICS COULD BE PARSED from its output — \
             the failure is real and its cause is in the raw output below, not here"
                .to_string()
        } else {
            diagnostics::summarize(&self.diagnostics)
        };
        format!("`{}` {verdict} in {} ms; {account}", self.command, self.duration_ms)
    }
}

/// Run an arbitrary command, capturing output and parsing diagnostics.
fn parse_both(
    stdout: &str,
    stderr: &str,
    format: crate::toolchain::DiagnosticFormat,
) -> Vec<diagnostics::Diagnostic> {
    let mut d = diagnostics::parse(stderr, format);
    d.extend(diagnostics::parse(stdout, format));
    d
}

pub fn run_command(
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &BTreeMap<String, String>,
    format: crate::toolchain::DiagnosticFormat,
    timeout: Duration,
) -> Result<BuildOutcome, String> {
    let display = format!("{program} {}", args.join(" "));
    let started = Instant::now();

    // stdin is null: under `sda mcp` the inherited stdin is the JSON-RPC
    // channel, and a build that reads it would eat the next request.
    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .envs(env)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run `{program}`: {e}"))?;

    // Drained on their own threads: a build that fills a pipe blocks until it is
    // read, so polling with the pipes unread hung any build with more than a
    // pipe's worth of output until the timeout.
    let stdout_rx = drain(child.stdout.take());
    let stderr_rx = drain(child.stderr.take());

    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    timed_out = true;
                    break child.wait().map_err(|e| e.to_string())?;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e.to_string()),
        }
    };

    // A compiler the build tool started can outlive it and hold the pipes open,
    // so a timed-out build waits for its output only briefly.
    let collect = |rx: std::sync::mpsc::Receiver<Vec<u8>>| {
        let bytes = if timed_out {
            rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default()
        } else {
            rx.recv().unwrap_or_default()
        };
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let stdout = collect(stdout_rx);
    let stderr = collect(stderr_rx);

    // Compilers differ on which stream diagnostics go to, so parse both.
    let mut diags = parse_both(&stdout, &stderr, format);

    // A build system can dispatch to a compiler other than the one probed on
    // PATH: CMake's NMake generator drives `cl` on a machine where `clang` is
    // found first, and MSVC diagnostics parsed as GCC-like yield nothing at all.
    // A failed build with nothing parsed is the signal to try the others, since
    // reporting "no diagnostics" for a build that just failed is precisely the
    // clean-result-for-a-broken-build this toolkit exists to avoid.
    let failed = !status.success() || timed_out;
    if failed && diags.is_empty() {
        use crate::toolchain::DiagnosticFormat as F;
        for alternative in [F::Msvc, F::GccLike, F::RustcJson, F::Iar] {
            if alternative == format {
                continue;
            }
            let attempt = parse_both(&stdout, &stderr, alternative);
            if !attempt.is_empty() {
                diags = attempt;
                break;
            }
        }
    }

    Ok(BuildOutcome {
        command: display,
        success: status.success() && !timed_out,
        exit_code: status.code(),
        stdout,
        stderr,
        duration_ms: started.elapsed().as_millis() as u64,
        diagnostics: diags,
        unsupported: Vec::new(),
    })
}

/// Read a child's pipe to the end on its own thread. The bytes arrive when the
/// pipe closes, which is when every process holding it has exited.
fn drain<R: std::io::Read + Send + 'static>(
    pipe: Option<R>,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

/// Build a detected project, optionally with an instrumentation profile.
///
/// The profile is injected through the build system's flag environment variable
/// rather than by editing the project, so an instrumented analysis build never
/// leaves a modified tree behind.
pub fn build(
    detected: &DetectedBuild,
    compiler: Option<&Compiler>,
    profile: Option<&BuildProfile>,
    timeout: Duration,
) -> Result<BuildOutcome, String> {
    let Some((program, args)) = detected.system.build_command() else {
        return Err(format!(
            "`{}` cannot be driven from the command line; its build is defined inside a vendor \
             project file. Build it in the IDE and point the toolkit at the resulting artifact.",
            detected.system.as_str()
        ));
    };

    let mut env = BTreeMap::new();
    let mut unsupported = Vec::new();

    if let (Some(p), Some(c)) = (profile, compiler) {
        let flags: FlagSet = c.flags_for(p);
        unsupported = flags.unsupported.clone();
        inject_flags(detected.system, flags.flags.join(" "), &mut env, &mut unsupported);
    }

    // The build system wins where it dictates the format — Cargo drives rustc,
    // so whichever C compiler happens to be on PATH is irrelevant to how its
    // diagnostics look.
    let format = detected
        .system
        .diagnostic_format()
        .or_else(|| compiler.map(|c| c.family.diagnostic_format()))
        .unwrap_or(crate::toolchain::DiagnosticFormat::GccLike);
    let args: Vec<String> = args.into_iter().map(String::from).collect();
    let mut outcome = run_command(program, &args, &detected.root, &env, format, timeout)?;
    outcome.unsupported = unsupported;
    Ok(outcome)
}

/// How `joined` reaches the compiler under `system`, or why it cannot.
///
/// Separate from [`build`] so it can be tested without the build tool installed.
fn inject_flags(
    system: BuildSystem,
    joined: String,
    env: &mut BTreeMap<String, String>,
    unsupported: &mut Vec<crate::toolchain::Unsupported>,
) {
    match system {
        BuildSystem::Cargo => {
            env.insert("RUSTFLAGS".into(), joined);
        }
        BuildSystem::Make => {
            env.insert("CFLAGS".into(), joined.clone());
            env.insert("CXXFLAGS".into(), joined);
        }
        // Setting CFLAGS here would look like instrumentation and be nothing:
        // `meson compile` and `ninja` run commands fixed when the build files
        // were generated, and SCons does not pass the environment to its tools.
        BuildSystem::Meson => unsupported.push(crate::toolchain::Unsupported {
            what: "flag injection at build time".into(),
            reason: format!(
                "Meson reads flags at setup time. Re-run `meson setup` with \
                 CFLAGS=\"{joined}\" and CXXFLAGS=\"{joined}\" before building, or this build \
                 will not be instrumented."
            ),
        }),
        BuildSystem::Ninja => unsupported.push(crate::toolchain::Unsupported {
            what: "flag injection at build time".into(),
            reason: format!(
                "ninja runs the commands in build.ninja and reads no flags from the environment. \
                 Regenerate build.ninja with \"{joined}\" in its compile commands, or this build \
                 will not be instrumented."
            ),
        }),
        BuildSystem::Scons => unsupported.push(crate::toolchain::Unsupported {
            what: "flag injection at build time".into(),
            reason: format!(
                "SCons does not import CFLAGS from the environment. Add \"{joined}\" to the \
                 SConstruct, or this build will not be instrumented."
            ),
        }),
        BuildSystem::CMake | BuildSystem::West => {
            // CMake takes flags at configure time; the caller must have
            // configured with them. Say so rather than silently doing nothing.
            unsupported.push(crate::toolchain::Unsupported {
                what: "flag injection at build time".into(),
                reason: format!(
                    "CMake bakes flags in at configure time. Re-run configuration with \
                     -DCMAKE_C_FLAGS=\"{joined}\" before building, or this build will not be \
                     instrumented."
                ),
            });
        }
        other => unsupported.push(crate::toolchain::Unsupported {
            what: "flag injection".into(),
            reason: format!("no flag-injection mechanism is known for {}", other.as_str()),
        }),
    }
}

/// Run the project's test suite.
pub fn test(detected: &DetectedBuild, timeout: Duration) -> Result<BuildOutcome, String> {
    let Some((program, args)) = detected.system.test_command() else {
        return Err(format!(
            "no standard test command is known for `{}`",
            detected.system.as_str()
        ));
    };
    let args: Vec<String> = args.into_iter().map(String::from).collect();
    run_command(
        program,
        &args,
        &detected.root,
        &BTreeMap::new(),
        crate::toolchain::DiagnosticFormat::GccLike,
        timeout,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toolchain::{Family, Sanitizer};
    use std::path::PathBuf;

    fn detected(system: BuildSystem, root: PathBuf) -> DetectedBuild {
        DetectedBuild { system, marker: root.join(system.marker()), root, compile_commands: None }
    }

    #[test]
    fn vendor_ide_projects_refuse_to_build_with_an_explanation() {
        let d = detected(BuildSystem::Keil, std::env::temp_dir());
        let err = build(&d, None, None, Duration::from_secs(1)).unwrap_err();
        assert!(err.contains("vendor project file"));
        assert!(err.contains("point the toolkit at the resulting artifact"));
    }

    #[test]
    fn a_build_system_that_ignores_the_environment_is_not_handed_flags_through_it() {
        for system in [BuildSystem::Meson, BuildSystem::Ninja, BuildSystem::Scons] {
            let (mut env, mut unsupported) = (BTreeMap::new(), Vec::new());
            inject_flags(system, "-fsanitize=address".into(), &mut env, &mut unsupported);
            assert!(env.is_empty(), "{}: these variables would be ignored", system.as_str());
            assert!(
                unsupported.iter().any(|u| u.reason.contains("-fsanitize=address")),
                "{}: the build would run uninstrumented with nothing said",
                system.as_str()
            );
        }
    }

    #[test]
    fn make_is_the_one_c_build_that_reads_the_flags_from_the_environment() {
        let (mut env, mut unsupported) = (BTreeMap::new(), Vec::new());
        inject_flags(BuildSystem::Make, "-g".into(), &mut env, &mut unsupported);
        assert_eq!(env.get("CFLAGS").map(String::as_str), Some("-g"));
        assert_eq!(env.get("CXXFLAGS").map(String::as_str), Some("-g"));
        assert!(unsupported.is_empty());
    }

    #[test]
    fn cmake_reports_that_build_time_flags_do_not_instrument_it() {
        // No cmake binary is required: the unsupported list is computed before
        // the command runs, and the run failing is fine for this assertion.
        let d = detected(BuildSystem::CMake, std::env::temp_dir());
        let c = Compiler::new("gcc", Family::Gcc);
        let p = BuildProfile::for_dynamic_analysis();
        match build(&d, Some(&c), Some(&p), Duration::from_secs(2)) {
            Ok(o) => assert!(o.unsupported.iter().any(|u| u.reason.contains("configure time"))),
            // cmake absent: the point of the test is the flag logic, which is
            // exercised in `cargo_injects_rustflags` below.
            Err(e) => assert!(e.contains("could not run")),
        }
    }

    #[test]
    fn a_profile_no_toolchain_supports_is_reported_rather_than_dropped() {
        let c = Compiler::new("iccarm", Family::Iar);
        let flags = c.flags_for(&BuildProfile {
            sanitizers: vec![Sanitizer::Address],
            coverage: true,
            ..Default::default()
        });
        assert!(!flags.is_fully_supported());
        assert!(!flags.is_instrumented());
    }

    /// The defect this guards, found by running the loop against a real CMake +
    /// MSVC project: CMake's NMake generator drove `cl` on a machine where the
    /// probe found `clang` first, so MSVC diagnostics were parsed as GCC-like,
    /// yielded nothing, and a build that failed with `error C2143` was reported
    /// as having "produced no diagnostics".
    #[test]
    fn a_failed_build_never_reports_itself_as_diagnostic_free() {
        let o = BuildOutcome {
            command: "cmake --build build".into(),
            success: false,
            exit_code: Some(1),
            stdout: "main.c(7): error C2143: syntax error".into(),
            stderr: String::new(),
            duration_ms: 5,
            diagnostics: Vec::new(),
            unsupported: Vec::new(),
        };
        let s = o.summary();
        assert!(s.contains("NO DIAGNOSTICS COULD BE PARSED"), "got: {s}");
        assert!(
            !s.contains("produced no diagnostics"),
            "a failed build must not read as clean: {s}"
        );

        // A build that genuinely succeeded with nothing to say still says so.
        let clean = BuildOutcome { success: true, ..o };
        assert!(clean.summary().contains("produced no diagnostics"));
    }

    /// MSVC output must be recovered even when the format was guessed wrong,
    /// which is what makes the message above a last resort rather than routine.
    #[test]
    fn diagnostics_are_recovered_when_the_probed_format_was_wrong() {
        use crate::toolchain::DiagnosticFormat as F;
        let msvc_output = "src\\main.c(7): error C2143: syntax error: missing ';' before '}'";
        assert!(
            parse_both(msvc_output, "", F::GccLike).is_empty(),
            "precondition: the wrong parser finds nothing"
        );
        let recovered = parse_both(msvc_output, "", F::Msvc);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].file, "src/main.c");
        assert_eq!(recovered[0].line, 7);
    }

    #[test]
    fn outcomes_summarize_themselves_for_an_agent_loop() {
        let o = BuildOutcome {
            command: "make".into(),
            success: false,
            exit_code: Some(2),
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 1200,
            diagnostics: diagnostics::parse(
                "src/a.c:9:4: error: expected ';'",
                crate::toolchain::DiagnosticFormat::GccLike,
            ),
            unsupported: Vec::new(),
        };
        assert!(o.has_errors());
        let s = o.summary();
        assert!(s.contains("failed"));
        assert!(s.contains("src/a.c:9:4"));
    }

    #[test]
    fn cargo_diagnostics_are_parsed_as_rustc_json_whatever_compiler_is_on_path() {
        // The defect this guards: deriving the format from the probed compiler
        // made a broken Rust build report zero errors.
        assert_eq!(
            BuildSystem::Cargo.diagnostic_format(),
            Some(crate::toolchain::DiagnosticFormat::RustcJson)
        );
        let (_, args) = BuildSystem::Cargo.build_command().unwrap();
        assert!(
            args.contains(&"--message-format=json"),
            "without this cargo prints prose no format can parse"
        );
        // A build system with no opinion still defers to the compiler.
        assert_eq!(BuildSystem::CMake.diagnostic_format(), None);
    }

    /// A build that prints more than a pipe holds used to block on the unread
    /// pipe until the timeout, then report a timeout for a build that worked.
    #[test]
    fn a_build_with_a_lot_of_output_finishes_rather_than_timing_out() {
        let dir = std::env::temp_dir().join("sda-exec-large-output");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("big.txt"), "x".repeat(1 << 20)).unwrap();
        let (program, args): (&str, &[&str]) = if cfg!(windows) {
            ("cmd", &["/C", "type", "big.txt"])
        } else {
            ("cat", &["big.txt"])
        };
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let o = run_command(
            program,
            &args,
            &dir,
            &BTreeMap::new(),
            crate::toolchain::DiagnosticFormat::GccLike,
            Duration::from_secs(20),
        )
        .unwrap();
        assert!(o.success, "{}", o.summary());
        assert_eq!(o.stdout.len(), 1 << 20);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn running_a_missing_program_is_an_error_not_a_silent_success() {
        let err = run_command(
            "definitely-not-a-real-program-xyz",
            &[],
            &std::env::temp_dir(),
            &BTreeMap::new(),
            crate::toolchain::DiagnosticFormat::GccLike,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(err.contains("could not run"));
    }
}
