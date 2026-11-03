//! Compiler abstraction.
//!
//! The toolkit has to work with whatever compiler a project already uses — GCC on
//! a Linux target, MSVC on Windows, armclang or IAR on the device that actually
//! ships. Rather than encode one vendor's flags, this module models the *intent*
//! (`sanitize address`, `emit coverage`, `warnings are errors`) and lets each
//! [`Compiler`] translate it, reporting honestly when it cannot.
//!
//! That last part matters more than it sounds. IAR has no AddressSanitizer. A
//! request for one must produce "this toolchain cannot do that", not silently
//! drop the flag and hand back a build the dynamic engine will treat as
//! instrumented.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A compiler family, which determines flag syntax and diagnostic format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Family {
    Gcc,
    Clang,
    /// Microsoft C/C++, whose flags and diagnostics share nothing with the others.
    Msvc,
    /// Arm Compiler 6, which is Clang-derived but not Clang.
    ArmClang,
    /// Legacy Arm Compiler 5.
    ArmCc,
    /// IAR Embedded Workbench.
    Iar,
    /// Texas Instruments code generation tools.
    TiCgt,
    Rustc,
    /// A compiler we do not recognise. Everything degrades to "unknown", which
    /// is the honest answer rather than guessing GCC and emitting bad flags.
    Unknown,
}

impl Family {
    pub fn as_str(&self) -> &'static str {
        match self {
            Family::Gcc => "gcc",
            Family::Clang => "clang",
            Family::Msvc => "msvc",
            Family::ArmClang => "armclang",
            Family::ArmCc => "armcc",
            Family::Iar => "iar",
            Family::TiCgt => "ti-cgt",
            Family::Rustc => "rustc",
            Family::Unknown => "unknown",
        }
    }

    /// Identify a family from a compiler's `--version` output.
    pub fn from_version_output(text: &str) -> Family {
        let t = text.to_ascii_lowercase();
        // Order matters: armclang identifies itself as clang, so it is tested
        // first, and every Apple/vendor clang mentions "clang" somewhere.
        if t.contains("arm compiler") && t.contains("clang") {
            Family::ArmClang
        } else if t.contains("armcc") || t.contains("arm/thumb c/c++ compiler") {
            Family::ArmCc
        } else if t.contains("iar") {
            Family::Iar
        } else if t.contains("ti-cgt") || t.contains("texas instruments") {
            Family::TiCgt
        } else if t.contains("rustc") {
            Family::Rustc
        } else if t.contains("clang") {
            Family::Clang
        } else if t.contains("microsoft") && t.contains("compiler") {
            Family::Msvc
        } else if t.contains("gcc") || t.contains("free software foundation") {
            Family::Gcc
        } else {
            Family::Unknown
        }
    }

    /// Guess from an executable name, used before a probe has run.
    pub fn from_executable(name: &str) -> Family {
        let n = name.to_ascii_lowercase();
        let stem = n.rsplit(['/', '\\']).next().unwrap_or(&n);
        if stem.starts_with("armclang") {
            Family::ArmClang
        } else if stem.starts_with("armcc") {
            Family::ArmCc
        } else if stem.starts_with("iccarm") || stem.starts_with("iccrl") || stem.contains("iar") {
            Family::Iar
        } else if stem.starts_with("cl20") || stem == "cl" || stem == "cl.exe" {
            Family::Msvc
        } else if stem.starts_with("rustc") {
            Family::Rustc
        } else if stem.contains("clang") {
            Family::Clang
        } else if stem.contains("gcc") || stem.contains("g++") || stem.contains("cc") {
            Family::Gcc
        } else {
            Family::Unknown
        }
    }

    /// The diagnostic format this family emits, which the parser needs.
    pub fn diagnostic_format(&self) -> DiagnosticFormat {
        match self {
            Family::Msvc => DiagnosticFormat::Msvc,
            Family::Rustc => DiagnosticFormat::RustcJson,
            Family::Iar => DiagnosticFormat::Iar,
            _ => DiagnosticFormat::GccLike,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticFormat {
    /// `file:line:col: severity: message`
    GccLike,
    /// `file(line,col): severity Cnnnn: message`
    Msvc,
    /// `"file",line severity[Tag]: message`
    Iar,
    RustcJson,
}

/// What we want the build to do, expressed independently of any toolchain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildProfile {
    /// Runtime instrumentation to enable.
    pub sanitizers: Vec<Sanitizer>,
    /// Emit coverage instrumentation, which the correlation engine needs to
    /// tell "did not happen" from "never ran".
    pub coverage: bool,
    /// Keep debug information so runtime evidence can be attributed to source.
    pub debug_info: bool,
    /// Optimisation level as an intent, not a flag.
    pub optimization: Optimization,
    /// Turn warnings into errors.
    pub warnings_as_errors: bool,
    /// Maximum warning verbosity.
    pub all_warnings: bool,
    /// Extra flags passed through verbatim, for anything this model omits.
    pub extra: Vec<String>,
}

impl BuildProfile {
    /// The profile the dynamic engine wants: instrumented, attributable, and
    /// still optimised enough to run at a useful speed.
    pub fn for_dynamic_analysis() -> Self {
        BuildProfile {
            sanitizers: vec![Sanitizer::Address, Sanitizer::UndefinedBehavior],
            coverage: true,
            debug_info: true,
            optimization: Optimization::Debug,
            warnings_as_errors: false,
            all_warnings: true,
            extra: Vec::new(),
        }
    }

    /// The profile for extracting compiler diagnostics as static findings.
    pub fn for_static_analysis() -> Self {
        BuildProfile {
            all_warnings: true,
            debug_info: true,
            optimization: Optimization::None,
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sanitizer {
    Address,
    UndefinedBehavior,
    Thread,
    Memory,
    Leak,
}

impl Sanitizer {
    pub fn as_str(&self) -> &'static str {
        match self {
            Sanitizer::Address => "address",
            Sanitizer::UndefinedBehavior => "undefined",
            Sanitizer::Thread => "thread",
            Sanitizer::Memory => "memory",
            Sanitizer::Leak => "leak",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Optimization {
    None,
    #[default]
    Debug,
    Size,
    Speed,
}

/// A flag the requested profile needed but the toolchain cannot provide.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unsupported {
    pub what: String,
    pub reason: String,
}

/// The result of translating a profile for one toolchain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlagSet {
    pub flags: Vec<String>,
    /// Requests this toolchain could not honour. Never empty silently: a caller
    /// that asked for AddressSanitizer and got none must find out here, not by
    /// wondering why the dynamic run found nothing.
    pub unsupported: Vec<Unsupported>,
}

impl FlagSet {
    pub fn is_fully_supported(&self) -> bool {
        self.unsupported.is_empty()
    }
    /// True when the build will actually carry runtime instrumentation.
    pub fn is_instrumented(&self) -> bool {
        self.flags.iter().any(|f| {
            f.contains("sanitize") || f.contains("coverage") || f.contains("profile") || f == "/fsanitize=address"
        })
    }
}

/// A compiler the toolkit can drive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compiler {
    pub path: PathBuf,
    pub family: Family,
    /// Version string as reported, kept verbatim for the report.
    pub version: String,
    /// Target triple, when the compiler reports one.
    pub target: Option<String>,
}

impl Compiler {
    pub fn new(path: impl Into<PathBuf>, family: Family) -> Self {
        Compiler { path: path.into(), family, version: String::new(), target: None }
    }

    /// Probe a compiler by running it. Returns `None` if it cannot be executed.
    pub fn probe(path: impl Into<PathBuf>) -> Option<Compiler> {
        let path = path.into();
        let name = path.to_string_lossy().to_string();
        // MSVC prints its banner with no arguments; everything else needs a flag.
        let guess = Family::from_executable(&name);
        let args: &[&str] = if guess == Family::Msvc { &[] } else { &["--version"] };

        let out = std::process::Command::new(&path).args(args).output().ok()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if text.trim().is_empty() {
            return None;
        }
        let family = match Family::from_version_output(&text) {
            Family::Unknown => guess,
            f => f,
        };
        let version = text.lines().next().unwrap_or("").trim().to_string();
        let target = parse_target(&text);
        Some(Compiler { path, family, version, target })
    }

    /// Translate a profile into this compiler's flags.
    pub fn flags_for(&self, profile: &BuildProfile) -> FlagSet {
        let mut fs = FlagSet::default();
        match self.family {
            Family::Gcc | Family::Clang | Family::ArmClang => self.gcc_like(profile, &mut fs),
            Family::Msvc => self.msvc(profile, &mut fs),
            Family::Rustc => self.rustc(profile, &mut fs),
            Family::ArmCc | Family::Iar | Family::TiCgt => self.embedded(profile, &mut fs),
            Family::Unknown => {
                fs.unsupported.push(Unsupported {
                    what: "any flag translation".into(),
                    reason: format!(
                        "the compiler at `{}` was not recognised, so no flags can be generated \
                         for it; pass them explicitly through `extra`",
                        self.path.display()
                    ),
                });
                fs.flags.extend(profile.extra.clone());
            }
        }
        fs
    }

    fn gcc_like(&self, p: &BuildProfile, fs: &mut FlagSet) {
        if p.debug_info {
            fs.flags.push("-g".into());
        }
        fs.flags.push(
            match p.optimization {
                Optimization::None => "-O0",
                Optimization::Debug => "-Og",
                Optimization::Size => "-Os",
                Optimization::Speed => "-O2",
            }
            .into(),
        );
        if p.all_warnings {
            fs.flags.push("-Wall".into());
            fs.flags.push("-Wextra".into());
        }
        if p.warnings_as_errors {
            fs.flags.push("-Werror".into());
        }

        for s in &p.sanitizers {
            // armclang targets bare metal, where the sanitizer runtimes do not exist.
            if self.family == Family::ArmClang {
                fs.unsupported.push(Unsupported {
                    what: format!("{} sanitizer", s.as_str()),
                    reason: "armclang targets bare metal, where the sanitizer runtime libraries \
                             are not available; use the native probe instrumentation instead"
                        .into(),
                });
                continue;
            }
            // MemorySanitizer is Clang-only, and needs an instrumented libc.
            if *s == Sanitizer::Memory && self.family != Family::Clang {
                fs.unsupported.push(Unsupported {
                    what: "memory sanitizer".into(),
                    reason: "MemorySanitizer is implemented only by Clang".into(),
                });
                continue;
            }
            fs.flags.push(format!("-fsanitize={}", s.as_str()));
        }
        if !p.sanitizers.is_empty() && fs.is_instrumented() {
            // Without this, a sanitizer report has no source location and the
            // correlation engine cannot attribute it.
            fs.flags.push("-fno-omit-frame-pointer".into());
        }
        if p.coverage {
            if self.family == Family::Clang {
                fs.flags.push("-fprofile-instr-generate".into());
                fs.flags.push("-fcoverage-mapping".into());
            } else {
                fs.flags.push("--coverage".into());
            }
        }
        fs.flags.extend(p.extra.clone());
    }

    fn msvc(&self, p: &BuildProfile, fs: &mut FlagSet) {
        if p.debug_info {
            fs.flags.push("/Zi".into());
        }
        fs.flags.push(
            match p.optimization {
                Optimization::None | Optimization::Debug => "/Od",
                Optimization::Size => "/O1",
                Optimization::Speed => "/O2",
            }
            .into(),
        );
        if p.all_warnings {
            fs.flags.push("/W4".into());
        }
        if p.warnings_as_errors {
            fs.flags.push("/WX".into());
        }
        for s in &p.sanitizers {
            match s {
                Sanitizer::Address => fs.flags.push("/fsanitize=address".into()),
                other => fs.unsupported.push(Unsupported {
                    what: format!("{} sanitizer", other.as_str()),
                    reason: "MSVC implements only AddressSanitizer".into(),
                }),
            }
        }
        if p.coverage {
            fs.unsupported.push(Unsupported {
                what: "coverage instrumentation".into(),
                reason: "MSVC has no compiler-level coverage flag; coverage comes from an \
                         external profiler, so the correlation engine will see no coverage data \
                         and will report findings as unreached rather than refuted"
                    .into(),
            });
        }
        fs.flags.extend(p.extra.clone());
    }

    fn rustc(&self, p: &BuildProfile, fs: &mut FlagSet) {
        if p.debug_info {
            fs.flags.push("-Cdebuginfo=2".into());
        }
        fs.flags.push(
            match p.optimization {
                Optimization::None | Optimization::Debug => "-Copt-level=0",
                Optimization::Size => "-Copt-level=s",
                Optimization::Speed => "-Copt-level=2",
            }
            .into(),
        );
        if p.warnings_as_errors {
            fs.flags.push("-Dwarnings".into());
        }
        for s in &p.sanitizers {
            match s {
                Sanitizer::Address | Sanitizer::Thread | Sanitizer::Memory | Sanitizer::Leak => {
                    fs.flags.push(format!("-Zsanitizer={}", s.as_str()));
                    fs.unsupported.push(Unsupported {
                        what: format!("{} sanitizer", s.as_str()),
                        reason: "rustc sanitizers require a nightly toolchain; the flag is emitted \
                                 but a stable compiler will reject it"
                            .into(),
                    });
                }
                Sanitizer::UndefinedBehavior => fs.unsupported.push(Unsupported {
                    what: "undefined-behaviour sanitizer".into(),
                    reason: "Rust has no UBSan; safe Rust excludes most of what it detects, and \
                             `unsafe` blocks are covered by Miri instead"
                        .into(),
                }),
            }
        }
        if p.coverage {
            fs.flags.push("-Cinstrument-coverage".into());
        }
        fs.flags.extend(p.extra.clone());
    }

    /// Embedded vendor toolchains: no sanitizers, no coverage, different spellings.
    fn embedded(&self, p: &BuildProfile, fs: &mut FlagSet) {
        let iar = self.family == Family::Iar;
        if p.debug_info {
            fs.flags.push(if iar { "--debug".into() } else { "-g".into() });
        }
        fs.flags.push(match (iar, p.optimization) {
            (true, Optimization::None) => "-On".to_string(),
            (true, Optimization::Size) => "-Ohz".to_string(),
            (true, Optimization::Speed) => "-Ohs".to_string(),
            (true, _) => "-Ol".to_string(),
            (false, Optimization::None) => "-O0".to_string(),
            (false, Optimization::Size) => "-Os".to_string(),
            (false, Optimization::Speed) => "-O3".to_string(),
            (false, _) => "-O1".to_string(),
        });
        if !p.sanitizers.is_empty() {
            fs.unsupported.push(Unsupported {
                what: "sanitizers".into(),
                reason: format!(
                    "{} targets bare metal and has no sanitizer runtime. Runtime evidence on this \
                     target must come from the native SDA probe instrumentation, which needs no \
                     runtime library",
                    self.family.as_str()
                ),
            });
        }
        if p.coverage {
            fs.unsupported.push(Unsupported {
                what: "coverage instrumentation".into(),
                reason: format!(
                    "{} has no coverage flag; use the SDA probe shim, or an on-target trace unit",
                    self.family.as_str()
                ),
            });
        }
        fs.flags.extend(p.extra.clone());
    }
}

fn parse_target(text: &str) -> Option<String> {
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("Target: ") {
            return Some(rest.trim().to_string());
        }
        if let Some(rest) = l.strip_prefix("host: ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Compiler executables to look for, in the order a project is most likely to
/// be using them.
pub const CANDIDATES: &[&str] = &[
    "cc", "gcc", "clang", "g++", "clang++", "cl", "armclang", "armcc", "iccarm", "rustc",
];

/// Probe every candidate on `PATH` and return those that answered.
pub fn discover_compilers() -> Vec<Compiler> {
    let mut found = Vec::new();
    for c in CANDIDATES {
        if let Some(compiler) = Compiler::probe(c)
            && !found.iter().any(|f: &Compiler| f.version == compiler.version) {
                found.push(compiler);
            }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_families_from_version_banners() {
        assert_eq!(
            Family::from_version_output("gcc (Ubuntu 13.2.0) 13.2.0\nCopyright (C) Free Software Foundation"),
            Family::Gcc
        );
        assert_eq!(
            Family::from_version_output("Apple clang version 15.0.0 (clang-1500.3.9.4)"),
            Family::Clang
        );
        assert_eq!(
            Family::from_version_output("Microsoft (R) C/C++ Optimizing Compiler Version 19.38"),
            Family::Msvc
        );
        assert_eq!(Family::from_version_output("rustc 1.97.1 (8bab26f4f 2026-07-14)"), Family::Rustc);
    }

    #[test]
    fn armclang_is_not_mistaken_for_clang() {
        let banner = "Product: Arm Compiler for Embedded 6.21\nComponent: Arm Compiler 6.21\n\
                      Tool: armclang [xyz]\nTarget: aarch64-arm-none-eabi";
        assert_eq!(Family::from_version_output(banner), Family::ArmClang);
    }

    #[test]
    fn executable_names_give_a_usable_guess_before_probing() {
        assert_eq!(Family::from_executable("/usr/bin/arm-none-eabi-gcc"), Family::Gcc);
        assert_eq!(Family::from_executable("C:\\...\\cl.exe"), Family::Msvc);
        assert_eq!(Family::from_executable("iccarm"), Family::Iar);
        assert_eq!(Family::from_executable("clang++-17"), Family::Clang);
    }

    #[test]
    fn gcc_translates_a_dynamic_profile_completely() {
        let c = Compiler::new("gcc", Family::Gcc);
        let fs = c.flags_for(&BuildProfile::for_dynamic_analysis());
        assert!(fs.is_fully_supported());
        assert!(fs.flags.contains(&"-fsanitize=address".to_string()));
        assert!(fs.flags.contains(&"-fsanitize=undefined".to_string()));
        assert!(fs.flags.contains(&"--coverage".to_string()));
        assert!(fs.flags.contains(&"-fno-omit-frame-pointer".to_string()));
        assert!(fs.is_instrumented());
    }

    #[test]
    fn clang_uses_its_own_coverage_flags() {
        let c = Compiler::new("clang", Family::Clang);
        let fs = c.flags_for(&BuildProfile::for_dynamic_analysis());
        assert!(fs.flags.contains(&"-fprofile-instr-generate".to_string()));
        assert!(!fs.flags.contains(&"--coverage".to_string()));
    }

    #[test]
    fn msvc_reports_what_it_cannot_do_instead_of_dropping_it() {
        let c = Compiler::new("cl", Family::Msvc);
        let fs = c.flags_for(&BuildProfile::for_dynamic_analysis());
        assert!(fs.flags.contains(&"/fsanitize=address".to_string()));
        assert!(!fs.is_fully_supported());
        let reasons: Vec<&str> = fs.unsupported.iter().map(|u| u.reason.as_str()).collect();
        assert!(
            reasons.iter().any(|r| r.contains("unreached rather than refuted")),
            "the consequence for correlation must be spelled out: {reasons:?}"
        );
    }

    #[test]
    fn embedded_toolchains_refuse_sanitizers_and_say_what_to_use_instead() {
        for family in [Family::Iar, Family::ArmCc, Family::TiCgt, Family::ArmClang] {
            let c = Compiler::new("cc", family);
            let fs = c.flags_for(&BuildProfile::for_dynamic_analysis());
            assert!(!fs.is_fully_supported(), "{family:?} should report unsupported sanitizers");
            assert!(
                fs.unsupported.iter().any(|u| u.reason.contains("probe")),
                "{family:?} must point at the native probe instrumentation"
            );
        }
    }

    #[test]
    fn iar_optimization_flags_use_iar_spellings() {
        let c = Compiler::new("iccarm", Family::Iar);
        let p = BuildProfile { optimization: Optimization::Size, debug_info: true, ..Default::default() };
        let fs = c.flags_for(&p);
        assert!(fs.flags.contains(&"-Ohz".to_string()));
        assert!(fs.flags.contains(&"--debug".to_string()));
    }

    #[test]
    fn an_unknown_compiler_generates_nothing_and_says_so() {
        let c = Compiler::new("/opt/mystery/cc", Family::Unknown);
        let mut p = BuildProfile::for_static_analysis();
        p.extra.push("-custom".into());
        let fs = c.flags_for(&p);
        assert!(!fs.is_fully_supported());
        assert_eq!(fs.flags, vec!["-custom".to_string()], "only pass-through flags survive");
    }

    #[test]
    fn rustc_is_honest_that_sanitizers_need_nightly() {
        let c = Compiler::new("rustc", Family::Rustc);
        let fs = c.flags_for(&BuildProfile::for_dynamic_analysis());
        assert!(fs.flags.contains(&"-Cinstrument-coverage".to_string()));
        assert!(fs.unsupported.iter().any(|u| u.reason.contains("nightly")));
        assert!(fs.unsupported.iter().any(|u| u.reason.contains("Miri")));
    }

    #[test]
    fn diagnostic_format_follows_the_family() {
        assert_eq!(Family::Msvc.diagnostic_format(), DiagnosticFormat::Msvc);
        assert_eq!(Family::Rustc.diagnostic_format(), DiagnosticFormat::RustcJson);
        assert_eq!(Family::ArmClang.diagnostic_format(), DiagnosticFormat::GccLike);
        assert_eq!(Family::Iar.diagnostic_format(), DiagnosticFormat::Iar);
    }

    #[test]
    fn target_triples_are_extracted_when_reported() {
        assert_eq!(
            parse_target("clang version 17\nTarget: x86_64-pc-windows-msvc\nThread model: posix"),
            Some("x86_64-pc-windows-msvc".to_string())
        );
        assert_eq!(parse_target("no target here"), None);
    }
}
