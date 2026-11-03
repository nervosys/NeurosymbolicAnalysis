//! Compiler and build-system backends.
//!
//! The toolkit does not own the project's build. It attaches to whatever is
//! already there: any compiler family, any build system, any target. Three
//! capabilities follow from that, and each is load-bearing for something else:
//!
//! * **Compile lines** ([`system::CompilationDatabase`]) tell semantics-level
//!   checks what a translation unit actually means — which macros are defined,
//!   which headers are on the path, which standard applies.
//! * **Instrumented builds** ([`toolchain::BuildProfile`]) produce the artifact
//!   the dynamic engine executes, with sanitizers and coverage where the
//!   toolchain supports them and an explicit refusal where it does not.
//! * **Diagnostics** ([`diagnostics`]) turn every compiler into an analysis
//!   provider, and give the autonomous SWE loop its feedback signal.

#![forbid(unsafe_code)]

pub mod compdb;
pub mod diagnostics;
pub mod exec;
pub mod system;
pub mod toolchain;

pub use compdb::{
    CompdbResult, Provenance, SuppliedCoverage, ensure as ensure_compile_commands,
    supplied_coverage,
};
pub use diagnostics::{Diagnostic, Level, parse as parse_diagnostics};
pub use exec::{BuildOutcome, build, run_command, test};
pub use system::{BuildSystem, CompilationDatabase, CompileCommand, DetectedBuild, detect};
pub use toolchain::{
    BuildProfile, Compiler, Family, FlagSet, Optimization, Sanitizer, discover_compilers,
};

/// Everything the toolkit could learn about how a project builds.
#[derive(Clone, Debug)]
pub struct BuildContext {
    pub builds: Vec<DetectedBuild>,
    pub compilers: Vec<Compiler>,
    pub database: Option<CompilationDatabase>,
}

impl BuildContext {
    /// Inspect a project root without building anything.
    pub fn probe(root: impl AsRef<std::path::Path>) -> BuildContext {
        let root = root.as_ref();
        let builds = detect(root);
        let database = system::find_compile_commands(root)
            .and_then(|p| CompilationDatabase::load(&p).ok());
        BuildContext { builds, compilers: discover_compilers(), database }
    }

    /// The build system to drive, when there is an obvious one.
    pub fn primary(&self) -> Option<&DetectedBuild> {
        self.builds.first()
    }

    /// Whether semantics-level analysis is possible at all right now.
    pub fn supports_semantic_analysis(&self) -> bool {
        self.database.as_ref().is_some_and(|d| !d.is_empty())
            || self.builds.iter().any(|b| b.system == BuildSystem::Cargo)
    }

    /// A plain-language account of what this project's build allows and blocks.
    pub fn summary(&self) -> String {
        let mut s = String::new();
        match self.primary() {
            Some(b) => s.push_str(&format!("Build system: {}. {}\n", b.system.as_str(), b.next_step())),
            None => s.push_str("No build system was recognised; only source-level checks can run.\n"),
        }
        if self.compilers.is_empty() {
            s.push_str("No compiler was found on PATH, so no instrumented build can be produced \
                        and no compiler diagnostics can be collected.\n");
        } else {
            let names: Vec<String> = self
                .compilers
                .iter()
                .map(|c| format!("{} ({})", c.path.display(), c.family.as_str()))
                .collect();
            s.push_str(&format!("Compilers: {}\n", names.join(", ")));
        }
        if let Some(db) = &self.database {
            s.push_str(&format!("Compilation database: {} translation unit(s).\n", db.len()));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn a_cargo_project_supports_semantic_analysis_without_a_database() {
        let d = std::env::temp_dir().join("sda-buildctx-cargo");
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("Cargo.toml"), "[package]\nname=\"x\"\n").unwrap();

        let ctx = BuildContext { builds: detect(&d), compilers: vec![], database: None };
        assert!(ctx.supports_semantic_analysis());
        assert!(ctx.summary().contains("cargo"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_c_project_without_a_database_says_semantics_are_blocked() {
        let d = std::env::temp_dir().join("sda-buildctx-cmake");
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("CMakeLists.txt"), "project(x)").unwrap();

        let ctx = BuildContext { builds: detect(&d), compilers: vec![], database: None };
        assert!(!ctx.supports_semantic_analysis());
        let s = ctx.summary();
        assert!(s.contains("CMAKE_EXPORT_COMPILE_COMMANDS"));
        assert!(s.contains("No compiler was found"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_unrecognised_project_degrades_to_source_level_checks() {
        let d = std::env::temp_dir().join("sda-buildctx-none");
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let ctx = BuildContext { builds: detect(&d), compilers: vec![], database: None };
        assert!(ctx.primary().is_none());
        assert!(ctx.summary().contains("only source-level checks"));
        fs::remove_dir_all(&d).ok();
    }
}
