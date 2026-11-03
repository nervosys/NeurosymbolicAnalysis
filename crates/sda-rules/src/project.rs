//! Project-level configuration, discovered from a `.sda/` directory.
//!
//! Two things a real compliance project needs to keep in version control next to
//! the code, rather than passing on a command line every time:
//!
//! * `.sda/deviations.toml` — the approved departures, which are as much a part
//!   of the compliance record as the code is.
//! * `.sda/misra-c-2023.toml` (and friends) — an authoritative guideline list
//!   licensed from the standards body, merged over the built-in catalogue so
//!   citations become real rule numbers instead of clause references.
//!
//! Discovery walks upward from the analysis root, the way `.git` and
//! `.editorconfig` are found, so analysing a subdirectory of a project still
//! picks up that project's compliance configuration.

use crate::{ArchitectureDeclaration, Catalog, DeviationRegister, ScopeRegister, Standard};
use std::path::{Path, PathBuf};

/// The configuration directory name.
pub const CONFIG_DIR: &str = ".sda";

/// How far up the tree to look before giving up.
const MAX_DEPTH: usize = 32;

/// Find the `.sda` directory governing `start`, searching upward.
pub fn find_config_dir(start: &Path) -> Option<PathBuf> {
    let mut current = if start.is_dir() {
        Some(start.to_path_buf())
    } else {
        start.parent().map(Path::to_path_buf)
    }?;

    for _ in 0..MAX_DEPTH {
        let candidate = current.join(CONFIG_DIR);
        if candidate.is_dir() {
            return Some(candidate);
        }
        current = current.parent()?.to_path_buf();
    }
    None
}

/// What was loaded, and what went wrong doing it.
#[derive(Debug, Default)]
pub struct ProjectConfig {
    pub config_dir: Option<PathBuf>,
    pub deviations: Option<DeviationRegister>,
    /// The declared analysis scope. `None` means everything discovered is in
    /// scope, which is the default and must stay so.
    pub scope: Option<ScopeRegister>,
    /// The declared shape of a hybrid system. `None` means no interposition
    /// claim is attempted — reported, not passed as clean.
    pub architecture: Option<ArchitectureDeclaration>,
    /// Standards whose catalogue was overridden, and how many rules were merged.
    pub imported: Vec<(Standard, usize)>,
    /// Problems worth surfacing. Never silently swallowed: a deviation register
    /// that failed to load must not look like a project with no deviations.
    pub problems: Vec<String>,
    /// The subset of `problems` where part of the configuration did not take
    /// effect and nothing downstream reports the consequence.
    ///
    /// These have to reach the *report*, not just the terminal. Every entry was
    /// printed as `warning:` on stderr and went no further, so
    /// `sda scan --format json > report.json` dropped it: a project declaring
    /// two components, one of them rejected, produced a saved report with no
    /// trace of the rejection and an interposition result computed over a graph
    /// smaller than the file describes. Measured, not supposed.
    ///
    /// Use [`ProjectConfig::dropped`] and [`ProjectConfig::advisory`] rather
    /// than pushing here directly; the two of them force the question at every
    /// site, which is what keeps this list honest.
    pub unapplied: Vec<String>,
}

impl ProjectConfig {
    /// A problem that also narrowed the run: it must reach the report.
    ///
    /// The user asked for something and did not get it. A clean result computed
    /// without it is not a clean result about the thing they configured.
    fn dropped(&mut self, message: String) {
        self.problems.push(message.clone());
        self.unapplied.push(message);
    }

    /// A problem the reader should see, where the report already accounts for
    /// the consequence by another route.
    ///
    /// Two entries saying the same thing in different words is its own defect —
    /// it teaches people to skim the section that exists to be read. So this is
    /// for the cases where something downstream already states the consequence,
    /// and each use says which.
    fn advisory(&mut self, message: String) {
        self.problems.push(message);
    }

    /// Load whatever `.sda/` governs `root`.
    pub fn discover(root: &Path) -> ProjectConfig {
        let mut config = ProjectConfig::default();
        let Some(dir) = find_config_dir(root) else {
            return config;
        };

        let deviations_path = dir.join("deviations.toml");
        if deviations_path.exists() {
            match std::fs::read_to_string(&deviations_path) {
                Ok(text) => match DeviationRegister::parse(&text) {
                    Ok(register) => {
                        for r in register.rejected() {
                            // Advisory because the engine already puts every
                            // rejected deviation in `NOT CHECKED` itself, from the
                            // register it was handed — see `run::analyze`. That
                            // path also covers callers who never built a
                            // `ProjectConfig`, so it stays where it is, and this
                            // must not say it a second time.
                            config.advisory(format!(
                                "deviation for `{}` rejected: {}",
                                r.rule, r.reason
                            ));
                        }
                        config.deviations = Some(register);
                    }
                    // A register that would not load is a different matter: there
                    // is no register to report from, so the run has no deviations
                    // and nothing downstream knows any were intended.
                    Err(e) => config.dropped(format!("{}: {e}", deviations_path.display())),
                },
                Err(e) => config.dropped(format!("{}: {e}", deviations_path.display())),
            }
        }

        // Same discipline as the register above: a scope declaration that fails
        // to load must not read as "no exclusions". It must also not read as
        // "everything excluded" — a broken scope file leaves the scan wide,
        // which over-reports, and over-reporting is the recoverable direction.
        let scope_path = dir.join("scope.toml");
        if scope_path.exists() {
            match std::fs::read_to_string(&scope_path) {
                Ok(text) => match ScopeRegister::parse(&text) {
                    Ok(register) => {
                        for r in register.rejected() {
                            config.dropped(format!(
                                "scope rule for `{}` rejected: {}",
                                r.path, r.reason
                            ));
                        }
                        config.scope = Some(register);
                    }
                    Err(e) => config.dropped(format!("{}: {e}", scope_path.display())),
                },
                Err(e) => config.dropped(format!("{}: {e}", scope_path.display())),
            }
        }

        // Same discipline again, and here the stakes are sharper. A bad scope
        // rule over-excludes and under-reports; a bad architecture entry
        // produces a *proof* about a system that is not the one being shipped,
        // because the interposition check walks exactly the paths this declares.
        let arch_path = dir.join("architecture.toml");
        if arch_path.exists() {
            match std::fs::read_to_string(&arch_path) {
                Ok(text) => match ArchitectureDeclaration::parse(&text) {
                    Ok(decl) => {
                        for r in decl.rejected() {
                            config.dropped(format!(
                                "architecture entry `{}` rejected: {}",
                                r.subject, r.reason
                            ));
                        }
                        // `warnings()` had no caller but its tests, so a mistyped flow
                        // edge left the proof and told nobody.
                        let ignored = decl.ignored();
                        for w in decl.warnings() {
                            if ignored.contains(&w) {
                                config.dropped(w);
                            } else {
                                config.advisory(w);
                            }
                        }
                        for w in decl.warnings() {
                            // Advisory: the declaration was accepted, and the
                            // consequence each warning describes is re-derived
                            // downstream where it bites. `no component is declared
                            // an effector` arrives in the report as
                            // `sda.interposition: sda.no-effector` from the
                            // interposition layer itself, which is the one that
                            // could not ask the question.
                            config.advisory(format!("architecture: {w}"));
                        }
                        config.architecture = Some(decl);
                    }
                    Err(e) => config.dropped(format!("{}: {e}", arch_path.display())),
                },
                Err(e) => config.dropped(format!("{}: {e}", arch_path.display())),
            }
        }

        // The same discipline once more, for the one `.sda/` file that never had
        // it. A project may ship its own transcription of a standard — that is
        // how the licensed rule text gets in, and what `unconfirmed_numbers`
        // counts down. `catalog()` discarded both failures: an unreadable file
        // through an `if let Ok` with no `else`, and a malformed one through
        // `let _ = catalog.import(&text)`. Either left the built-in catalogue
        // silently in place, so `sda rules audit` went on describing a catalogue
        // the project had tried to replace, and the conformance argument rested
        // on rule text nobody had supplied.
        //
        // Validated here rather than in `catalog()` because this runs once per
        // run, while `catalog()` is called per analyzer; and because every other
        // declaration is checked at load, which is where a reader looks for the
        // reason their file did nothing.
        for standard in Standard::all() {
            let path = dir.join(format!("{}.toml", standard.as_str()));
            if !path.exists() {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let mut catalog = Catalog::load(*standard);
                    match catalog.import(&text) {
                        Err(e) => config.dropped(format!("{}: {e}", path.display())),
                        // `s = "system"` is parsed into `Rule::scope`, which no check reads:
                        // the declaration was accepted and changes nothing, so say so.
                        Ok(_) => {
                            let n = catalog.imported_system_scope();
                            if n > 0 {
                                config.dropped(format!(
                                    "{}: {n} imported rule(s) declare system scope; no analysis \
                                     reads a rule's scope, so that declaration did not take effect",
                                    path.display()
                                ));
                            }
                        }
                    }
                }
                Err(e) => config.dropped(format!("{}: {e}", path.display())),
            }
        }

        config.config_dir = Some(dir);
        config
    }

    /// The directory this configuration governs: the parent of the `.sda/` it
    /// was loaded from.
    ///
    /// Every path in a declaration — a scope rule today — is relative to this,
    /// **not** to whatever directory the user asked to scan. `.sda/` is found by
    /// searching upward, so the two differ whenever a subdirectory is scanned,
    /// and a rule that quietly stops applying is worse than no rule at all.
    pub fn root(&self) -> Option<&Path> {
        self.config_dir.as_deref().and_then(Path::parent)
    }

    /// Load a catalogue with any project override merged over it.
    ///
    /// A failed read or a failed import leaves the built-in catalogue in place,
    /// which is the recoverable direction: the built-in text describes every
    /// guideline and merely lacks the licensed wording, so the scan over-reports
    /// rather than going quiet. The failure itself is not swallowed — it is
    /// recorded as a problem by [`ProjectConfig::discover`], which is where every
    /// other `.sda/` declaration reports its failures, and reaches the reader
    /// through the same channel.
    pub fn catalog(&self, standard: Standard) -> Catalog {
        let mut catalog = Catalog::load(standard);
        let Some(dir) = &self.config_dir else {
            return catalog;
        };
        let path = dir.join(format!("{}.toml", standard.as_str()));
        if !path.exists() {
            return catalog;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            let _ = catalog.import(&text);
        }
        catalog
    }

    /// Load every catalogue with overrides applied, reporting what was merged.
    pub fn catalogs(&mut self) -> Vec<Catalog> {
        let mut out = Vec::new();
        for standard in Standard::all() {
            let before = Catalog::load(*standard).audit().unconfirmed_numbers;
            let catalog = self.catalog(*standard);
            let after = catalog.audit().unconfirmed_numbers;
            if after < before {
                self.imported.push((*standard, before - after));
            }
            out.push(catalog);
        }
        out
    }

    /// A line for the run's log, so an operator sees what configuration applied.
    pub fn summary(&self) -> String {
        match &self.config_dir {
            None => "no .sda/ configuration found; using built-in catalogues and no deviations"
                .to_string(),
            Some(dir) => {
                let mut s = format!("configuration from {}", dir.display());
                if let Some(d) = &self.deviations {
                    s.push_str(&format!(", {} deviation(s)", d.len()));
                }
                if let Some(sc) = &self.scope {
                    s.push_str(&format!(", {} scope exclusion(s)", sc.len()));
                }
                if let Some(a) = &self.architecture {
                    s.push_str(&format!(
                        ", {} component(s) and {} flow edge(s)",
                        a.len(),
                        a.flows().len()
                    ));
                }
                for (standard, n) in &self.imported {
                    s.push_str(&format!(", {n} imported guideline(s) for {}", standard.title()));
                }
                if !self.problems.is_empty() {
                    s.push_str(&format!(", {} problem(s)", self.problems.len()));
                }
                s
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sda-project-{name}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join(CONFIG_DIR)).unwrap();
        d
    }

    #[test]
    fn a_project_without_configuration_loads_cleanly() {
        let d = std::env::temp_dir().join("sda-project-none");
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let c = ProjectConfig::discover(&d);
        assert!(c.config_dir.is_none());
        assert!(c.deviations.is_none());
        assert!(c.summary().contains("no .sda/"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn deviations_are_discovered_from_the_config_directory() {
        let d = scratch("deviations");
        fs::write(
            d.join(CONFIG_DIR).join("deviations.toml"),
            "[[deviation]]\nrule = \"MISRA-C-2023-15.6\"\nscope = \"project\"\n\
             rationale = \"legacy driver, rewrite scheduled\"\napprover = \"a.erickson\"\n",
        )
        .unwrap();

        let c = ProjectConfig::discover(&d);
        assert_eq!(c.deviations.as_ref().unwrap().len(), 1);
        assert!(c.summary().contains("1 deviation"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn discovery_walks_upward_from_a_subdirectory() {
        let d = scratch("upward");
        let nested = d.join("src").join("drivers");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            d.join(CONFIG_DIR).join("deviations.toml"),
            "[[deviation]]\nrule = \"MISRA-C-2023-15.6\"\nscope = \"project\"\n\
             rationale = \"documented in the safety case\"\napprover = \"a.erickson\"\n",
        )
        .unwrap();

        let c = ProjectConfig::discover(&nested);
        assert!(c.config_dir.is_some());
        assert_eq!(c.deviations.unwrap().len(), 1);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_rejected_deviation_is_reported_rather_than_silently_dropped() {
        let d = scratch("rejected");
        fs::write(
            d.join(CONFIG_DIR).join("deviations.toml"),
            "[[deviation]]\nrule = \"MISRA-C-2023-9.1\"\nscope = \"project\"\n\
             rationale = \"inconvenient\"\napprover = \"someone\"\n",
        )
        .unwrap();

        let c = ProjectConfig::discover(&d);
        assert_eq!(c.problems.len(), 1);
        assert!(c.problems[0].contains("Mandatory"));
        assert_eq!(c.deviations.unwrap().len(), 0, "the record must not take effect");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_malformed_register_is_a_reported_problem_not_an_empty_project() {
        let d = scratch("malformed");
        fs::write(d.join(CONFIG_DIR).join("deviations.toml"), "this is not toml {{{").unwrap();
        let c = ProjectConfig::discover(&d);
        assert!(!c.problems.is_empty());
        assert!(c.deviations.is_none());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_imported_catalogue_upgrades_citations_and_is_reported() {
        let d = scratch("import");
        fs::write(
            d.join(CONFIG_DIR).join("misra-cpp-2023.toml"),
            "standard = \"MISRA C++:2023\"\n\
             [[rule]]\nn = \"8.2.2\"\nt = \"Official text\"\n\
             o = \"required\"\nd = \"decidable\"\ns = \"single\"\nc = \"native\"\n",
        )
        .unwrap();

        let mut c = ProjectConfig::discover(&d);
        let catalogs = c.catalogs();
        let cpp = catalogs
            .iter()
            .find(|c| c.standard == Standard::MisraCpp2023)
            .unwrap();
        assert_eq!(cpp.get("8.2.2").unwrap().citation(), "MISRA C++:2023 8.2.2");
        assert!(c.imported.iter().any(|(s, n)| *s == Standard::MisraCpp2023 && *n >= 1));
        assert!(c.summary().contains("imported"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_analysis_scope_is_discovered_and_summarised() {
        let d = scratch("scope");
        fs::write(
            d.join(CONFIG_DIR).join("scope.toml"),
            "[[excluded]]\npath = \"tests/\"\n\
             reason = \"unit test harness\"\napprover = \"a.erickson\"\n",
        )
        .unwrap();

        let c = ProjectConfig::discover(&d);
        assert_eq!(c.scope.as_ref().unwrap().len(), 1);
        assert!(c.summary().contains("1 scope exclusion"));
        fs::remove_dir_all(&d).ok();
    }

    /// A scope rule is a claim that code is not part of the product. An
    /// unattributed one must be reported and must not take effect — the same
    /// treatment a rejected deviation gets, for a stronger reason: this one
    /// removes files rather than annotating a finding.
    #[test]
    fn a_rejected_scope_rule_is_reported_and_does_not_narrow_the_scan() {
        let d = scratch("scope-rejected");
        fs::write(
            d.join(CONFIG_DIR).join("scope.toml"),
            "[[excluded]]\npath = \"src/\"\nreason = \"\"\napprover = \"\"\n",
        )
        .unwrap();

        let c = ProjectConfig::discover(&d);
        assert_eq!(c.problems.len(), 1);
        assert!(c.problems[0].contains("scope rule"));
        assert_eq!(c.scope.unwrap().len(), 0, "the rule must not take effect");
        fs::remove_dir_all(&d).ok();
    }

    /// A broken scope file must leave the scan *wide*, not narrow. Over-reporting
    /// is the recoverable direction; silently analysing less than the report
    /// claims is not.
    #[test]
    fn a_malformed_scope_file_is_a_problem_and_excludes_nothing() {
        let d = scratch("scope-malformed");
        fs::write(d.join(CONFIG_DIR).join("scope.toml"), "not toml {{{").unwrap();
        let c = ProjectConfig::discover(&d);
        assert!(!c.problems.is_empty());
        assert!(c.scope.is_none(), "a scope that failed to load excludes nothing");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_project_without_a_scope_file_has_no_scope_and_analyses_everything() {
        let d = scratch("scope-absent");
        let c = ProjectConfig::discover(&d);
        assert!(c.scope.is_none());
        // Not `contains("scope")`: the scratch directory's own path contains it.
        assert!(!c.summary().contains("scope exclusion"));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_project_without_overrides_gets_the_builtin_catalogue_unchanged() {
        let d = scratch("no-override");
        let c = ProjectConfig::discover(&d);
        let catalog = c.catalog(Standard::MisraC2023);
        assert_eq!(catalog.len(), Catalog::load(Standard::MisraC2023).len());
        fs::remove_dir_all(&d).ok();
    }

    /// A catalogue override that does not load is reported, like every other
    /// declaration in `.sda/`.
    ///
    /// This was the one file whose failures were discarded. `catalog()` dropped
    /// the read error through an `if let Ok` with no `else`, and the import
    /// error through `let _ = catalog.import(&text)`. A project supplying its own
    /// transcription of a standard — which is how the licensed rule text gets in
    /// — would get the built-in catalogue, no message, and an `sda rules audit`
    /// describing a catalogue it had tried to replace.
    #[test]
    fn a_catalogue_override_that_fails_to_load_is_reported() {
        let d = scratch("bad-override");
        fs::write(d.join(CONFIG_DIR).join("misra-c-2023.toml"), "not toml {{{").unwrap();

        let c = ProjectConfig::discover(&d);
        assert!(
            c.problems.iter().any(|p| p.contains("misra-c-2023.toml")),
            "a malformed override must name itself: {:?}",
            c.problems
        );

        // And the scan still runs on the built-in text rather than going quiet:
        // over-reporting is the recoverable direction.
        assert_eq!(
            c.catalog(Standard::MisraC2023).len(),
            Catalog::load(Standard::MisraC2023).len(),
            "a failed override leaves the built-in catalogue in place"
        );
        fs::remove_dir_all(&d).ok();
    }

    /// And one that loads is not reported, or the notice means nothing.
    #[test]
    fn a_catalogue_override_that_loads_is_not_reported() {
        let d = scratch("good-override");
        let rule = Catalog::load(Standard::MisraC2023)
            .rules()
            .first()
            .map(|r| r.number.clone())
            .expect("the built-in catalogue has rules");
        fs::write(
            d.join(CONFIG_DIR).join("misra-c-2023.toml"),
            format!(
                "[[rule]]\nn = \"{rule}\"\nt = \"the licensed wording\"\n\
                 o = \"required\"\nc = \"native\"\nd = \"decidable\"\ns = \"single\"\n"
            ),
        )
        .unwrap();

        let c = ProjectConfig::discover(&d);
        assert!(
            !c.problems.iter().any(|p| p.contains("misra-c-2023.toml")),
            "a valid override is not a problem: {:?}",
            c.problems
        );
        fs::remove_dir_all(&d).ok();
    }
}
