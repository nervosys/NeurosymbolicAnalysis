//! The NERVOSYS native statodynamic engines — the toolkit's default providers.
//!
//! Industry tools are welcome here (see `sda-adapters`), but they are not the
//! baseline. The baseline is this crate: native Rust, no external process, no
//! configuration, deterministic, and honest about what it did not check.
//!
//! ```no_run
//! use sda_engine::{default_registry, discover, run};
//! let target = discover::discover("./firmware", &discover::DiscoveryOptions::default());
//! let report = run::analyze(&default_registry(), &target, &run::RunConfig::default());
//! println!("{} findings", report.summary.total);
//! // A static-only run says so, rather than implying it verified anything:
//! for e in &report.exclusions {
//!     println!("not checked: {} — {}", e.provider, e.reason);
//! }
//! ```

#![forbid(unsafe_code)]

pub mod checks;
pub mod correlate;
pub mod coverage;
pub mod cstatic;
pub mod discover;
pub mod dynamic;
pub mod fuzz;
pub mod interposition;
pub mod neurosymbolic;
pub mod rstatic;
pub mod run;
pub mod history;
pub mod impact;
pub mod vcs;

pub use correlate::{CorrelationPolicy, CorrelationResult, correlate};
pub use coverage::{CoverageFormat, ExternalCoverage};
pub use cstatic::CStaticAnalyzer;
pub use discover::{DiscoveryOptions, discover};
pub use dynamic::{
    DynamicEngine, Observation, ProbeRecord, RunSpec, StreamSummary, parse_probe_capture,
};
pub use fuzz::{Crash, FuzzConfig, FuzzReport, campaign as fuzz_campaign};
pub use interposition::{
    Bypass, DeclaredSystem, Edge, FlowGraph, Interposition, from_declaration,
};
pub use neurosymbolic::{Adjudication, Component, Role, SystemMap, adjudicate};
pub use rstatic::RustStaticAnalyzer;

use sda_core::Registry;
use std::sync::Arc;

/// A registry containing exactly the native providers.
///
/// This is what a bare `sda scan` uses: everything here runs with no external
/// dependency, so a first run on a new machine produces real results rather
/// than a list of tools to go and install.
pub fn default_registry() -> Registry {
    let mut r = Registry::new();
    r.register(Arc::new(CStaticAnalyzer::c()));
    r.register(Arc::new(CStaticAnalyzer::cpp()));
    r.register(Arc::new(RustStaticAnalyzer::new()));
    r
}

/// The native registry plus a dynamic engine bound to the given runs.
pub fn registry_with_dynamic(specs: Vec<RunSpec>) -> Registry {
    let mut r = default_registry();
    r.register(Arc::new(DynamicEngine::new(specs)));
    r
}

/// A registry whose analyzers use a project's catalogues.
///
/// Use this rather than [`default_registry`] wherever a project root is known.
/// The difference is visible in every citation: with a licensed guideline list
/// in `.sda/`, findings cite real rule numbers instead of reporting a clause and
/// admitting the number is unconfirmed.
pub fn registry_for_project(config: &sda_rules::ProjectConfig) -> Registry {
    use sda_rules::Standard;
    let mut r = Registry::new();
    r.register(Arc::new(CStaticAnalyzer::with_catalog(
        sda_syntax::Dialect::C23,
        config.catalog(Standard::MisraC2023),
    )));
    r.register(Arc::new(CStaticAnalyzer::with_catalog(
        sda_syntax::Dialect::Cpp23,
        config.catalog(Standard::MisraCpp2023),
    )));
    r.register(Arc::new(RustStaticAnalyzer::with_catalog(
        config.catalog(Standard::Rust2024),
    )));
    r
}

/// Analyze one in-memory buffer the way the project would analyze it on disk.
///
/// This is the editor's live-typing path, and it has to agree with
/// [`run::analyze`] about the same text — same catalogues, same deviations.
/// When it did not, the editor underlined a rule the project had formally
/// deviated while the findings list greyed the identical finding out, in the
/// same window at the same moment.
pub fn check_buffer(
    config: &sda_rules::ProjectConfig,
    path: &std::path::Path,
    text: &str,
) -> Vec<sda_core::Finding> {
    use sda_rules::Standard;

    let mut findings = match sda_core::Language::from_path(path) {
        sda_core::Language::C => {
            CStaticAnalyzer::with_catalog(sda_syntax::Dialect::C23, config.catalog(Standard::MisraC2023))
                .check_source(path, text)
        }
        sda_core::Language::Cpp => CStaticAnalyzer::with_catalog(
            sda_syntax::Dialect::Cpp23,
            config.catalog(Standard::MisraCpp2023),
        )
        .check_source(path, text),
        sda_core::Language::Rust => {
            RustStaticAnalyzer::with_catalog(config.catalog(Standard::Rust2024))
                .check_source(path, text)
        }
        // Model files and unknown extensions have no buffer-level checker; the
        // full scan still covers them.
        _ => Vec::new(),
    };

    if let Some(reg) = &config.deviations {
        // The editor's buffer check suppresses through the same register as a
        // full scan, so a lapsed acceptance used to go on hiding a finding here
        // too — in the one place a developer is looking straight at the line.
        let today = sda_core::report::now_rfc3339();
        reg.apply(&mut findings, today.get(..10).unwrap_or("1970-01-01"));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::{ProviderOrigin, SelectionPolicy};

    #[test]
    fn the_default_registry_is_entirely_native() {
        let r = default_registry();
        assert!(!r.is_empty());
        assert!(r.describe().iter().all(|p| p.origin == ProviderOrigin::Native));
    }

    #[test]
    fn every_default_provider_is_available_without_installing_anything() {
        let r = default_registry();
        let (chosen, excluded) = r.select(&SelectionPolicy::default());
        assert_eq!(chosen.len(), r.len(), "excluded: {excluded:?}");
    }

    /// SARIF conformance on a *realistic* report.
    ///
    /// The exporter's own tests build one- and two-finding reports by hand, so
    /// the invariants that only break at scale — a `ruleIndex` that does not
    /// point at its own rule, a Windows path escaping as a backslash URI — were
    /// never exercised. This runs the real pipeline over the example project and
    /// checks the document a consumer would actually receive.
    #[test]
    fn exported_sarif_holds_together_on_a_real_scan() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("examples")
            .join("firmware");
        let path = root.to_string_lossy().to_string();

        let target = discover::discover(&path, &discover::DiscoveryOptions::default());
        let project = sda_rules::ProjectConfig::discover(&root);
        let mut config = run::RunConfig::default();
        if let Some(reg) = project.deviations.clone() {
            config = config.with_deviations(reg);
        }
        let report = run::analyze(&registry_for_project(&project), &target, &config);
        assert!(!report.findings.is_empty(), "the example project must produce findings");

        let doc = sda_core::sarif::to_sarif(&report);
        assert_eq!(doc["version"], "2.1.0");
        assert!(doc["$schema"].is_string(), "a consumer needs the schema reference");

        let run = &doc["runs"][0];
        let rules = run["tool"]["driver"]["rules"].as_array().expect("driver.rules");
        let results = run["results"].as_array().expect("results");
        assert_eq!(results.len(), report.findings.len(), "every finding must be exported");

        for r in results {
            let rule_id = r["ruleId"].as_str().expect("every result carries a ruleId");

            // A ruleIndex that does not resolve to its own rule silently
            // mislabels the finding in every consumer that trusts the index.
            let idx = r["ruleIndex"].as_u64().expect("every result carries a ruleIndex") as usize;
            let named = rules.get(idx).unwrap_or_else(|| panic!("ruleIndex {idx} out of range"));
            assert_eq!(named["id"], rule_id, "ruleIndex {idx} points at the wrong rule");

            assert!(
                !r["message"]["text"].as_str().unwrap_or_default().is_empty(),
                "{rule_id}: a result with no message tells a reviewer nothing"
            );

            let phys = &r["locations"][0]["physicalLocation"];
            let uri = phys["artifactLocation"]["uri"].as_str().expect("artifactLocation.uri");
            // SARIF URIs are URI references, not native paths. On Windows a
            // path copied through verbatim would carry backslashes and no
            // consumer would resolve it.
            assert!(!uri.contains('\\'), "{rule_id}: `{uri}` is a native path, not a URI");

            let region = &phys["region"];
            let (sl, sc) = (region["startLine"].as_u64(), region["startColumn"].as_u64());
            assert!(sl.is_some() && sc.is_some(), "{rule_id}: region needs a start");
            if let (Some(el), Some(ec)) = (region["endLine"].as_u64(), region["endColumn"].as_u64())
            {
                assert!(
                    (el, ec) >= (sl.unwrap(), sc.unwrap()),
                    "{rule_id}: region ends before it starts"
                );
            }
        }

        // The deviation register suppresses three findings; SARIF must carry
        // them as suppressions rather than dropping them, or the compliance
        // record loses the justification.
        let suppressed: Vec<_> =
            results.iter().filter(|r| r["suppressions"].is_array()).collect();
        assert!(!suppressed.is_empty(), "approved deviations must appear as suppressions");
        for s in suppressed {
            let j = s["suppressions"][0]["justification"].as_str().unwrap_or_default();
            assert!(!j.is_empty(), "a suppression without a justification is not a record");
        }
    }

    /// The editor and the findings list must not disagree about one buffer.
    ///
    /// `check_buffer` used to call the analyzers raw, so a project's approved
    /// deviations applied to a scan and not to live typing: the same rule was
    /// underlined in the editor and greyed out in the list simultaneously.
    #[test]
    fn live_typing_and_a_full_scan_agree_about_deviations() {
        use sda_core::{Target, TargetFile};

        let d = std::env::temp_dir().join("sda-buffer-agreement");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".sda")).unwrap();

        // `printf` trips MISRA C:2023 21.6 (Required, decidable), and this
        // project has formally accepted that departure.
        let source = "#include <stdio.h>\nvoid log_it(void) { printf(\"x\\n\"); }\n";
        let file = d.join("log.c");
        std::fs::write(&file, source).unwrap();
        std::fs::write(
            d.join(".sda").join("deviations.toml"),
            "[[deviation]]\nrule = \"MISRA-C-2023-21.6\"\nscope = \"project\"\n\
             rationale = \"diagnostic build only, stripped in release\"\napprover = \"a.erickson\"\n",
        )
        .unwrap();

        let project = sda_rules::ProjectConfig::discover(&d);
        assert!(project.deviations.is_some(), "the register must load");

        let buffer = check_buffer(&project, &file, source);
        assert!(!buffer.is_empty(), "the buffer check must still find 21.6");

        let target = Target::new(&d).with_files(vec![TargetFile {
            path: file.clone(),
            language: sda_core::Language::C,
            bytes: source.len() as u64,
        }]);
        let config = run::RunConfig::default()
            .with_deviations(project.deviations.clone().unwrap());
        let report = run::analyze(&registry_for_project(&project), &target, &config);

        let scanned: Vec<_> =
            report.findings.iter().filter(|f| f.rule.as_str().contains("21.6")).collect();
        assert!(!scanned.is_empty(), "the scan must find 21.6 too");

        // The property that matters: both paths reach the same verdict.
        for f in &scanned {
            assert!(f.is_suppressed(), "the scan must honour the deviation");
        }
        for f in buffer.iter().filter(|f| f.rule.as_str().contains("21.6")) {
            assert!(
                f.is_suppressed(),
                "live typing must honour the same deviation the scan honours, \
                 or the editor contradicts the findings list in one window"
            );
        }
        std::fs::remove_dir_all(&d).ok();
    }

    /// A licensed guideline list in `.sda/` must reach the findings. It used to
    /// sit unread: the analyzers always loaded the built-in catalogue, so an
    /// import changed nothing and every citation still said "unconfirmed".
    #[test]
    fn an_imported_guideline_list_reaches_the_citations() {
        use sda_core::{RunOptions, Target, TargetFile};

        let d = std::env::temp_dir().join("sda-project-catalog");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".sda")).unwrap();
        std::fs::write(
            d.join(".sda").join("misra-cpp-2023.toml"),
            "standard = \"MISRA C++:2023\"\n\
             [[rule]]\nn = \"8.2.2\"\nt = \"no reinterpret_cast (a project's own label)\"\n\
             o = \"required\"\nd = \"decidable\"\ns = \"single\"\nc = \"native\"\n",
        )
        .unwrap();
        let source = "void f(void) { int *q = reinterpret_cast<int *>(p); (void)q; }\n";
        std::fs::write(d.join("a.cpp"), source).unwrap();

        let target = Target::new(&d).with_files(vec![TargetFile {
            path: d.join("a.cpp"),
            language: sda_core::Language::Cpp,
            bytes: source.len() as u64,
        }]);

        let cite = |registry: &Registry| -> String {
            let provider = registry.get("sda.static.cpp").unwrap();
            provider
                .analyze(&target, &RunOptions::default())
                .unwrap()
                .into_iter()
                .find(|f| f.rule.as_str().ends_with("8.2.2"))
                .map(|f| {
                    f.evidence
                        .iter()
                        .filter_map(|e| match e {
                            sda_core::Evidence::Note { text } => Some(text.clone()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
        };

        // Built-in catalogue: the number is unconfirmed, and the finding says so.
        assert!(cite(&default_registry()).contains("unconfirmed"));

        // With the project's list, the caveat is gone.
        let config = sda_rules::ProjectConfig::discover(&d);
        assert!(config.config_dir.is_some(), "the .sda directory must be found");
        let cited = cite(&registry_for_project(&config));
        assert!(
            !cited.contains("unconfirmed"),
            "an imported list must upgrade the citation, got: {cited:?}"
        );

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn adding_a_dynamic_engine_does_not_disturb_the_static_ones() {
        let r = registry_with_dynamic(vec![]);
        assert_eq!(r.len(), default_registry().len() + 1);
        // With no runs configured the dynamic engine excludes itself, loudly.
        let (_, excluded) = r.select(&SelectionPolicy::default());
        assert!(excluded.iter().any(|e| e.provider.as_str() == "sda.dynamic"));
    }
}
