//! A default run must name the external providers it did not use.
//!
//! `sda scan` registered the external adapters only when `--with` was given, so
//! the unsuppressible *NOT CHECKED* section was **shorter on a default run than
//! on one that asked for a tool**: a plain scan named none of the nine external
//! providers it had not run, while `--with ext.miri` listed the other eight. That
//! is exactly inverted. The run that enables nothing is the run whose reader most
//! needs telling, and it is the run a first-time user makes.
//!
//! Found on a 2,270-file scan of PX4-Autopilot: 14,284 findings and a `NOT
//! CHECKED` section with one line in it, which read as "nothing else to say".
//!
//! The registry is the seam, not the report: `analyze` can only exclude a
//! provider it was handed, so this is a test about what the callers register. It
//! costs nothing to register them, because `Registry::select` applies the
//! selection policy *before* it asks a provider whether it is available — a
//! disabled adapter never spawns its probe process.

use sda_core::{Language, Target, TargetFile};
use sda_engine::run::{RunConfig, analyze};

fn target(dir: &std::path::Path) -> Target {
    let file = dir.join("main.c");
    let src = "int main(void) { return 0; }\n";
    std::fs::write(&file, src).unwrap();
    Target::new(dir).with_files(vec![TargetFile {
        path: file,
        language: Language::C,
        bytes: src.len() as u64,
    }])
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sda-default-skips-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn every_registered_external_provider_is_accounted_for_when_none_are_enabled() {
    let dir = scratch("all");
    let mut registry = sda_engine::default_registry();
    sda_adapters::register_all(&mut registry);

    let report = analyze(&registry, &target(&dir), &RunConfig::default());
    let named: Vec<&str> = report.exclusions.iter().map(|e| e.provider.as_str()).collect();

    for spec in sda_adapters::specs() {
        assert!(
            named.contains(&spec.id),
            "`{}` ran in no form and the report does not mention it: {named:?}",
            spec.id
        );
    }
}

/// The property stated the other way round, because the defect was a *difference*
/// between two runs rather than a missing line in one of them.
#[test]
fn enabling_one_tool_does_not_reveal_gaps_the_default_run_hid() {
    let dir = scratch("delta");
    let mut registry = sda_engine::default_registry();
    sda_adapters::register_all(&mut registry);

    let default_run = analyze(&registry, &target(&dir), &RunConfig::default());
    let with_one = analyze(
        &registry,
        &target(&dir),
        &RunConfig::default().tap(|c| c.selection = c.selection.clone().enable("ext.cppcheck")),
    );

    let gaps = |r: &sda_core::Report| -> std::collections::BTreeSet<String> {
        r.exclusions
            .iter()
            .filter(|e| e.provider.as_str().starts_with("ext."))
            .map(|e| e.provider.as_str().to_string())
            .collect()
    };
    // The enabled tool is either run or reported unavailable, so it may leave the
    // set; nothing else may appear that the default run did not already name.
    let extra: Vec<String> = gaps(&with_one).difference(&gaps(&default_run)).cloned().collect();
    assert!(extra.is_empty(), "asking for a tool revealed gaps the default run hid: {extra:?}");
}

/// A tiny helper so the test above reads as one expression; `RunConfig` has no
/// builder for a single-id enable, and adding one to the shipping type for a
/// test's convenience would be the tail wagging the dog.
trait Tap: Sized {
    fn tap(mut self, f: impl FnOnce(&mut Self)) -> Self {
        f(&mut self);
        self
    }
}
impl Tap for RunConfig {}
