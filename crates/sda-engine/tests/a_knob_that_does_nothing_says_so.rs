//! Two of `RunOptions`' three knobs are honoured by nothing.
//!
//! | field | doc comment | who reads it |
//! |---|---|---|
//! | `disabled_rules` | rules to skip | three providers |
//! | `timeout_secs` | "wall-clock budget for the whole provider" | **nobody** |
//! | `settings` | "provider-specific settings, keyed by provider id" | **nobody** |
//!
//! `timeout_secs` appears exactly once in the workspace: its own declaration. So
//! does the `max_runs` example in `RunOptions::get`'s doc comment, which names a
//! setting that has never existed. A caller sets a budget, gets none, and is told
//! nothing — the public API promising a capability it does not have.
//!
//! Neither is wired up here, and that is a decision rather than an omission. A
//! wall-clock budget across native providers needs cancellation this engine does
//! not have, and inventing a setting for a provider that never asked for one
//! would be worse than the gap. What can be done honestly is to refuse the
//! instruction out loud: the difference between "your timeout did nothing" and
//! silence is the whole of what *NOT CHECKED* is for.
//!
//! Found by sweeping public *fields* nobody reads, after
//! `RustLexed::unterminated_block_comments` turned out to be one.
//! `uncalled-api-sweep.py` could not have found it — it lists `pub fn`. It also
//! misses `RunOptions::get` and `set`, which are dead on this type and invisible
//! to a name-based sweep because `HashMap::get` is called everywhere.

use sda_core::RunOptions;
use sda_engine::run::{RunConfig, analyze};
use sda_engine::{default_registry, discover};

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sda-knob-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    std::fs::write(dir.join("a.c"), "int f(int x) { return x + 1; }\n").expect("a source");
    dir
}

fn notices(dir: &std::path::Path, options: RunOptions) -> Vec<String> {
    let target = discover::discover(dir, &discover::DiscoveryOptions::default());
    let config = RunConfig { options, ..RunConfig::default() };
    analyze(&default_registry(), &target, &config)
        .exclusions
        .iter()
        .filter(|e| e.provider.as_str() == "sda.options")
        .map(|e| e.reason.clone())
        .collect()
}

/// A budget nothing enforces is reported rather than accepted in silence.
#[test]
fn a_timeout_nothing_enforces_is_named_in_not_checked() {
    let dir = scratch("timeout");
    let reasons = notices(&dir, RunOptions { timeout_secs: Some(30), ..RunOptions::default() });

    assert_eq!(reasons.len(), 1, "one knob was set: {reasons:?}");
    assert!(
        reasons[0].contains("no provider enforces one"),
        "it has to say the budget did not apply: {}",
        reasons[0]
    );
    assert!(
        reasons[0].contains("will not be stopped"),
        "and what that costs, which is the reason to say it at all: {}",
        reasons[0]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// So are settings nothing consumes, with the count, because it is knowable.
#[test]
fn provider_settings_nothing_reads_are_named_in_not_checked() {
    let dir = scratch("settings");
    let mut options = RunOptions::default();
    options.set("sda.dynamic", "max_runs", serde_json::json!(10));
    options.set("sda.static.c", "pedantic", serde_json::json!(true));
    let reasons = notices(&dir, options);

    assert_eq!(reasons.len(), 1, "one kind of knob was set: {reasons:?}");
    assert!(
        reasons[0].contains("2 provider setting(s)"),
        "the count is knowable, so it is stated: {}",
        reasons[0]
    );
    assert!(
        reasons[0].contains("did not change"),
        "and the consequence: {}",
        reasons[0]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A run that sets neither says nothing, so the notice means something when it
/// does appear.
///
/// Without this the two above would pass on an engine that printed both notices
/// unconditionally — which would put two permanent entries in the section whose
/// value is that everything in it is true of *this* run.
#[test]
fn a_run_that_sets_no_knobs_is_not_told_about_them() {
    let dir = scratch("default");
    let reasons = notices(&dir, RunOptions::default());

    assert!(
        reasons.is_empty(),
        "nothing was asked for, so there is nothing to report: {reasons:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The third knob is honoured, and this is what says the other two are the
/// exception rather than the rule.
#[test]
fn the_knob_that_does_work_still_works() {
    let dir = scratch("disabled");
    let target = discover::discover(&dir, &discover::DiscoveryOptions::default());

    let all = analyze(&default_registry(), &target, &RunConfig::default());
    let before = all.findings.iter().filter(|f| f.rule.as_str().ends_with("D4.6")).count();
    assert!(before > 0, "the fixture has to trip the rule being disabled");

    let config = RunConfig {
        options: RunOptions { disabled_rules: vec!["D4.6".into()], ..RunOptions::default() },
        ..RunConfig::default()
    };
    let after = analyze(&default_registry(), &target, &config);
    assert_eq!(
        after.findings.iter().filter(|f| f.rule.as_str().ends_with("D4.6")).count(),
        0,
        "`disabled_rules` is read by three providers and does what it says"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
