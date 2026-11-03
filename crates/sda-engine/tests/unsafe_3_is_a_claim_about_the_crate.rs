//! `UNSAFE.3` is about a crate, and was decided from one file.
//!
//! The guideline is *"a crate with no need for unsafe code shall declare
//! `#![forbid(unsafe_code)]`"*. The check fired on any `lib.rs` containing no
//! `unsafe` and no `forbid` — which a crate whose root is clean and whose
//! modules are not satisfies exactly. So the finding appeared, and its advice
//! was worse than merely wrong: `#![forbid(unsafe_code)]` is crate-wide, so a
//! reader who followed it would not get a stricter crate, they would get one
//! that does not compile.
//!
//! It was found by asking how widely each rule fires across the *other* rules'
//! fixtures. `UNSAFE.3` fired on twelve of fifteen. Most of that was an artifact
//! of fixtures being named `lib.rs`, but the question it raised was the right
//! one, and no fixture could ever have caught this: a fixture is one file, and
//! one file cannot answer a question about a crate.
//!
//! The rule is `system` scope now, beside MISRA 5.1 and D4.5, and decided in
//! `analyze` where the crate is visible. The editor's buffer path no longer
//! raises it at all — a rule that cannot be decided from a buffer should not
//! appear to have been.

use sda_engine::run::{RunConfig, analyze};
use sda_engine::{default_registry, discover};

fn crate_at(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sda-unsafe3-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("src")).expect("a scratch crate");
    std::fs::write(
        d.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[workspace]\n",
    )
    .unwrap();
    for (path, text) in files {
        std::fs::write(d.join(path), text).unwrap();
    }
    d
}

fn unsafe_3_sites(dir: &std::path::Path) -> Vec<String> {
    let target = discover::discover(dir, &discover::DiscoveryOptions::default());
    assert!(!target.files.is_empty(), "discovery found nothing under {}", dir.display());
    let report = analyze(&default_registry(), &target, &RunConfig::default());
    report
        .findings
        .iter()
        .filter(|f| f.rule.as_str().ends_with("UNSAFE.3"))
        .map(|f| f.location.display())
        .collect()
}

/// The defect: unsafe in a module, a clean root, and a finding telling you to
/// forbid it.
#[test]
fn a_crate_whose_module_uses_unsafe_is_not_told_to_forbid_it() {
    let d = crate_at(
        "module-unsafe",
        &[
            ("src/lib.rs", "pub mod hw;\n\npub fn entry() -> u32 { hw::read() }\n"),
            (
                "src/hw.rs",
                "pub fn read() -> u32 {\n    // SAFETY: a memory-mapped register.\n    \
                 unsafe { core::ptr::read_volatile(0x4000_0000 as *const u32) }\n}\n",
            ),
        ],
    );

    assert!(
        unsafe_3_sites(&d).is_empty(),
        "this crate needs `unsafe`; advising `#![forbid(unsafe_code)]` would stop it compiling"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// And the rule still fires where it should, or the fix is just a deletion.
#[test]
fn a_crate_with_no_unsafe_anywhere_is_still_told_to_declare_it() {
    let d = crate_at(
        "all-safe",
        &[
            ("src/lib.rs", "pub mod calc;\n\npub fn entry() -> u32 { calc::add(1, 2) }\n"),
            ("src/calc.rs", "pub fn add(a: u32, b: u32) -> u32 { a + b }\n"),
        ],
    );

    let sites = unsafe_3_sites(&d);
    assert_eq!(sites.len(), 1, "one crate root, one finding: {sites:?}");
    assert!(sites[0].contains("lib.rs"), "reported against the crate root: {sites:?}");
    let _ = std::fs::remove_dir_all(&d);
}

/// A crate that already declares it is silent, which is the guideline's point.
#[test]
fn a_crate_that_already_forbids_unsafe_is_silent() {
    let d = crate_at(
        "declared",
        &[("src/lib.rs", "#![forbid(unsafe_code)]\n\npub fn entry() -> u32 { 7 }\n")],
    );
    assert!(unsafe_3_sites(&d).is_empty(), "it declared exactly what the guideline asks for");
    let _ = std::fs::remove_dir_all(&d);
}

/// The buffer path does not decide it, and does not pretend to.
///
/// `check_buffer` is the editor's live-typing path. It sees one file, so it
/// cannot know whether any sibling uses `unsafe` — and the previous behaviour,
/// raising the finding anyway, is the defect above shown to a developer while
/// they type.
#[test]
fn the_editor_buffer_path_does_not_raise_a_crate_wide_rule() {
    let config = sda_rules::ProjectConfig::default();
    let found = sda_engine::check_buffer(
        &config,
        std::path::Path::new("src/lib.rs"),
        "pub fn entry() -> u32 { 7 }\n",
    );
    assert!(
        !found.iter().any(|f| f.rule.as_str().ends_with("UNSAFE.3")),
        "one buffer is not evidence about a crate: {:?}",
        found.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>()
    );
}
