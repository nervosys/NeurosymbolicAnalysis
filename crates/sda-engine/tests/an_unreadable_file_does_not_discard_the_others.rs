//! One file that cannot be read must not throw away the files that could.
//!
//! Both native analyzers read each source with `?`:
//!
//! ```ignore
//! let src = std::fs::read_to_string(&file.path)
//!     .map_err(|e| sda_core::Error::io(file.path.display().to_string(), e))?;
//! ```
//!
//! so the first unreadable file failed the whole provider and took every finding
//! from every other file with it. On a two-file tree, four findings became zero.
//!
//! The trigger is not exotic. `read_to_string` requires valid UTF-8, and a
//! copyright line with a Latin-1 `©` in it — ordinary in legacy C, and in plenty
//! of live embedded trees — is not. A single such file anywhere under the scan
//! root reduced the entire C analysis to nothing, reported as
//! `provider failed during analysis`.
//!
//! This is the rule the `--artifact` launch already learned, in the same words:
//! an inability to check one thing must not throw away the checks that did
//! happen, and must not pass silently either. The file is skipped, the rest are
//! analysed, and the skip is named in *NOT CHECKED* — because a file discovery
//! counted and analysis never read is the difference between "we looked at your
//! tree" and "we looked at most of your tree", and only the report can tell the
//! reader which.

use sda_core::Severity;
use sda_engine::run::{RunConfig, analyze};
use sda_engine::{default_registry, discover};

/// A fresh directory under the system temp, owned by this test alone.
fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sda-unreadable-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("a scratch directory");
    d
}

fn run(dir: &std::path::Path) -> sda_core::Report {
    let target = discover::discover(dir, &discover::DiscoveryOptions::default());
    assert!(!target.files.is_empty(), "discovery found nothing under {}", dir.display());
    analyze(&default_registry(), &target, &RunConfig::default())
}

fn real_findings(report: &sda_core::Report, prefix: &str) -> usize {
    report
        .findings
        .iter()
        .filter(|f| f.severity != Severity::Info)
        .filter(|f| f.rule.as_str().starts_with(prefix))
        .count()
}

/// The C analyzer keeps what it could read.
#[test]
fn a_latin1_c_file_does_not_discard_the_findings_from_its_neighbours() {
    let d = scratch("c");
    std::fs::write(d.join("good.c"), "int f(int a) {\n  if (a) return 1;\n  return 0;\n}\n")
        .unwrap();

    let alone = run(&d);
    let expected = real_findings(&alone, "MISRA-C-2023-");
    assert!(expected > 0, "the well-formed file must produce findings to lose");

    // `0xA9` is `©` in Latin-1 and is not valid UTF-8 on its own.
    std::fs::write(d.join("legacy.c"), b"/* Copyright \xA9 2003 Acme */\nint g(void) { return 0; }\n")
        .unwrap();

    let together = run(&d);
    assert_eq!(
        real_findings(&together, "MISRA-C-2023-"),
        expected,
        "a file that could not be read discarded the analysis of the file that could"
    );

    assert!(
        together
            .exclusions
            .iter()
            .any(|e| e.reason.contains("legacy.c") && e.reason.contains("could not be read")),
        "and the skipped file has to be named, or a shorter report reads as a cleaner one: {:?}",
        together.exclusions.iter().map(|e| &e.reason).collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// And so does the Rust analyzer, which had the same `?`.
#[test]
fn a_latin1_rust_file_does_not_discard_the_findings_from_its_neighbours() {
    let d = scratch("rust");
    std::fs::write(
        d.join("good.rs"),
        "pub fn f(v: Option<u32>) -> u32 {\n    v.unwrap()\n}\n",
    )
    .unwrap();

    let alone = run(&d);
    let expected = real_findings(&alone, "RUST-2024-");
    assert!(expected > 0, "the well-formed file must produce findings to lose");

    std::fs::write(d.join("legacy.rs"), b"// Copyright \xA9 2003 Acme\npub fn g() {}\n").unwrap();

    let together = run(&d);
    assert_eq!(
        real_findings(&together, "RUST-2024-"),
        expected,
        "a file that could not be read discarded the analysis of the file that could"
    );
    assert!(
        together
            .exclusions
            .iter()
            .any(|e| e.reason.contains("legacy.rs") && e.reason.contains("could not be read")),
        "and the skipped file has to be named: {:?}",
        together.exclusions.iter().map(|e| &e.reason).collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// A tree with nothing wrong in it says nothing about unreadable files.
///
/// The notice has to be absent when it does not apply, or it becomes noise that
/// a reader learns to skip — and this report's last section is the one that must
/// never be skipped.
#[test]
fn a_readable_tree_produces_no_such_notice() {
    let d = scratch("clean");
    std::fs::write(d.join("good.c"), "int f(int a) {\n  if (a) return 1;\n  return 0;\n}\n")
        .unwrap();

    let report = run(&d);
    assert!(
        !report.exclusions.iter().any(|e| e.reason.contains("could not be read")),
        "nothing was unreadable here: {:?}",
        report.exclusions.iter().map(|e| &e.reason).collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(&d);
}
