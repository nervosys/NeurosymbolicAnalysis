//! Every adapter must be able to produce a finding from its tool's real output.
//!
//! This exists because `ext.valgrind` shipped declaring `OutputFormat::GccLike`,
//! which matches not one line Memcheck emits. It compiled, it was covered by the
//! availability tests, it passed a full suite and two clean self-scans, and it
//! could not have produced a finding on any input in the universe. Nothing ever
//! asked it to parse Valgrind output.
//!
//! A spec that compiles and a spec that works are different claims. Type
//! checking gets the first one; only a recorded sample of the tool's own output,
//! run through the same dispatch the adapter uses, gets the second.
//!
//! **Adding an adapter means adding a fixture.** The completeness test below
//! fails if a spec has no `tests/fixtures/<id>.txt`, so the pairing cannot be
//! forgotten — which is the whole point, since forgetting it is exactly what
//! happened.
//!
//! Fixtures are captured or reconstructed tool output. Where a tool is not
//! installed on the machine this was written on, the fixture is built from that
//! tool's documented format and says so.
//!
//! `ext.modelscan` used to be such a case, and is now captured from modelscan
//! 0.8.8. Replacing it was worth doing: the reconstruction had the per-issue
//! fields right and everything around them wrong — the top-level keys were
//! actually nested under `summary`, and, far worse, the real tool's *stdout* is
//! not valid JSON at all. See `OutputFormat::ModelScanJson`.
//!
//! `ext.miri` was the next one, and it was wrong about the stream, the format
//! and the toolchain together. **`ext.codeql` is now the only reconstruction
//! left**, and [`Provenance`] records that as data rather than as prose, so
//! adding an adapter forces the question and the set cannot quietly grow.

use sda_adapters::{parse_output_channels, specs, AdapterSpec};
use sda_core::Severity;

/// Where a fixture's bytes came from.
///
/// Recorded as data rather than as a comment because it is the single fact this
/// file most needs to state accurately, and comments about it have been wrong
/// twice: `ext.modelscan` carried a note calling a real capture a
/// reconstruction, and `ext.miri`'s reconstruction was believed to be right
/// until the tool was run. A reader cannot tell the difference by looking at the
/// bytes, and neither can a test — so it is declared, and the declaration is
/// checked below.
#[derive(PartialEq, Eq, Debug)]
enum Provenance {
    /// Recorded from a real run of the tool, at the stated version.
    Captured(&'static str),
    /// Written from the tool's documented format. Assume it is wrong: of the ten
    /// adapters whose real tool has now been run, nine were defective, and the
    /// reconstruction agreed with the defect every time.
    Reconstructed,
}

/// The recorded output for a spec, and what it must yield.
struct Fixture {
    id: &'static str,
    text: &'static str,
    provenance: Provenance,
    /// The tool's second stream, for the one format that needs both.
    ///
    /// Empty for every single-channel adapter. `ext.verus` is the exception:
    /// its JSON counts the obligations that failed and its diagnostics name
    /// them, and a fixture carrying only one of the two would test a parser
    /// reading half of what the tool writes.
    secondary: &'static str,
    /// Findings the sample must produce. Fewer means the parser lost some.
    expect: usize,
    /// A rule id and location that must appear, to catch a parser that returns
    /// the right *number* of findings while mislocating every one of them.
    anchor_rule: &'static str,
    anchor_file: &'static str,
    anchor_line: u32,
    /// The worst severity in the sample, so a parser cannot flatten everything
    /// to one level and still pass.
    worst: Severity,
}

fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            id: "ext.cppcheck",
            provenance: Provenance::Captured("cppcheck 2.21.0"),
            text: include_str!("fixtures/ext.cppcheck.txt"),
            secondary: "",
            // Captured from cppcheck 2.21.0 on stderr, with only the absolute
            // source path shortened. Ten `<error>` elements, nine findings: the
            // tenth is `checkersReport`, which has no location and is metadata.
            expect: 9,
            anchor_rule: "arrayIndexOutOfBounds",
            anchor_file: "src/bug.c",
            anchor_line: 7,
            worst: Severity::High,
        },
        Fixture {
            id: "ext.clang-tidy",
            provenance: Provenance::Captured("clang-tidy, against a real clang compilation database"),
            text: include_str!("fixtures/ext.clang-tidy.txt"),
            secondary: "",
            // Three warnings. The capture also holds two `note:` lines, and this
            // said 5 because they used to become findings of their own with the
            // rule id `note`. They are the second half of the diagnostic above
            // them and are now evidence on it — see
            // `a_note_is_evidence_for_the_diagnostic_above_it_not_a_finding`.
            // The count went *down* because the report got more accurate, which
            // is the only reason it is allowed to.
            expect: 3,
            anchor_rule: "clang-analyzer-unix.Malloc",
            anchor_file: "src/main.c",
            anchor_line: 5,
            worst: Severity::Medium,
        },
        Fixture {
            id: "ext.clippy",
            provenance: Provenance::Captured("cargo clippy on a Cargo project"),
            text: include_str!("fixtures/ext.clippy.txt"),
            secondary: "",
            expect: 2,
            anchor_rule: "clippy::needless_range_loop",
            anchor_file: "src/main.rs",
            anchor_line: 4,
            worst: Severity::High,
        },
        Fixture {
            id: "ext.miri",
            provenance: Provenance::Captured("Miri on nightly, over a stacked-borrows violation"),
            // Captured from Miri on nightly (rustc 1.99.0-nightly) over a
            // stacked-borrows violation, paths shortened. This fixture replaces
            // a reconstruction that had the stream, the format and the parser
            // wrong together: it claimed a `compiler-message` on stdout, and the
            // real run writes two `compiler-artifact` lines and
            // `"success":true` there while reporting the UB on stderr in prose.
            // The adapter was fully green and could not have read a single real
            // Miri finding.
            text: include_str!("fixtures/ext.miri.txt"),
            secondary: "",
            // One diagnostic, not three. The two `help:` blocks below it name
            // where the pointer was created and where it was invalidated; they
            // are the explanation of the one defect and are kept as its trace,
            // not counted as defects of their own. Cargo's own
            // `error: test failed` and `error: aborting due to 1 previous error`
            // are on the same stream and are not findings either: they carry no
            // `-->`, which is the tool's own distinction between a defect in the
            // code and a fact about the process.
            expect: 1,
            anchor_rule: "Undefined Behavior",
            anchor_file: "src/lib.rs",
            anchor_line: 11,
            worst: Severity::High,
        },
        Fixture {
            id: "ext.semgrep",
            provenance: Provenance::Captured("semgrep 1.172.0"),
            text: include_str!("fixtures/ext.semgrep.txt"),
            secondary: "",
            // Captured from semgrep 1.172.0. Reduced only by dropping 1073 of
            // the 1074 rule definitions the real driver carries — the fixture
            // would otherwise be 2 MB — and by shortening the absolute source
            // path. The backslashes in the fixture are real — Semgrep writes a
            // Windows path into `artifactLocation.uri`, not a URI — and the
            // anchor below is the forward-slash form because the toolkit
            // normalises separators on the way in.
            //
            // The result carries **no `level`**, which is why the severity here
            // is High: it comes from the rule's `defaultConfiguration`, which
            // the parser now consults. Before that, every real Semgrep finding
            // arrived as Medium.
            expect: 1,
            anchor_rule: "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
            anchor_file: "src/app.py",
            anchor_line: 4,
            worst: Severity::High,
        },
        Fixture {
            id: "ext.verus",
            provenance: Provenance::Captured("cargo verus verify, Verus 0.2026.08.30.b432e82"),
            text: include_str!("fixtures/ext.verus-cargo.json"),
            secondary: include_str!("fixtures/ext.verus-cargo.txt"),
            // Captured from `cargo verus verify -- --output-json` on a crate
            // generated by `cargo verus new`, Verus 0.2026.08.30.b432e82.
            // `verified: 3, errors: 1`, and the one failure is the postcondition
            // on a function written without the guard.
            //
            // One finding, not three: Verus names the obligations it could not
            // discharge and only counts the ones it could, so there is nothing
            // to attach the successes to. See `real_verus_output.rs`.
            expect: 1,
            anchor_rule: "VERUS-POSTCONDITION-NOT-SATISFIED",
            anchor_file: "src/main.rs",
            anchor_line: 41,
            worst: Severity::High,
        },
        Fixture {
            id: "ext.codeql",
            provenance: Provenance::Captured("CodeQL 2.26.4, default C/C++ suite"),
            text: include_str!("fixtures/ext.codeql.txt"),
            secondary: "",
            // Captured by running the adapter's **own** argv against a real
            // database (`tools/codeql-taint-cpp/db`), which is how the invocation
            // defect was found: see `ext.codeql`'s spec. Trimmed the way the
            // Semgrep fixture is — 57 of the 58 rule definitions dropped and the
            // surviving `ruleIndex` renumbered, plus the `artifacts`,
            // `invocations` and driver `notifications` blocks, none of which the
            // parser reads. Every byte of the result itself is the tool's.
            //
            // The reconstruction this replaced was wrong in three ways at once:
            // it named a rule the run does not produce, it carried
            // `"level": "error"` where real CodeQL emits **no `level` at all`,
            // and it had no `properties.tags`, so it could not have exercised the
            // CWE path that the `external/cwe/cwe-078` form once broke.
            expect: 1,
            anchor_rule: "cpp/command-line-injection",
            anchor_file: "actuator/drive.cpp",
            anchor_line: 8,
            // No `level` on the result, so this comes from the rule's
            // `defaultConfiguration.level` — the same fallback the real Semgrep
            // capture forced. A parser reading only `level` reports Medium here.
            worst: Severity::High,
        },
        Fixture {
            id: "ext.modelscan",
            provenance: Provenance::Captured("modelscan 0.8.8"),
            text: include_str!("fixtures/ext.modelscan.txt"),
            secondary: "",
            // Captured from modelscan 0.8.8 via `-o`: one issue plus one
            // artifact that could not be scanned at all. Only `input_path` and
            // `absolute_path` were edited, to strip a local temp path; no field
            // the parser reads was touched.
            expect: 2,
            anchor_rule: "MODELSCAN-PickleUnsafeOpScan-system",
            anchor_file: "backdoored.pkl",
            anchor_line: 1,
            worst: Severity::Critical,
        },
        Fixture {
            id: "ext.valgrind",
            provenance: Provenance::Captured("Valgrind 3.24.0 Memcheck, under WSL Debian"),
            text: include_str!("fixtures/ext.valgrind.txt"),
            secondary: "",
            // Captured from Valgrind 3.24.0 (Memcheck) under WSL Debian, run
            // with the adapter's own arguments against a program written to
            // commit exactly three sins: an invalid write, a conditional jump on
            // an uninitialised value, and a definite leak.
            //
            // `main.c:6` is the store `a[4] = 1`. The frame above it in the
            // trace is Valgrind's own `vg_replace_malloc.c:446`, and reporting
            // *that* was one of the four defects this adapter shipped with.
            expect: 3,
            anchor_rule: "VALGRIND-INVALID-WRITE",
            anchor_file: "main.c",
            anchor_line: 6,
            worst: Severity::Critical,
        },
    ]
}

fn spec_for(id: &str) -> AdapterSpec {
    specs()
        .into_iter()
        .find(|s| s.id == id)
        .unwrap_or_else(|| panic!("no spec with id `{id}`"))
}

/// The central claim: each adapter, given its tool's real output, produces
/// findings that point somewhere real.
#[test]
fn every_adapter_turns_its_tools_output_into_located_findings() {
    for f in fixtures() {
        let spec = spec_for(f.id);
        let found = parse_output_channels(f.text, f.secondary, spec.format, spec.id)
            .unwrap_or_else(|e| panic!("{}: parsing its own tool's output failed: {e}", f.id));

        assert!(
            !found.is_empty(),
            "{}: declared {:?}, parsed its tool's real output, and found nothing — \
             the format is wrong or the parser is",
            f.id,
            spec.format
        );
        assert_eq!(
            found.len(),
            f.expect,
            "{}: expected {} findings, got {}: {:?}",
            f.id,
            f.expect,
            found.len(),
            found.iter().map(|x| x.rule.to_string()).collect::<Vec<_>>()
        );

        let anchor = found
            .iter()
            .find(|x| x.rule.as_str() == f.anchor_rule)
            .unwrap_or_else(|| {
                panic!(
                    "{}: no finding with rule `{}`: {:?}",
                    f.id,
                    f.anchor_rule,
                    found.iter().map(|x| x.rule.to_string()).collect::<Vec<_>>()
                )
            });
        assert_eq!(
            anchor.location.file.to_string_lossy().replace('\\', "/"),
            f.anchor_file,
            "{}: `{}` is mislocated",
            f.id,
            f.anchor_rule
        );
        assert_eq!(anchor.location.line, f.anchor_line, "{}: `{}` is on the wrong line", f.id, f.anchor_rule);

        let worst = found.iter().map(|x| x.severity).max().expect("non-empty");
        assert_eq!(
            worst, f.worst,
            "{}: severity mapping has flattened or inflated the sample",
            f.id
        );

        // Every finding must be attributed to the adapter that produced it, or
        // the report cannot say where a claim came from.
        for x in &found {
            assert_eq!(x.provider.as_str(), f.id, "{}: misattributed finding", f.id);
            assert!(!x.location.file.as_os_str().is_empty(), "{}: finding with no file", f.id);
            assert!(x.location.line >= 1, "{}: finding on line 0", f.id);
        }
    }
}

/// Adding an adapter must mean adding a fixture. Without this, the next spec
/// with a wrong `format` ships exactly the way `ext.valgrind` did.
#[test]
fn every_spec_has_a_fixture_behind_it() {
    let covered: Vec<&str> = fixtures().iter().map(|f| f.id).collect();
    let missing: Vec<&str> = specs()
        .iter()
        .map(|s| s.id)
        .filter(|id| !covered.contains(id))
        .collect();
    assert!(
        missing.is_empty(),
        "these adapters have no recorded tool output to prove they work: {missing:?} — \
         add `crates/sda-adapters/tests/fixtures/<id>.txt` and an entry in `fixtures()`"
    );
}

/// And the reverse, so a fixture for a deleted adapter does not sit here
/// passing forever and implying coverage that no longer means anything.
#[test]
fn no_fixture_outlives_the_adapter_it_covers() {
    let ids: Vec<&str> = specs().iter().map(|s| s.id).collect();
    for f in fixtures() {
        assert!(ids.contains(&f.id), "fixture `{}` covers an adapter that no longer exists", f.id);
    }
}

/// Executables that are Python console scripts.
///
/// This is not trivia. `rich` — which almost every modern Python CLI renders
/// through — wraps and colourises whatever the program prints, **including
/// output redirected to a file**, and that is what broke `ext.modelscan`: its
/// stdout was not valid JSON at all. It was not a ModelScan bug and it will not
/// be the last tool to have it. Semgrep, also Python, writes clean SARIF to
/// stdout, so the failure is not universal either — which is exactly why it has
/// to be checked per tool rather than assumed in either direction.
const PYTHON_CLIS: &[&str] = &["semgrep", "modelscan"];

/// The population at risk, and the rule that keeps it checked.
///
/// A reconstruction cannot discover how a tool actually renders its output,
/// because it is written from the format the tool documents rather than from the
/// bytes it emits — and the `rich` failure is invisible in the documented format.
/// So an adapter wrapping a Python CLI must rest on a capture.
#[test]
fn no_adapter_wrapping_a_python_cli_rests_on_a_reconstruction() {
    for f in fixtures() {
        let spec = spec_for(f.id);
        if !PYTHON_CLIS.contains(&spec.executable) {
            continue;
        }
        assert!(
            matches!(f.provenance, Provenance::Captured(_)),
            "`{}` wraps the Python CLI `{}`, whose real stdout is exactly what a reconstruction cannot predict — see `PYTHON_CLIS`",
            f.id,
            spec.executable
        );
    }
}

/// The reconstructions, named. Failing here is the point: a new adapter must
/// choose, and a fixture that stops being a reconstruction must say so.
#[test]
fn the_reconstructed_fixtures_are_exactly_the_ones_we_admit_to() {
    let reconstructed: Vec<&str> = fixtures()
        .iter()
        .filter(|f| f.provenance == Provenance::Reconstructed)
        .map(|f| f.id)
        .collect();
    let none: Vec<&str> = Vec::new();
    assert_eq!(
        reconstructed,
        none,
        "the set of unverified adapters changed. Nine of the ten real-tool encounters so far found a defect, seven in adapters that were fully green, so growing this set is a regression even when everything still passes"
    );
}

/// A capture must say what it captured. "Captured" with no version is a claim
/// nobody can re-run.
#[test]
fn every_capture_names_its_tool_version() {
    for f in fixtures() {
        if let Provenance::Captured(from) = f.provenance {
            assert!(
                !from.trim().is_empty(),
                "{}: a capture with no stated source cannot be reproduced",
                f.id
            );
        }
    }
}

/// No spec may ask a tool to write its report to `-`.
///
/// `ext.codeql` shipped with `--output=-`, on the reasonable assumption that a
/// dash means stdout. CodeQL creates a **file literally named `-`** in the
/// working directory, writes the SARIF into it, prints a prose coverage line to
/// stdout, and exits 0 — so the adapter parsed that sentence as SARIF, could
/// never have produced a finding, and left a junk file in the user's repository
/// on every run. The convention is a convention, not a guarantee, and a tool that
/// does not honour it fails in a way that looks like success.
///
/// A tool that writes to a file gets `{output}`, which names a real path the
/// adapter reads back.
#[test]
fn no_spec_asks_a_tool_to_write_its_report_to_a_file_named_dash() {
    for spec in specs() {
        for (i, arg) in spec.args.iter().enumerate() {
            let is_dash_output = *arg == "-o"
                || arg.ends_with("--output=-")
                || (*arg == "--output" && spec.args.get(i + 1) == Some(&"-"));
            let next_is_dash = spec.args.get(i + 1) == Some(&"-");
            assert!(
                !(arg.ends_with("--output=-") || (is_dash_output && next_is_dash)),
                "`{}` asks its tool to write to `-`. Use `{{output}}`: see this test's comment",
                spec.id
            );
        }
    }
}
