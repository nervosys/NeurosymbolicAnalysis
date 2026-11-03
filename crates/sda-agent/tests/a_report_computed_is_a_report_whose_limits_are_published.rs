//! Every function that computes a report has to carry what that report could
//! not check.
//!
//! `run::analyze` attaches `sda.discovery` when no enabled provider read
//! anything that was found — a mistyped path, a build directory, a tree of
//! languages this does not handle. `report_json` publishes it, so the scan
//! tools are fine. The functions that call `analyze` for *part* of an answer
//! and render that part themselves were not: they took `report.findings`, or
//! `report.summary.by_verdict`, and dropped `report.exclusions` on the floor.
//!
//! Four did, and they were found one at a time rather than as a class:
//!
//! * `hotspots` (CLI) — an empty ranking under a heading promising the files
//!   worth looking at first.
//! * `analysis_hotspots` (MCP) — the same, to a caller who cannot notice that
//!   the directory looked wrong on the way past.
//! * `fuzz` / `fuzz_campaign` — a correlation table with no rows. The source
//!   path is a different argument from the artifact and can be wrong alone.
//! * `analysis_baseline` — the one that writes to disk, and the reason this
//!   file exists rather than a fourth one-off test.
//!
//! Finding the fourth after fixing the first three is the argument for checking
//! the class instead of the instance. This is a source-shape test, which is a
//! blunt instrument: it cannot tell that a caveat is *good*, only that the
//! function looked at the field at all. It is worth having anyway, because the
//! defect it catches is the one where nobody looked.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

/// Top-level `fn` bodies in a file, as `(name, body)`.
///
/// Crude on purpose: functions start at column zero in this codebase, so the
/// next one begins the next body. A parser would be more correct and would also
/// be a second thing that can be wrong.
fn functions(source: &str) -> Vec<(String, String)> {
    let starts: Vec<usize> = source
        .match_indices("\nfn ")
        .chain(source.match_indices("\npub fn "))
        .map(|(i, _)| i + 1)
        .collect();
    let mut starts = starts;
    starts.sort_unstable();

    let mut out = Vec::new();
    for (i, at) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(source.len());
        let body = &source[*at..end];
        let name = body
            .trim_start_matches("pub ")
            .trim_start_matches("fn ")
            .split(['(', '<'])
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        if !name.is_empty() {
            out.push((name, body.to_string()));
        }
    }
    out
}

/// Does this body obtain a report — by computing one, or by loading one
/// somebody else computed?
///
/// The loading half was missing, and `report_query` sat in the gap. It
/// deserialises a `sda_core::Report` from disk, so it never calls `analyze` and
/// the first version of this test never looked at it. A stored scan of a tree
/// nothing could read carries eleven exclusions, and that tool answered
/// `{"matched": 0, "shown": 0, "findings": []}` to an agent.
///
/// A guard written around how a report is *produced* misses every surface that
/// reads one back, which is the half a caller is most likely to be talking to
/// six months later.
fn computes_a_report(body: &str) -> bool {
    body.contains("analyze(&registry")
        || body.contains("analyze(&default_registry()")
        || body.contains("run::analyze(")
        || body.contains("sda_core::Report =")
}

/// Does it acknowledge what that report could not check?
///
/// `report_json` counts because publishing through it carries every exclusion.
/// `not_checked` counts because `analysis_impact` builds one from its own
/// caveats and never touches `report.exclusions` at all.
///
/// **And that last allowance is a hole, measured.** Replace `report_query`'s
/// notices with `let not_checked: Vec<Value> = Vec::new();` and this test still
/// passes: the identifier survives, and a name is all this can see. It is the
/// failure this repository keeps a table of — a check that something was said
/// rather than that the right thing was — living in a guard written against
/// exactly that.
///
/// It is kept anyway, because it catches the case where nobody looked, which is
/// every instance found so far. The vacuous-binding case is caught one level
/// up, by tests that call the tool and read the payload; see
/// `report_query_carries_the_stored_report's_own_not_checked` beside the MCP
/// suite. Two instruments, two failures, and neither pretending to be the
/// other.
fn publishes_the_limits(body: &str) -> bool {
    body.contains("exclusions") || body.contains("report_json") || body.contains("not_checked")
}

#[test]
fn every_function_that_computes_a_report_reads_its_exclusions() {
    let files = [
        repo_root().join("crates").join("sda-agent").join("src").join("dispatch.rs"),
        repo_root().join("crates").join("sda-cli").join("src").join("main.rs"),
    ];

    let mut checked = 0;
    let mut offenders = Vec::new();

    for path in &files {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()));
        for (name, body) in functions(&source) {
            if !computes_a_report(&body) {
                continue;
            }
            checked += 1;
            if !publishes_the_limits(&body) {
                offenders.push(format!("{}::{name}", path.file_name().unwrap().to_string_lossy()));
            }
        }
    }

    // If this drops to zero the walk has stopped reaching the tree, and a test
    // that checks nothing passes loudest of all.
    assert!(
        checked >= 6,
        "only {checked} report-computing function(s) found; the scan is not reaching them"
    );

    assert!(
        offenders.is_empty(),
        "these compute a report and never look at what it could not check, so whatever they \
         render is a number from a scan whose limits went nowhere: {offenders:?}"
    );
}

/// A run over a project carries the project's declared position, or says why
/// not.
///
/// `project_setup` exists because two call sites drifted apart, and its doc
/// comment says so: *shared rather than repeated, because the two call sites
/// drifted precisely while nobody was comparing them*. Three more call sites
/// were written afterwards that repeated it anyway, and each got part of the
/// project and not the rest:
///
/// * `analysis_hotspots` -- no scope and no deviations, so it ranked excluded
///   files and counted accepted findings.
/// * `fuzz_campaign` and the CLI `fuzz` -- no deviations, so the campaign's
///   verdict table re-raised findings the process had settled. `correlate`
///   refuses to do that, and the refusal needs something marked suppressed
///   before it can fire.
/// * the CLI `plan` -- no scope, so it promised a step the scan would not run.
///
/// A warning in a doc comment is not a check. This is the check: anything
/// building a `RunConfig` for a project has to load the deviation register, or
/// go through the helper that does.
#[test]
fn every_run_over_a_project_loads_the_deviation_register() {
    let files = [
        repo_root().join("crates").join("sda-agent").join("src").join("dispatch.rs"),
        repo_root().join("crates").join("sda-cli").join("src").join("main.rs"),
    ];

    let mut checked = 0;
    let mut bare = Vec::new();

    for path in &files {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()));

        for (name, body) in functions(&source) {
            if !body.contains("RunConfig::default()") {
                continue;
            }
            // The helper is where the loading lives.
            if name == "project_setup" {
                continue;
            }
            checked += 1;
            let loads = body.contains("with_deviations") || body.contains("project_setup");
            if !loads {
                bare.push(format!(
                    "{}::{name}",
                    path.file_name().unwrap().to_string_lossy()
                ));
            }
        }
    }

    assert!(
        checked >= 3,
        "only {checked} project run(s) found; the scan is not reaching them"
    );
    assert!(
        bare.is_empty(),
        "these build a run over a project without its deviation register, so findings the \
         project formally accepted come back as live ones: {bare:?}. Use `project_setup`, or \
         load the register the way `scan` does"
    );
}
