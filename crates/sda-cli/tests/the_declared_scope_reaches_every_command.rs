//! A command that runs its own discovery has to decide about `.sda/scope.toml`,
//! and the decision has to be visible in the source.
//!
//! `.sda/scope.toml` names directories the project has declared outside
//! analysis, each with a reason and a named approver. `sda scan` removes them
//! before any provider is built. Six commands run their own discovery, and the
//! declaration reached two of them.
//!
//! The rest were found one at a time, which is the reason this file exists
//! rather than a sixth individual test:
//!
//! * `hotspots` analyzed excluded files and **ranked one first**, under a
//!   heading offering the files worth looking at first.
//! * `plan` promised a `sda.static.cpp` step for a project whose only C++ was
//!   excluded — a plan is a promise about a run, and the scan ran one step.
//! * `fuzz` correlated coverage into verdicts about files `sda scan` will not
//!   report on.
//! * `ai scan` printed a digest and a format for artifacts under an excluded
//!   directory.
//!
//! And `plan` is the one worth reading twice: the MCP copy of that same command
//! had applied scope since it was written, with the reason in a comment beside
//! the call. The argument for the correct behaviour was already written down,
//! in the other implementation of the same command, and neither the comment nor
//! the behaviour reached this one.
//!
//! This is a source-shape test and it is blunt: it can tell that a function
//! decided, not that it decided well. `impact` is here as a named exemption
//! precisely because the right answer for it is *ignore the scope* — a caller
//! in an excluded directory still reaches your code, and hiding it would put
//! the floor below the truth. A list of exemptions that has to be edited
//! deliberately is the point; the defect this catches is the one where nobody
//! chose at all.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

/// Commands that run discovery and deliberately do **not** narrow by scope.
///
/// Each must say so in its own output — there are tests for that beside each
/// one — so this list is about the source, not about the user-visible promise.
const CROSSES_SCOPE_ON_PURPOSE: &[&str] = &[
    // A blast radius that hides an out-of-scope caller is a floor below the
    // truth, which is the one direction that answer must never move.
    "impact",
    "analysis_impact",
];

fn functions(source: &str) -> Vec<(String, String)> {
    let mut starts: Vec<usize> = source
        .match_indices("\nfn ")
        .chain(source.match_indices("\npub fn "))
        .map(|(i, _)| i + 1)
        .collect();
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

#[test]
fn every_command_that_discovers_its_own_files_decides_about_scope() {
    let files = [
        repo_root().join("crates").join("sda-cli").join("src").join("main.rs"),
        repo_root().join("crates").join("sda-agent").join("src").join("dispatch.rs"),
    ];

    let mut checked = 0;
    let mut silent = Vec::new();

    for path in &files {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()));

        for (name, body) in functions(&source) {
            // Its own discovery, as opposed to going through a helper that has
            // already applied scope.
            if !body.contains("discover::discover(") {
                continue;
            }
            checked += 1;

            if CROSSES_SCOPE_ON_PURPOSE.contains(&name.as_str()) {
                continue;
            }
            // `apply_scope` narrows it; `discover_project` and `target_for` are
            // the helpers that narrow it for you.
            let decided = body.contains("apply_scope")
                || body.contains("discover_project")
                || body.contains("target_for");
            if !decided {
                silent.push(format!(
                    "{}::{name}",
                    path.file_name().unwrap().to_string_lossy()
                ));
            }
        }
    }

    assert!(
        checked >= 5,
        "only {checked} self-discovering command(s) found; the scan is not reaching them"
    );

    assert!(
        silent.is_empty(),
        "these run their own discovery and never mention the declared scope, so they analyze \
         files the project excluded and no reader can tell whether that was a decision: \
         {silent:?}. Either apply the scope, or add the name to CROSSES_SCOPE_ON_PURPOSE with \
         the reason"
    );
}
