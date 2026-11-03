//! A run given an artifact that will not execute must not say none was given.
//!
//! `--artifact broken.bin` on a file that is not an executable produces two
//! notices. `sda.dynamic` says the artifact could not be launched, which is
//! right. `sda.correlate` said *no runtime observation was supplied*, which was
//! false in the one run where it mattered: the operator supplied exactly what was
//! asked for, and it failed.
//!
//! The distinction is not pedantry — it is the difference between two different
//! next actions. *You did not supply one* sends a reader to build the artifact.
//! *Yours did not run* sends them to fix it. A report carrying both statements at
//! once sends them nowhere, and quietly teaches them that one of the two sections
//! is unreliable.
//!
//! The wording is now true of both cases — nothing *reached* the run — and
//! `sda.dynamic` carries the cause when there is one. Found by sweeping the CLI's
//! eighteen `eprintln!` sites for limitations the report might not carry, after
//! three separate defects this session turned out to be exactly that shape.

use std::process::Command;

/// Scan with a deliberately unexecutable artifact and return the exclusions.
fn exclusions_with_broken_artifact() -> Vec<(String, String)> {
    let dir = std::env::temp_dir().join("sda-broken-artifact");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch project");
    std::fs::write(dir.join("a.c"), "int f(int x) { return x + 1; }\n").expect("a source file");
    // Not an executable in any format, on any platform.
    let artifact = dir.join("broken.bin");
    std::fs::write(&artifact, "not an executable at all\n").expect("the artifact");

    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .args(["scan", &dir.to_string_lossy()])
        .args(["--artifact", &artifact.to_string_lossy()])
        .args(["--format", "json"])
        .output()
        .expect("the sda binary runs");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("the report must be JSON ({e}): {stdout}"));

    let rows = value["exclusions"]
        .as_array()
        .expect("a report always has an exclusions array")
        .iter()
        .map(|e| {
            (
                e["provider"].as_str().unwrap_or_default().to_string(),
                e["reason"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();

    let _ = std::fs::remove_dir_all(&dir);
    rows
}

/// The failure is reported, and nothing claims the artifact was never given.
#[test]
fn an_artifact_that_could_not_run_is_not_reported_as_one_that_was_never_supplied() {
    let exclusions = exclusions_with_broken_artifact();

    assert!(
        exclusions.iter().any(|(p, _)| p == "sda.dynamic"),
        "the launch failure has to be in the report: {exclusions:?}"
    );

    for (provider, reason) in &exclusions {
        assert!(
            !reason.contains("observation was supplied"),
            "`{provider}` says nothing was supplied, in a run where something was and it \
             failed. The reader is sent to build an artifact they already have: {reason}"
        );
    }

    let correlate = exclusions
        .iter()
        .find(|(p, _)| p == "sda.correlate")
        .map(|(_, r)| r.clone())
        .expect("correlation still accounts for itself");
    assert!(
        correlate.contains("reached this run"),
        "the wording has to be true whether none was supplied or one failed: {correlate}"
    );
    assert!(
        correlate.contains("static-only"),
        "and still say what the run amounts to: {correlate}"
    );
}
