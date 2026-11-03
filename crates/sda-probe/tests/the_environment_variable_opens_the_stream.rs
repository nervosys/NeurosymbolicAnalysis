//! `SDA_PROBE_OUT` is how instrumentation finds its output, and nothing ran it.
//!
//! This is the mechanism the whole statodynamic claim rests on. The engine sets
//! the variable before launching a target (`dynamic::run_once`); the target's
//! instrumentation reads it when the session first initialises; records land in
//! that file and come back as coverage. Without it there is no coverage, so
//! nothing can be confirmed, refuted or called unreached, and the result is a
//! static one wearing a dynamic name.
//!
//! The unit tests in this crate cannot exercise it. The session is a
//! process-global `OnceLock` — an instrumented target has one output stream, not
//! one per call site — and their `rebind` helper points the already-initialised
//! session at a fresh file, deliberately bypassing the env-var path. `run_once`
//! is called by the runner and the fuzzer and by no test at all.
//!
//! So it was verified by hand, once: a Cortex-M3 image under QEMU, twelve
//! records captured, recorded in the metrics table and dated. That is a
//! measurement of an afternoon rather than a check that runs again.
//!
//! An integration test is its own binary and therefore its own process, with its
//! own `OnceLock`. One test in this file, and it sets the variable before
//! anything touches the session — which is the only ordering under which the
//! real initialisation path can be observed.

/// The variable names the file, and the records arrive in it.
#[test]
fn records_reach_the_file_named_by_the_environment_variable() {
    let dir = std::env::temp_dir().join("sda-probe-env-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("stream.jsonl");

    // SAFETY: this is the first statement in the only test in this binary, so
    // no other thread exists yet and nothing has read the environment. The
    // session's `OnceLock` is untouched until the first probe call below, which
    // is the point: this is the one ordering that exercises the real path.
    unsafe {
        std::env::set_var(sda_probe::OUTPUT_ENV, &path);
    }

    assert!(
        sda_probe::is_enabled(),
        "with `{}` set, instrumentation must be live. Disabled here means every probe below \
         is a no-op and every assertion would fail as though the emitters were broken",
        sda_probe::OUTPUT_ENV
    );

    sda_probe::cov("src/main.c", 42);
    sda_probe::cov("src/main.c", 42);
    sda_probe::fault("src/main.c", 51, "bounds", "index past end of buffer");
    sda_probe::flush();

    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "nothing was written to `{}` ({e}). An empty capture is indistinguishable from a \
             program that executed nothing, which is exactly the reading this toolkit exists \
             to refuse",
            path.display()
        )
    });

    let obs = sda_engine::dynamic::parse_probe_stream(&text, "env-test");
    assert_eq!(
        obs.covered("src/main.c", 42),
        2,
        "both hits on line 42 reach the observation through the real path: {text}"
    );
    assert_eq!(
        obs.defects().count(),
        1,
        "and the fault with them: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
