//! Configuration the project asked for and did not get must be in the report.
//!
//! `.sda/` can declare deviations, scope, an architecture and a replacement
//! catalogue. Each of those can be partly refused — a component whose boundary
//! makes no sense, a scope rule that excludes the analysis root, a catalogue
//! that will not parse — and each refusal narrows the run.
//!
//! All of them were printed as `warning:` on stderr and went no further. That is
//! not the report. `sda scan --format json > report.json` keeps `exclusions` and
//! discards stderr, so a project declaring two components, one of them rejected,
//! produced a saved report with no trace of the rejection — and an interposition
//! result computed over a graph smaller than the file describes. Measured before
//! it was fixed: `grep -c llm-judge report.json` returned zero.
//!
//! The comment in `main.rs` two lines below where those warnings were printed
//! already read "`scope_notices` must reach the report"; somebody had made this
//! exact argument for scope and the configuration loader never got it.
//!
//! The other half of the claim is that the report must not say the same thing
//! twice. An accepted declaration's advisory warnings are re-derived downstream
//! by the layer they affect, and a *NOT CHECKED* section with two wordings of
//! one fact is a section people learn to skim. `no_effector` below pins both
//! halves at once.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A project directory with a `.sda/` holding one declaration file.
fn project(name: &str, file: &str, text: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sda-config-report-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".sda")).expect("a scratch .sda");
    std::fs::create_dir_all(dir.join("src")).expect("a source directory");
    std::fs::write(dir.join("src/a.c"), "int f(int x) { return x + 1; }\n").expect("a source file");
    std::fs::write(dir.join(".sda").join(file), text).expect("the declaration");
    dir
}

/// Scan as JSON and return the `exclusions` array, which is the report's
/// *NOT CHECKED* section as an artifact rather than as terminal output.
fn exclusions(dir: &Path) -> Vec<(String, String)> {
    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .args(["scan", &dir.to_string_lossy(), "--format", "json"])
        .output()
        .expect("the sda binary runs");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("the report must be JSON ({e}): {stdout}"));

    value["exclusions"]
        .as_array()
        .expect("a report always has an exclusions array")
        .iter()
        .map(|e| {
            (
                e["provider"].as_str().unwrap_or_default().to_string(),
                e["reason"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn config_notices(ex: &[(String, String)]) -> Vec<String> {
    ex.iter()
        .filter(|(p, _)| p == "sda.config")
        .map(|(_, r)| r.clone())
        .collect()
}

/// A component the parser refused is named in the saved report.
///
/// A neural guard is refused because a guard that is itself a model moves the
/// premise rather than discharging it. The refusal is right; losing it between
/// the terminal and the file is not. Without the component the interposition
/// proof walks a graph with one fewer node than the declaration describes, and
/// that is precisely the shape of result this tool exists to refuse to give.
#[test]
fn a_rejected_architecture_component_is_named_in_the_report() {
    let dir = project(
        "arch",
        "architecture.toml",
        "[[component]]\nname = \"core\"\npath = \"src\"\nboundary = \"symbolic\"\n\
         [[component]]\nname = \"llm-judge\"\npath = \"judge\"\nboundary = \"neural\"\n\
         role = \"guard\"\n",
    );
    let ex = exclusions(&dir);
    let notices = config_notices(&ex);

    assert!(
        notices.iter().any(|r| r.contains("llm-judge") && r.contains("rejected")),
        "the dropped component must be in the report, not only on stderr: {notices:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// And the report does not then say the same thing twice.
///
/// That declaration also draws an advisory warning — no component is declared an
/// effector — which the interposition layer already states in its own words,
/// because it is the layer that could not ask the question. Routing every
/// problem rather than only the unapplied ones would have produced both.
#[test]
fn an_advisory_warning_is_not_repeated_alongside_the_layer_that_states_it() {
    let dir = project(
        "advisory",
        "architecture.toml",
        "[[component]]\nname = \"core\"\npath = \"src\"\nboundary = \"symbolic\"\n",
    );
    let ex = exclusions(&dir);

    assert!(
        ex.iter().any(|(p, r)| p == "sda.interposition" && r.contains("effector")),
        "the layer that could not ask the question must still say so: {ex:?}"
    );
    assert!(
        config_notices(&ex).iter().all(|r| !r.contains("effector")),
        "and the configuration loader must not say it a second time in different words: {ex:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A scope rule that was refused is in the report too.
///
/// A rule owning the analysis root would exclude everything; it is refused, and
/// the run then scans wider than the project asked for. Over-reporting is the
/// recoverable direction, which is why it is not an error — and exactly why the
/// report has to say it happened.
#[test]
fn a_rejected_scope_rule_is_named_in_the_report() {
    let dir = project("scope", "scope.toml", "[[excluded]]\npath = \".\"\nreason = \"all of it\"\n");
    let notices = config_notices(&exclusions(&dir));

    assert!(
        !notices.is_empty(),
        "a scope declaration that did not take effect leaves the scan wider than declared, \
         and the report must say so: {notices:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A replacement catalogue that will not load is in the report.
///
/// This is the sharpest of the four. A project ships its own transcription of a
/// standard — that is how licensed rule text gets in — and when it fails to
/// load, the built-in catalogue stays silently in place. `sda rules audit` then
/// goes on describing a catalogue the project tried to replace, and the
/// conformance argument rests on rule text nobody supplied.
#[test]
fn a_catalogue_that_would_not_load_is_named_in_the_report() {
    let dir = project("catalog", "misra-c-2023.toml", "this is not toml at all [[[\n");
    let notices = config_notices(&exclusions(&dir));

    assert!(
        notices.iter().any(|r| r.contains("misra-c-2023")),
        "a catalogue the project meant to replace, still the built-in one, with nothing in \
         the report to say so: {notices:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A flow edge naming no component is named in the report.
///
/// The warning existed and its only callers were tests, so the edge's path left
/// the interposition proof with nothing said anywhere.
#[test]
fn a_flow_edge_to_nothing_is_named_in_the_report() {
    let dir = project(
        "flow-typo",
        "architecture.toml",
        "[[component]]\nname = \"core\"\npath = \"src\"\nboundary = \"symbolic\"\n\
         role = \"effector\"\n\n[[flow]]\nfrom = \"polcy\"\nto = \"core\"\n",
    );
    let notices = config_notices(&exclusions(&dir));

    assert!(
        notices.iter().any(|r| r.contains("polcy") && r.contains("not a declared component")),
        "a typo that removes a path from the proof must be in the report: {notices:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A neural profile field with no architecture is named in the report.
///
/// `parameters`, `sequence_bound` and `input_region` are read only where a
/// profile is built, and a profile is built only for a named architecture. With
/// no architecture the declared size was parsed and then read by nothing, and the
/// proof ran as though the model had no declared size at all.
#[test]
fn a_neural_size_with_no_architecture_is_named_in_the_report() {
    let dir = project(
        "neural-size",
        "architecture.toml",
        "[[component]]\nname = \"policy\"\npath = \"models/policy\"\nboundary = \"neural\"\n\
         parameters = 7000000000\n",
    );
    let notices = config_notices(&exclusions(&dir));

    assert!(
        notices.iter().any(|r| r.contains("policy") && r.contains("no architecture")),
        "a declared size that the proof never reads must be in the report: {notices:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A neural profile field on a symbolic component is named in the report.
///
/// The same field on a component that is not neural has no profile to land in.
/// The component stays in the proof and the field is reported as ignored.
#[test]
fn a_sequence_bound_on_a_symbolic_component_is_named_in_the_report() {
    let dir = project(
        "symbolic-bound",
        "architecture.toml",
        "[[component]]\nname = \"core\"\npath = \"src\"\nboundary = \"symbolic\"\n\
         sequence_bound = 64\n",
    );
    let notices = config_notices(&exclusions(&dir));

    assert!(
        notices.iter().any(|r| r.contains("core") && r.contains("not neural")),
        "a bound on a component that is not a model must be in the report: {notices:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A catalogue rule declaring system scope is named in the report.
///
/// The `s` key of an imported guideline is parsed into `Rule::scope`, and no
/// check reads it. A project that imported "judged across the program" for a
/// guideline got a result judged one translation unit at a time, with no notice.
#[test]
fn a_catalogue_rule_declaring_system_scope_is_named_in_the_report() {
    let dir = project(
        "catalog-scope",
        "misra-c-2023.toml",
        "[[rule]]\nn = \"15.5\"\nt = \"a rule the project restates\"\no = \"required\"\n\
         d = \"decidable\"\ns = \"system\"\nc = \"native\"\n",
    );
    let notices = config_notices(&exclusions(&dir));

    assert!(
        notices.iter().any(|r| r.contains("misra-c-2023") && r.contains("system scope")),
        "a declared scope that no check reads must be in the report: {notices:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
