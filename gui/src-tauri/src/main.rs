//! The Tauri shell for the StatodynamicAnalysis workbench.
//!
//! Thin by design: every command here delegates straight into the analysis
//! crates and returns already-shaped data. No analysis logic lives in the GUI,
//! and none lives in the JavaScript.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod pty;
mod shell;

use shell::{CoverageLine, Document, UiFinding, to_ui};
use std::path::PathBuf;
use std::sync::Mutex;

/// The workbench's state: the last report, so the UI can re-query it without
/// re-running analysis.
#[derive(Default)]
struct State {
    report: Mutex<Option<sda_core::Report>>,
    terminal: Mutex<Option<pty::Terminal>>,
    /// The project the last scan covered, so triage writes land next to the code
    /// that was analysed rather than next to wherever the binary was launched.
    root: Mutex<Option<PathBuf>>,
}

/// Where a project's review state lives.
fn triage_path(root: &str) -> PathBuf {
    PathBuf::from(root).join(sda_rules::CONFIG_DIR).join("triage.toml")
}

/// Where the recorded previous run lives.
fn baseline_path(root: &str) -> PathBuf {
    PathBuf::from(root).join(sda_rules::CONFIG_DIR).join("baseline.toml")
}

#[tauri::command]
fn open_document(path: String) -> Result<Document, String> {
    let p = PathBuf::from(&path);
    let text = std::fs::read_to_string(&p).map_err(|e| format!("{path}: {e}"))?;
    let language = sda_core::Language::from_path(&p);
    Ok(Document { path: p, text, language: language.to_string(), version: 1 })
}

/// Analyze a buffer that may never have been written to disk — the fast path
/// that makes the editor feel live.
#[tauri::command]
fn check_buffer(path: String, text: String) -> Result<Vec<UiFinding>, String> {
    let p = PathBuf::from(&path);
    // Through the engine, so live typing and the findings list cannot disagree
    // about the project's catalogues or its approved deviations.
    let project = sda_rules::ProjectConfig::discover(&p);
    let findings = sda_engine::check_buffer(&project, &p, &text);
    let report = sda_core::Report::new(path, findings.clone());
    Ok(findings.iter().map(|f| to_ui(f, &report)).collect())
}

/// Build the analyzer set and run configuration for a project.
///
/// Shared so the workbench and `sda scan` answer identically for one project.
/// They did not, once: the GUI ignored `.sda/`, so a project's approved
/// deviations were applied on the command line and not in the window. Two
/// different answers for one project is worse than either answer alone.
/// Discover a target and apply the project's declared analysis scope.
///
/// Separate from [`project_setup`] only because `plan` needs a target without a
/// registry. Everything that analyses goes through one of the two, so a
/// `scope.toml` cannot be honoured on the command line and ignored in the
/// window — which is exactly what happened with `.sda/` deviations once already.
fn scoped_target(
    path: &str,
    project: &sda_rules::ProjectConfig,
) -> (sda_core::Target, Vec<sda_core::Exclusion>) {
    let mut target = sda_engine::discover::discover(
        path,
        &sda_engine::discover::DiscoveryOptions::default(),
    );
    // Anchored at the directory the declaration governs — see
    // `ProjectConfig::root`. Opening a subdirectory of a configured project in
    // the workbench must honour the same rules the command line does.
    let notices = match (&project.scope, project.root()) {
        (Some(scope), Some(anchor)) => {
            sda_engine::discover::apply_scope(&mut target, scope, anchor)
        }
        _ => Vec::new(),
    };
    (target, notices)
}

/// Returns the target as well as the registry and config, so a caller cannot
/// analyse an unscoped target with a scoped configuration by accident.
fn project_setup(
    path: &str,
    allow_external: bool,
) -> (sda_core::Target, sda_core::Registry, sda_engine::run::RunConfig) {
    let mut project = sda_rules::ProjectConfig::discover(std::path::Path::new(path));
    let (target, notices) = scoped_target(path, &project);
    let mut registry = sda_engine::registry_for_project(&project);
    registry.register(std::sync::Arc::new(sda_ai::ModelScanner::new()));

    let mut config = sda_engine::run::RunConfig::default().with_notices(notices);
    if let Some(register) = project.deviations.take() {
        config = config.with_deviations(register);
    }
    if let Some(decl) = project.architecture.take() {
        config = config.with_architecture(decl);
    }
    // Registered either way, enabled only on request: the *NOT CHECKED* section
    // must name the external providers this run did not use, and it cannot name
    // a provider the registry never heard of. `Registry::select` applies the
    // policy before it probes availability, so a disabled adapter costs nothing.
    sda_adapters::register_all(&mut registry);
    if allow_external {
        config = config.with_external();
    }
    (target, registry, config)
}

/// Run a full analysis over a project, optionally executing an artifact.
#[tauri::command]
fn scan(
    path: String,
    artifact: Option<String>,
    allow_external: bool,
    state: tauri::State<State>,
) -> Result<Vec<UiFinding>, String> {
    let (target, registry, mut config) = project_setup(&path, allow_external);

    if let Some(a) = artifact.filter(|a| !a.is_empty()) {
        let engine = sda_engine::DynamicEngine::new(vec![
            sda_engine::RunSpec::new(&a).id("gui-run-0"),
        ]);
        config = config.with_observation(engine.observe().map_err(|e| e.to_string())?);
    }

    let report = sda_engine::run::analyze(&registry, &target, &config);
    // Review state is folded in here rather than fetched separately, so a finding
    // and the conclusion someone reached about it cannot arrive out of step.
    // Propagated, for the reason the comment below gives about the baseline. An
    // absent triage file is already `Ok(default)`, so the only thing
    // `unwrap_or_default()` could swallow was a *malformed* one — and it turned
    // every recorded conclusion into "nobody has looked at this", which is the
    // state that gets a finding dismissed a second time. The write paths in this
    // file have always propagated; only the read path did not, so a corrupt
    // store showed as untriaged and then errored the moment anyone tried to
    // triage.
    let triage = sda_rules::TriageStore::load(&triage_path(&path))?;
    // `None` here means no baseline was recorded, and every finding's `is_new`
    // stays `None` — unknown, which the UI shows as such. A malformed baseline is
    // an error rather than an absent one, so it does not quietly become "nothing
    // is new".
    let baseline = sda_rules::Baseline::load(&baseline_path(&path))?;
    let ui: Vec<UiFinding> = report
        .findings
        .iter()
        .map(|f| shell::to_ui_full(f, &report, Some(&triage), baseline.as_ref()))
        .collect();
    *state.report.lock().unwrap() = Some(report);
    *state.root.lock().unwrap() = Some(PathBuf::from(&path));
    Ok(ui)
}

/// Record a conclusion about a finding, or clear one.
///
/// Writes `.sda/triage.toml`, which is the same file an agent reads and writes
/// over MCP. Neither side owns the state, so a human scrolling the workbench and
/// an agent working the backlog cannot diverge without it showing in a diff.
// Tauri maps each named field of the frontend's `invoke` call to a parameter, so
// the argument list is the IPC schema; a struct would only rename it.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
fn set_triage(
    id: String,
    state_name: String,
    note: Option<String>,
    by: Option<String>,
    rule: Option<String>,
    location: Option<String>,
    title: Option<String>,
    state: tauri::State<State>,
) -> Result<(), String> {
    let root = state
        .root
        .lock()
        .unwrap()
        .clone()
        .ok_or("no project has been scanned yet, so there is nothing to record against")?;
    let path = triage_path(&root.to_string_lossy());
    let parsed = sda_rules::TriageState::parse(&state_name)
        .ok_or_else(|| format!("`{state_name}` is not a triage state"))?;

    let mut store = sda_rules::TriageStore::load(&path)?;
    store.set(sda_rules::TriageRecord {
        id,
        state: parsed,
        note: note.filter(|n| !n.trim().is_empty()),
        by: by.filter(|b| !b.trim().is_empty()),
        rule,
        location,
        title,
        assignee: None,
        comments: Vec::new(),
    });
    store.save(&path)
}

/// Context copied onto a new record so the file reads without the tool.
fn context(
    id: &str,
    rule: Option<String>,
    location: Option<String>,
    title: Option<String>,
) -> sda_rules::TriageRecord {
    sda_rules::TriageRecord {
        id: id.to_string(),
        state: sda_rules::TriageState::Open,
        note: None,
        by: None,
        rule,
        location,
        title,
        assignee: None,
        comments: Vec::new(),
    }
}

/// Hand a finding to a person or an agent.
#[tauri::command]
fn assign_finding(
    id: String,
    to: Option<String>,
    rule: Option<String>,
    location: Option<String>,
    title: Option<String>,
    state: tauri::State<State>,
) -> Result<(), String> {
    let root = state.root.lock().unwrap().clone().ok_or("no project has been scanned yet")?;
    let path = triage_path(&root.to_string_lossy());
    let mut store = sda_rules::TriageStore::load(&path)?;
    store.assign(&id, to.filter(|t| !t.trim().is_empty()), context(&id, rule, location, title));
    store.save(&path)
}

/// Append a remark to a finding's discussion.
#[tauri::command]
fn comment_on_finding(
    id: String,
    by: String,
    text: String,
    rule: Option<String>,
    location: Option<String>,
    title: Option<String>,
    state: tauri::State<State>,
) -> Result<(), String> {
    if text.trim().is_empty() {
        return Err("an empty remark is not a remark".into());
    }
    let root = state.root.lock().unwrap().clone().ok_or("no project has been scanned yet")?;
    let path = triage_path(&root.to_string_lossy());
    let mut store = sda_rules::TriageStore::load(&path)?;
    store.comment(&id, &by, &text, context(&id, rule, location, title));
    store.save(&path)
}

/// Record this run's findings as the line future runs are compared against.
///
/// Only ever on request. A baseline written automatically by each scan is a
/// baseline that reports zero new findings forever, and looks like it works.
#[tauri::command]
fn set_baseline(note: Option<String>, state: tauri::State<State>) -> Result<String, String> {
    let root = state.root.lock().unwrap().clone().ok_or("no project has been scanned yet")?;
    let guard = state.report.lock().unwrap();
    let report = guard.as_ref().ok_or("no report to record")?;
    let taken_at = report.generated_at.clone();
    let baseline = sda_rules::Baseline::of(
        report.findings.iter().map(|f| f.id.to_string()),
        taken_at.clone(),
        note.filter(|n| !n.trim().is_empty()),
    );
    let n = baseline.len();
    baseline.save(&baseline_path(&root.to_string_lossy()))?;
    Ok(format!("baseline set: {n} finding(s) recorded at {taken_at}"))
}

/// What the baseline says, and what this run lost relative to it.
///
/// A malformed baseline is an error here too, for the reason the scan path gives
/// about the same file: it must not quietly become *nothing is recorded*. This
/// read swallowed it with `.ok()`, so the scan refused to run against a corrupt
/// baseline while the panel describing that baseline reported none — one file
/// saying two things about itself, a hundred and forty lines apart, with the
/// principle written down in between.
///
/// The cost is not the panel. A reader told no baseline is recorded records a
/// new one, and the set of findings somebody had already accepted is gone.
#[tauri::command]
fn baseline_info(state: tauri::State<State>) -> Result<Option<serde_json::Value>, String> {
    let Some(root) = state.root.lock().unwrap().clone() else { return Ok(None) };
    let Some(baseline) = sda_rules::Baseline::load(&baseline_path(&root.to_string_lossy()))?
    else {
        return Ok(None);
    };
    let guard = state.report.lock().unwrap();
    let seen: std::collections::BTreeSet<String> = guard
        .as_ref()
        .map(|r| r.findings.iter().map(|f| f.id.to_string()).collect())
        .unwrap_or_default();
    Ok(Some(serde_json::json!({
        "taken_at": baseline.taken_at,
        "note": baseline.note,
        "recorded": baseline.len(),
        "resolved": baseline.resolved(&seen).len(),
    })))
}

/// Triage records whose finding did not appear in the last run.
///
/// Surfaced rather than cleaned up: a stale record means the code moved under a
/// conclusion somebody reached, and "it was fixed" and "it moved and is now
/// unreviewed" are both live readings that this cannot tell apart.
#[tauri::command]
fn stale_triage(state: tauri::State<State>) -> Vec<String> {
    let Some(root) = state.root.lock().unwrap().clone() else { return Vec::new() };
    let guard = state.report.lock().unwrap();
    let Some(report) = guard.as_ref() else { return Vec::new() };
    // This returns notices, so a failure to read becomes one rather than an
    // empty list. Returning `Vec::new()` said "nothing is stale", which is a
    // claim about the review state — made by a call that could not read it.
    let store = match sda_rules::TriageStore::load(&triage_path(&root.to_string_lossy())) {
        Ok(store) => store,
        Err(e) => {
            return vec![format!(
                "the review state could not be read ({e}), so whether any recorded conclusion \
                 has gone stale is unknown rather than no"
            )];
        }
    };
    let seen: Vec<String> = report.findings.iter().map(|f| f.id.to_string()).collect();
    store
        .stale(&seen)
        .into_iter()
        .map(|r| {
            format!(
                "{} ({}) was marked `{}` and no longer appears — fixed, or moved and now unreviewed",
                r.rule.clone().unwrap_or_else(|| "a finding".into()),
                r.location.clone().unwrap_or_else(|| "location unrecorded".into()),
                r.state.as_str()
            )
        })
        .collect()
}

/// What the last run did *not* check. Surfaced in the UI as a permanent banner,
/// not a dismissible toast.
#[tauri::command]
fn not_checked(state: tauri::State<State>) -> Vec<String> {
    state
        .report
        .lock()
        .unwrap()
        .as_ref()
        .map(|r| {
            r.exclusions
                .iter()
                .map(|e| format!("{}: {}", e.provider, e.reason))
                .collect()
        })
        .unwrap_or_default()
}

/// Collapse findings into one glyph-margin marker per line.
///
/// Pure, and deliberately in Rust rather than in the webview: which finding owns
/// a shared line is an analysis judgement — a runtime-confirmed defect outranks
/// a higher raw severity — and a second shell must reach the same answer. The
/// same argument that put `css_class` here.
#[tauri::command]
fn glyph_markers(findings: Vec<UiFinding>) -> Vec<shell::LineMarker> {
    shell::line_markers(&findings)
}

#[tauri::command]
fn coverage_for(file: String, state: tauri::State<State>) -> Vec<CoverageLine> {
    let guard = state.report.lock().unwrap();
    guard.as_ref().map(|r| coverage_lines(r, &file)).unwrap_or_default()
}

/// The execution counts the correlation engine measured at findings in `file`.
///
/// The count is evidence on the *correlation*, not on the finding, and this used
/// to read the finding's evidence, where it never is: the gutter stayed empty on
/// every scan, including ones whose probe measured those very lines. The
/// correlation names its finding by id, which is how the location is found.
/// A line nothing measured has no metric and is left out rather than shown as 0.
fn coverage_lines(report: &sda_core::Report, file: &str) -> Vec<CoverageLine> {
    let mut lines: Vec<CoverageLine> = report
        .correlations
        .iter()
        .filter_map(|c| {
            let hits = c.evidence.iter().find_map(|e| match e {
                sda_core::Evidence::Metric { name, value, .. } if name == "executions" => Some(*value),
                _ => None,
            })?;
            let id = c.static_finding.as_ref()?;
            let f = report.findings.iter().find(|f| &f.id == id)?;
            f.location
                .file
                .to_string_lossy()
                .replace('\\', "/")
                .ends_with(file)
                .then_some(CoverageLine { line: f.location.line, hits: hits as u64 })
        })
        .collect();
    lines.sort_by_key(|l| l.line);
    lines.dedup_by_key(|l| l.line);
    lines
}

#[tauri::command]
fn rule_detail(rule: String) -> Option<serde_json::Value> {
    sda_rules::lookup(&rule).map(|r| {
        serde_json::json!({
            "citation": r.citation(),
            "title": r.title,
            "obligation": r.obligation.as_str(),
            "decidable": r.decidability == sda_rules::Decidability::Decidable,
            "coverage": r.coverage.as_str(),
            "clean_means_conformant": r.coverage.clean_means_conformant(),
        })
    })
}

#[tauri::command]
fn plan(path: String) -> Result<String, String> {
    let project = sda_rules::ProjectConfig::discover(std::path::Path::new(&path));
    let (target, _) = scoped_target(&path, &project);
    let ctx = sda_build::BuildContext::probe(&path);
    let inputs = sda_agent::PlanInputs {
        available: sda_engine::default_registry()
            .describe()
            .into_iter()
            .map(|p| p.id.to_string())
            .collect(),
        allow_external: false,
        has_artifact: false,
        has_compile_commands: ctx.database.is_some(),
        standards: Vec::new(),
    };
    Ok(sda_agent::plan(&target, &inputs).render())
}

// --- terminal ---------------------------------------------------------------

#[tauri::command]
fn terminal_start(cwd: String, state: tauri::State<State>) -> Result<(), String> {
    let t = pty::Terminal::spawn(&cwd)?;
    *state.terminal.lock().unwrap() = Some(t);
    Ok(())
}

#[tauri::command]
fn terminal_write(data: String, state: tauri::State<State>) -> Result<(), String> {
    state
        .terminal
        .lock()
        .unwrap()
        .as_mut()
        .ok_or("terminal is not running")?
        .write(&data)
}

#[tauri::command]
fn terminal_read(state: tauri::State<State>) -> Result<String, String> {
    state
        .terminal
        .lock()
        .unwrap()
        .as_mut()
        .ok_or("terminal is not running")?
        .read()
}

#[tauri::command]
fn terminal_resize(rows: u16, cols: u16, state: tauri::State<State>) -> Result<(), String> {
    state
        .terminal
        .lock()
        .unwrap()
        .as_mut()
        .ok_or("terminal is not running")?
        .resize(rows, cols)
}

fn main() {
    tauri::Builder::default()
        .manage(State::default())
        .invoke_handler(tauri::generate_handler![
            open_document,
            check_buffer,
            scan,
            not_checked,
            glyph_markers,
            coverage_for,
            rule_detail,
            set_triage,
            stale_triage,
            set_baseline,
            baseline_info,
            assign_finding,
            comment_on_finding,
            plan,
            terminal_start,
            terminal_write,
            terminal_read,
            terminal_resize,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the StatodynamicAnalysis workbench");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No read of a persisted store may discard its error.
    ///
    /// `Baseline::load` and `TriageStore::load` both distinguish *absent* from
    /// *malformed* — absent is `Ok(None)` or `Ok(default)`, malformed is `Err` —
    /// and `sda-rules` has a test for each saying so. The distinction only
    /// survives if every caller keeps it.
    ///
    /// Both have been lost here before, a hundred and forty lines apart in this
    /// file, with the principle written down in between. The triage read turned a
    /// corrupt store into "nobody has looked at this", which is the state that
    /// gets a finding dismissed twice. The baseline read turned a corrupt file
    /// into "no baseline is recorded" — and a reader told that records a new one,
    /// losing the set somebody had already accepted.
    ///
    /// A source-level check rather than a behavioural one because these are
    /// `#[tauri::command]`s taking `State`, and because the class is what keeps
    /// coming back rather than either instance.
    #[test]
    fn no_store_read_in_this_file_swallows_its_error() {
        let src = include_str!("main.rs");
        let offenders: Vec<(usize, &str)> = src
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let l = l.trim_start();
                !l.starts_with("//")
                    && (l.contains("Baseline::load") || l.contains("TriageStore::load"))
                    && l.contains(".ok()")
            })
            .map(|(i, l)| (i + 1, l.trim()))
            .collect();

        assert!(
            offenders.is_empty(),
            "a store read that discards its error makes a corrupt file look like an absent              one, and the two call for opposite responses:
{}",
            offenders
                .iter()
                .map(|(n, l)| format!("  line {n}: {l}"))
                .collect::<Vec<_>>()
                .join("
")
        );
    }

    /// Three lists name the commands the page may call: `generate_handler!`
    /// here, `COMMANDS` in build.rs, and the grants in `capabilities/main.json`.
    /// A command missing from the last two is refused at runtime with nothing in
    /// the build to say so, which is a broken button found by a user.
    #[test]
    fn every_registered_command_is_granted_and_nothing_else_is() {
        let between = |src: &'static str, open: &str, close: &str| -> Vec<String> {
            let start = src.find(open).expect(open) + open.len();
            let end = start + src[start..].find(close).expect(close);
            src[start..end]
                .split(',')
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        let mut handler = between(include_str!("main.rs"), "generate_handler![", "]");
        let mut manifest = between(include_str!("../build.rs"), "= &[", "];");
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/main.json")).unwrap();
        let mut granted: Vec<String> = capability["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().trim_start_matches("allow-").replace('-', "_"))
            .collect();
        handler.sort();
        manifest.sort();
        granted.sort();
        assert_eq!(handler, manifest, "build.rs COMMANDS differs from generate_handler!");
        assert_eq!(handler, granted, "capabilities/main.json differs from generate_handler!");
    }

    /// The gutter was empty on every scan: the count was read from the finding,
    /// and the correlation engine puts it on the correlation. A line nothing
    /// measured carries a note instead of a metric and must stay off the gutter.
    #[test]
    fn coverage_comes_from_the_correlation_that_measured_it() {
        use sda_core::{Correlation, CorrelationVerdict, Evidence, Finding, Location, Report, Severity};
        let at = |file: &str, line| {
            Finding::new("sda.static.c", "MISRA-C-2023-15.5", "t", Severity::Low, Location::new(file, line, 1))
        };
        let (hit, zero, unmeasured, elsewhere) =
            (at("src\\glyph.c", 3), at("src\\glyph.c", 4), at("src\\glyph.c", 9), at("src\\other.c", 3));
        let measured = |f: &Finding, n: f64| {
            Correlation::new(CorrelationVerdict::Inconclusive, "r")
                .about(f.id.clone())
                .evidence(Evidence::metric("executions", n))
        };
        let mut report = Report::new("t", vec![hit.clone(), zero.clone(), unmeasured.clone(), elsewhere.clone()]);
        report.correlations = vec![
            measured(&zero, 0.0),
            measured(&hit, 5.0),
            Correlation::new(CorrelationVerdict::Inconclusive, "r")
                .about(unmeasured.id.clone())
                .evidence(Evidence::note("unknown rather than zero")),
            measured(&elsewhere, 7.0),
        ];
        let got: Vec<(u32, u64)> =
            coverage_lines(&report, "glyph.c").iter().map(|l| (l.line, l.hits)).collect();
        assert_eq!(got, vec![(3, 5), (4, 0)]);
    }

    fn repo_root() -> PathBuf {
        // `<repo>/gui/src-tauri` -> `<repo>`
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
    }

    /// The bug this pins: the workbench used to build its registry from
    /// defaults, so a project's `.sda/` deviations were honoured by the CLI and
    /// silently ignored in the GUI. Found by clicking Scan and comparing counts.
    #[test]
    fn the_workbench_honours_a_project_deviation_register() {
        let project = repo_root().join("examples").join("firmware");
        let path = project.to_string_lossy().to_string();

        let (target, registry, config) = project_setup(&path, false);
        let report = sda_engine::run::analyze(&registry, &target, &config);

        let suppressed = report.findings.iter().filter(|f| f.is_suppressed()).count();
        assert!(
            suppressed > 0,
            "examples/firmware ships a deviation register; the workbench must \
             apply it as the CLI does, but {} of {} findings were suppressed",
            suppressed,
            report.findings.len()
        );
    }

    /// The same bug one feature later. `.sda/deviations.toml` was once honoured
    /// by the CLI and ignored by the window; `.sda/scope.toml` removes *files*
    /// rather than annotating findings, so the same divergence would be worse.
    #[test]
    fn the_workbench_honours_a_project_scope_declaration() {
        let d = std::env::temp_dir().join("sda-workbench-scope");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("tests")).unwrap();
        std::fs::create_dir_all(d.join(".sda")).unwrap();
        std::fs::write(d.join("tests").join("harness.c"), "void t(char *s){ char b[4]; strcpy(b,s); }\n").unwrap();
        std::fs::write(d.join("main.c"), "int main(void){ return 0; }\n").unwrap();
        std::fs::write(
            d.join(".sda").join("scope.toml"),
            "[[excluded]]\npath = \"tests/\"\n\
             reason = \"unit test harness\"\napprover = \"a.erickson\"\n",
        )
        .unwrap();

        let path = d.to_string_lossy().to_string();
        let (target, registry, config) = project_setup(&path, false);

        assert_eq!(target.files.len(), 1, "the excluded file must never reach an analyzer");
        let report = sda_engine::run::analyze(&registry, &target, &config);
        assert!(
            report.exclusions.iter().any(|e| e.provider.as_str() == "sda.scope"
                && e.reason.contains("1 file")),
            "the window must state what it did not check: {:?}",
            report.exclusions
        );

        std::fs::remove_dir_all(&d).ok();
    }

    /// Whatever the run excluded must be reachable by the UI, because the
    /// "not checked" banner is the one thing the user may not dismiss.
    #[test]
    fn a_scan_can_always_report_what_it_did_not_check() {
        let path = repo_root().join("examples").join("firmware").to_string_lossy().to_string();
        let (target, registry, config) = project_setup(&path, false);
        let report = sda_engine::run::analyze(&registry, &target, &config);

        for e in &report.exclusions {
            assert!(!e.reason.is_empty(), "exclusion for {} carries no reason", e.provider);
        }
    }
}
