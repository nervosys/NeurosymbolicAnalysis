//! Wiring the MCP tool surface to the actual subsystems.

use crate::plan::{PlanInputs, plan};
use sda_core::{Language, Severity, Target};
use sda_engine::{
    RunSpec, discover,
    run::{RunConfig, analyze},
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// Execute one tool call.
pub fn dispatch(name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "ontology.search" => ontology_search(args),
        "ontology.describe" => ontology_describe(args),
        "ontology.gaps" => ontology_gaps(args),
        "rules.lookup" => rules_lookup(args),
        "rules.audit" => rules_audit(args),
        "plan.create" => plan_create(args),
        "analysis.scan" => analysis_scan(args),
        "analysis.statodynamic" => analysis_statodynamic(args),
        "analysis.verify" => analysis_verify(args),
        "analysis.triage" => analysis_triage(args),
        "analysis.baseline" => analysis_baseline(args),
        "analysis.impact" => analysis_impact(args),
        "analysis.hotspots" => analysis_hotspots(args),
        "ai.scan_model" => ai_scan_model(args),
        "ai.probe_suite" => ai_probe_suite(args),
        "ai.evaluate_probes" => ai_evaluate_probes(args),
        "build.detect" => build_detect(args),
        "build.compile" => build_compile(args),
        "swe.iterate" => swe_iterate(args),
        "fuzz.campaign" => fuzz_campaign(args),
        "report.query" => report_query(args),
        other => Err(format!(
            "unknown tool `{other}`. Call `tools/list` for the published surface."
        )),
    }
}

fn str_arg(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing required argument `{key}`"))
}

fn bool_arg(args: &Value, key: &str) -> bool {
    args.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn severity_arg(args: &Value, key: &str) -> Option<Severity> {
    match args.get(key).and_then(|v| v.as_str())? {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

// --- ontology --------------------------------------------------------------

fn ontology_search(args: &Value) -> Result<Value, String> {
    let query = str_arg(args, "query")?;
    let o = sda_ontology::Ontology::load();
    let hits = o.search(&query);
    if hits.is_empty() {
        return Ok(json!(format!(
            "No tool matched `{query}`. Try a capability name such as `memory-safety`, \
             `fuzzing`, `taint-analysis`, or `model-artifact-scan`."
        )));
    }
    Ok(json!(hits.iter().map(|t| t.brief()).collect::<Vec<_>>().join("\n\n")))
}

fn ontology_describe(args: &Value) -> Result<Value, String> {
    let id = str_arg(args, "id")?;
    sda_ontology::Ontology::load()
        .describe(&id)
        .map(Value::String)
        .ok_or_else(|| format!("no tool with id `{id}`; call `ontology.search` to find one"))
}

fn ontology_gaps(args: &Value) -> Result<Value, String> {
    let lang = parse_language(&str_arg(args, "language")?)?;
    let o = sda_ontology::Ontology::load();
    let available: BTreeSet<String> = args
        .get("available")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        // Default to every native tool, which always ships with the toolkit.
        // A hand-written list here drifts: it previously omitted the fuzzer and
        // the dynamic engine, so gap analysis recommended installing AFL++ for
        // something already in the box.
        .unwrap_or_else(|| o.native_ids());
    let gaps = o.gaps(&lang, &available);
    if gaps.is_empty() {
        return Ok(json!("Every catalogued capability is covered by an available tool."));
    }
    let lines: Vec<String> = gaps
        .iter()
        .map(|c| {
            let candidates: Vec<&str> =
                o.recommend(*c, &lang).into_iter().take(3).map(|t| t.id.as_str()).collect();
            format!("{}: not covered. Candidates: {}", c.as_str(), candidates.join(", "))
        })
        .collect();
    Ok(json!(lines.join("\n")))
}

fn parse_language(s: &str) -> Result<Language, String> {
    match s {
        "c" => Ok(Language::C),
        "cpp" | "c++" => Ok(Language::Cpp),
        "rust" => Ok(Language::Rust),
        "model-artifact" | "model" => Ok(Language::ModelArtifact),
        other => Err(format!("unsupported language `{other}`")),
    }
}

// --- rules -----------------------------------------------------------------

fn rules_lookup(args: &Value) -> Result<Value, String> {
    let query = str_arg(args, "query")?;
    let standards = match args.get("standard").and_then(|v| v.as_str()) {
        Some(s) => vec![sda_rules::Standard::parse(s).ok_or(format!("unknown standard `{s}`"))?],
        None => sda_rules::Standard::all().to_vec(),
    };

    let mut lines = Vec::new();
    for st in standards {
        let catalog = sda_rules::Catalog::load(st);
        for r in catalog.find(&query).into_iter().take(25) {
            lines.push(format!(
                "{} [{}] {} — {}\n    checked: {} ({}); {}",
                r.citation(),
                r.obligation.as_str(),
                if r.decidability == sda_rules::Decidability::Decidable {
                    "decidable"
                } else {
                    "UNDECIDABLE — no analyzer can settle this in general"
                },
                r.title,
                r.coverage.as_str(),
                if r.coverage.checked_by_default() { "runs by default" } else { "not run by default" },
                if r.coverage.clean_means_conformant() {
                    "a clean result is evidence of conformance"
                } else {
                    "a clean result does NOT establish conformance"
                },
            ));
        }
    }
    if lines.is_empty() {
        return Ok(json!(format!("No guideline matched `{query}`.")));
    }
    Ok(json!(lines.join("\n\n")))
}

fn rules_audit(args: &Value) -> Result<Value, String> {
    let s = str_arg(args, "standard")?;
    let standard = sda_rules::Standard::parse(&s).ok_or(format!("unknown standard `{s}`"))?;
    let audit = sda_rules::Catalog::load(standard).audit();
    Ok(json!({
        "standard": standard.title(),
        "caveat": audit.caveat(),
        "total": audit.total,
        "checked_by_default": audit.checked_by_default,
        "conformance_provable": audit.conformance_provable,
        "undecidable": audit.undecidable,
        "catalog_complete": audit.catalog_complete,
        "unconfirmed_numbers": audit.unconfirmed_numbers,
        "by_coverage": audit.by_coverage,
    }))
}

// --- planning and analysis -------------------------------------------------

/// Discover a target with the project's declared analysis scope applied.
///
/// Returns the notices as well as the target, and every caller must carry them
/// into its report. Making this the only way to get a target is deliberate: the
/// MCP surface is the third place that could honour `.sda/scope.toml` on the
/// command line and ignore it here, and an agent reading a silently narrowed
/// result has no way to notice.
fn target_for(path: &str) -> (Target, Vec<sda_core::Exclusion>) {
    let (target, notices, _) = discover_project(path);
    (target, notices)
}

/// The target, its scope notices, and the project configuration that produced
/// them — discovered once.
fn discover_project(path: &str) -> (Target, Vec<sda_core::Exclusion>, sda_rules::ProjectConfig) {
    let mut target = discover::discover(path, &discover::DiscoveryOptions::default());
    let project = sda_rules::ProjectConfig::discover(std::path::Path::new(path));
    // See `ProjectConfig::root`: rules are relative to the declaration, not to
    // the path the agent asked about.
    let notices = match (&project.scope, project.root()) {
        (Some(scope), Some(anchor)) => discover::apply_scope(&mut target, scope, anchor),
        _ => Vec::new(),
    };
    (target, notices, project)
}

/// Everything a run over a project needs, built the same way for every tool that
/// analyses one.
///
/// `analysis.statodynamic` used to build a bare `default_registry()` and no
/// project configuration at all: no imported catalogues, no deviations, no
/// architecture. An agent driving a statodynamic run therefore saw different
/// citations and different suppressions from a human running `sda scan` over the
/// same project — the one thing this surface exists not to do, and invisible
/// from either report alone because each is internally consistent.
///
/// Shared rather than repeated, because the two call sites drifted precisely
/// while nobody was comparing them.
fn project_setup(path: &str) -> (Target, sda_core::Registry, RunConfig) {
    let (target, notices, mut project) = discover_project(path);

    let mut registry = sda_engine::registry_for_project(&project);
    // Registered, not enabled: the selection policy still leaves them out, and
    // the report can only name a provider it was handed. See `run::analyze`.
    sda_adapters::register_all(&mut registry);
    registry.register(std::sync::Arc::new(sda_ai::ModelScanner::new()));

    let mut config = RunConfig::default().with_notices(notices);
    if let Some(register) = project.deviations.take() {
        config = config.with_deviations(register);
    }
    if let Some(decl) = project.architecture.take() {
        config = config.with_architecture(decl);
    }
    (target, registry, config)
}

fn plan_create(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    // A plan over files the scan will not read would propose work on nothing.
    let (target, scope_notices) = target_for(&path);
    let ctx = sda_build::BuildContext::probe(&path);

    let mut available: BTreeSet<String> = sda_ontology::Ontology::load().native_ids();
    for (id, availability) in sda_adapters::availability_report() {
        if availability.is_usable() {
            available.insert(id);
        }
    }

    let inputs = PlanInputs {
        available,
        allow_external: bool_arg(args, "allow_external"),
        has_artifact: args.get("artifact").and_then(|v| v.as_str()).is_some_and(|p| PathBuf::from(p).exists()),
        has_compile_commands: ctx.database.is_some(),
        standards: target
            .languages()
            .iter()
            .flat_map(sda_rules::Standard::for_language)
            .collect(),
    };
    Ok(json!(plan(&target, &inputs).noting_scope(&scope_notices).render()))
}

fn analysis_scan(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    // The project's catalogues, deviations, scope and architecture, so an agent
    // sees the same citations and suppressions a human running `sda scan` would.
    let (target, registry, mut config) = project_setup(&path);
    if bool_arg(args, "allow_external") {
        config = config.with_external();
    }

    let report = analyze(&registry, &target, &config);
    Ok(report_json(&report, severity_arg(args, "severity_at_least")))
}

fn analysis_statodynamic(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let artifact = str_arg(args, "artifact")?;
    // Same setup as `analysis.scan`, and for the same reason: a statodynamic run
    // is a scan with runtime evidence added, not a different analysis.
    let (target, registry, config) = project_setup(&path);

    let run_args: Vec<String> = args
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let mut spec = RunSpec::new(&artifact).id("mcp-run-0");
    spec.args = run_args;

    let engine = sda_engine::DynamicEngine::new(vec![spec]);
    let observation = engine.observe().map_err(|e| e.to_string())?;
    let config = config.with_observation(observation);

    let report = analyze(&registry, &target, &config);
    let mut out = report_json(&report, None);
    out["correlation_summary"] = json!(sda_engine::correlate::summarize(
        &sda_engine::CorrelationResult {
            findings: report.findings.clone(),
            correlations: report.correlations.clone(),
        }
    ));
    Ok(out)
}

/// What is new since the line was last drawn, or draw it.
///
/// The counterpart to `analysis.triage` for the other half of a review workflow:
/// triage says what someone concluded, the baseline says what they had already
/// seen. Both are files in the project, so an agent and a human share them.
fn analysis_baseline(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let file = std::path::Path::new(&path)
        .join(sda_rules::CONFIG_DIR)
        .join("baseline.toml");

    let (target, registry, config) = project_setup(&path);
    let report = analyze(&registry, &target, &config);
    let seen: std::collections::BTreeSet<String> =
        report.findings.iter().map(|f| f.id.to_string()).collect();

    // Everything else in this file reports and lets the caller decide. This one
    // branch writes to disk, and what it would write is the thing that makes
    // refusing right.
    //
    // A baseline records "these findings are the accepted state". Record one
    // from a scan that read nothing — a mistyped path, a tree of languages
    // nothing here handles — and the accepted state becomes *the empty set*,
    // saved into `.sda/baseline.toml`, where every later run compares against it
    // and reports nothing new. The false clean result stops being this run's
    // answer and becomes the project's, until somebody notices, which is the one
    // failure in this codebase that does not expire.
    //
    // Narrow on purpose: it refuses only when `sda.discovery` fired, meaning
    // nothing was read at all. A genuinely clean C project still records an
    // empty baseline, which is a real and useful thing to do.
    let read_nothing =
        report.exclusions.iter().find(|e| e.provider.as_str() == "sda.discovery");

    if args.get("set").and_then(|v| v.as_bool()).unwrap_or(false) {
        if let Some(e) = read_nothing {
            return Err(format!(
                "refusing to record a baseline from a scan that read nothing: {}. A baseline \
                 written from this run would record the empty set as the accepted state, and \
                 every later comparison would report nothing new against it",
                e.reason
            ));
        }
        let b = sda_rules::Baseline::of(
            seen.iter().cloned(),
            report.generated_at.clone(),
            args.get("note").and_then(|v| v.as_str()).map(String::from),
        );
        b.save(&file)?;
    }

    // A malformed baseline is an error rather than an absent one, so a broken
    // file cannot quietly become "nothing is new".
    let baseline = sda_rules::Baseline::load(&file)?;

    let new_ids: Vec<&sda_core::Finding> = match &baseline {
        Some(b) => report.findings.iter().filter(|f| b.is_new(f.id.as_str())).collect(),
        None => Vec::new(),
    };

    Ok(json!({
        "path": path,
        "has_baseline": baseline.is_some(),
        "taken_at": baseline.as_ref().map(|b| b.taken_at.clone()),
        "note": baseline.as_ref().and_then(|b| b.note.clone()),
        "recorded": baseline.as_ref().map(|b| b.len()),
        "findings_in_scan": report.findings.len(),
        // And when only *reading* the baseline, the same fact still governs
        // every number above: `findings_in_scan: 0` against a recorded baseline
        // makes every recorded finding look resolved.
        "not_checked": read_nothing.map(|e| vec![e.reason.clone()]).unwrap_or_default(),
        // `null`, not `0`, when nothing was recorded: unknown is not zero.
        "new": baseline.as_ref().map(|_| new_ids.len()),
        "new_findings": new_ids.iter().take(200).map(|f| json!({
            "id": f.id.to_string(),
            "rule": f.rule.to_string(),
            "severity": f.severity.as_str(),
            "location": f.location.display(),
            "title": f.title,
        })).collect::<Vec<_>>(),
        "resolved": baseline.as_ref().map(|b| b.resolved(&seen).len()),
        "limits": match baseline {
            Some(_) => "`new` means absent from the recorded set: not a claim about a commit or an author. A finding can be new because a rule was added or a provider was enabled. `resolved` cannot tell fixed from moved from filtered out by a scope change.",
            None => "no baseline is recorded, so nothing here is a comparison. `new` is null rather than zero: the question has not been asked, which is not the same as answered.",
        },
    }))
}

/// Read or record review state, over the same file the workbench uses.
///
/// The hybrid part of hybrid agent-human review: an agent working a backlog and a
/// person scrolling the workbench write one `.sda/triage.toml`, so neither can
/// diverge from the other without it showing up in a diff. Nothing here
/// suppresses anything — see the tool description.
fn analysis_triage(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let file = std::path::Path::new(&path)
        .join(sda_rules::CONFIG_DIR)
        .join("triage.toml");
    let mut store = sda_rules::TriageStore::load(&file)?;

    // A write, when an id is given.
    if let Some(id) = args.get("id").and_then(|v| v.as_str()) {
        let assign = args.get("assign").and_then(|v| v.as_str());
        let remark = args.get("comment").and_then(|v| v.as_str());
        let state_arg = args.get("state").and_then(|v| v.as_str());
        if state_arg.is_none() && assign.is_none() && remark.is_none() {
            return Err(
                "recording against an `id` needs one of `state`, `assign` or `comment`".into()
            );
        }

        // The finding's rule and location are copied in so the file reads without
        // the tool. They are looked up from a fresh scan rather than taken on
        // trust: an agent that mistyped an id would otherwise write a plausible
        // record about a finding that does not exist.
        let (target, registry, config) = project_setup(&path);
        let report = analyze(&registry, &target, &config);
        let found = report.findings.iter().find(|f| f.id.as_str() == id);
        if found.is_none() {
            return Err(format!(
                "no finding with id `{id}` in the current scan of `{path}`. Recording against a finding that is not there would be a record nobody can check"
            ));
        }
        let ctx = sda_rules::TriageRecord {
            id: id.to_string(),
            state: sda_rules::TriageState::Open,
            note: None,
            by: None,
            rule: found.map(|f| f.rule.to_string()),
            location: found.map(|f| f.location.display()),
            title: found.map(|f| f.title.clone()),
            assignee: None,
            comments: Vec::new(),
        };

        // Handing work to someone and remarking on it conclude nothing, so they
        // are applied first and never imply a verdict.
        if let Some(to) = assign {
            let to = (!to.trim().is_empty()).then(|| to.to_string());
            store.assign(id, to, ctx.clone());
        }
        if let Some(text) = remark {
            let by = args.get("by").and_then(|v| v.as_str()).unwrap_or("agent");
            store.comment(id, by, text, ctx.clone());
        }

        if let Some(state_name) = state_arg {
            let state = sda_rules::TriageState::parse(state_name)
                .ok_or_else(|| format!("`{state_name}` is not a triage state"))?;
            let mut r = ctx.clone();
            r.state = state;
            r.note = args.get("note").and_then(|v| v.as_str()).map(String::from);
            r.by = args.get("by").and_then(|v| v.as_str()).map(String::from);
            store.set(r);
        }
        store.save(&file)?;
    }

    // Stale records need the current scan to be known. When this call was a pure
    // read, run one: a listing that silently omitted them would be the quiet
    // cleanup this deliberately refuses.
    let (target, registry, config) = project_setup(&path);
    let report = analyze(&registry, &target, &config);
    let seen: Vec<String> = report.findings.iter().map(|f| f.id.to_string()).collect();

    Ok(json!({
        "path": path,
        "records": store.records().iter().map(|r| json!({
            "id": r.id,
            "state": r.state.as_str(),
            "note": r.note,
            "by": r.by,
            "rule": r.rule,
            "location": r.location,
            "title": r.title,
            "assignee": r.assignee,
            "comments": r.comments.iter().map(|c| json!({
                "by": c.by, "at": c.at, "text": c.text,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "by_assignee": store.by_assignee(),
        "by_state": store.by_state(),
        "reviewed": store.len(),
        "findings_in_scan": seen.len(),
        // Not a count of what is left to do: `open` is the absence of a record,
        // so this is derived rather than stored.
        "unreviewed": seen.iter().filter(|id| !store.state_of(id).is_reviewed()).count(),
        "stale": store.stale(&seen).iter().map(|r| json!({
            "id": r.id,
            "state": r.state.as_str(),
            "rule": r.rule,
            "location": r.location,
            "why_it_matters": "the finding is gone: either it was fixed, or it moved and is now unreviewed. Nothing here can tell those apart, so the record is reported rather than deleted",
        })).collect::<Vec<_>>(),
        "not_a_suppression": "triage annotates and never hides. A finding recorded here still appears in every report and still counts toward every gate. Suppression is a deviation, and it needs an approver.",
    }))
}

/// Prove interposition over a declared architecture, and let evidence refute it.
///
/// The three things this returns that an agent must not conflate: what was
/// *proved* over the declaration, what a tool *observed* in the code, and what
/// nobody checked. They are separate keys for that reason, and `not_checked` is
/// present even on a clean run.
fn analysis_verify(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let project = sda_rules::ProjectConfig::discover(std::path::Path::new(&path));

    let Some(decl) = &project.architecture else {
        // Not an error, and not a pass. An agent that read a bare `ok` here
        // would report a safety property nobody claimed.
        return Ok(json!({
            "declared": false,
            "interposed": null,
            "summary": "no `.sda/architecture.toml`, so interposition was not checked. Nothing \
                        was claimed and nothing was proved; this is not a clean result.",
            "problems": project.problems,
            "not_checked": ["sda.no-architecture: the project declares no components or dataflow"],
        }));
    };

    let system = sda_engine::from_declaration(decl);

    let taint = match args.get("taint").and_then(|v| v.as_str()) {
        Some(p) => {
            let text = std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?;
            match serde_json::from_str::<sda_core::Report>(&text) {
                Ok(r) => r.findings,
                Err(_) => sda_adapters::parse_sarif(&text, "ext.taint")?,
            }
        }
        None => Vec::new(),
    };
    let with_flow = taint
        .iter()
        .filter(|f| {
            f.evidence
                .iter()
                .any(|e| matches!(e, sda_core::Evidence::Trace { frames } if frames.len() >= 2))
        })
        .count();

    let result = sda_engine::interposition::verify(&system.map, &system.flow, &taint);
    let mut not_checked = result.not_checked.clone();
    not_checked.extend(system.problems.iter().cloned());

    let mut ledger = result.merge_into(Default::default());
    let mut prover = Value::Null;
    if let Some(p) = args.get("proofs").and_then(|v| v.as_str()) {
        let json_text = std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?;
        let diagnostics = match args.get("proof_log").and_then(|v| v.as_str()) {
            Some(l) => std::fs::read_to_string(l).map_err(|e| format!("{l}: {e}"))?,
            None => String::new(),
        };
        let run = sda_adapters::parse_verus(&json_text, &diagnostics)?;
        prover = json!({
            "tool": "verus",
            "version": run.version,
            "verified": run.verified,
            "errors": run.errors,
            "located": run.failures.len(),
            // Said here because it cannot be inferred from anything else in this
            // response, and an agent gating on a process exit code would be
            // gating on nothing.
            "exit_code_is_meaningless": true,
            "failures": run
                .failures
                .iter()
                .map(|f| json!({
                    "statement": f.statement,
                    "location": f.location.as_ref().map(|l| l.display()),
                }))
                .collect::<Vec<_>>(),
        });
        for problem in &run.problems {
            not_checked.push(format!("sda.prover: {problem}"));
        }
        ledger.obligations.extend(run.obligations());
    }

    let adjudication = sda_engine::adjudicate(&[], &ledger, &system.map);
    not_checked.extend(adjudication.not_checked);

    Ok(json!({
        "declared": true,
        "interposed": result.is_interposed(),
        "summary": sda_engine::interposition::summarize(&result),
        "obligations": result.obligations.len(),
        "bypasses": result
            .bypasses
            .iter()
            .map(|b| json!({
                "model": b.model,
                "effector": b.effector,
                "path": b.path,
                "observed": b.witness.is_some(),
                "description": b.describe(),
            }))
            .collect::<Vec<_>>(),
        "taint_findings": taint.len(),
        "taint_findings_with_flow": with_flow,
        "prover": prover,
        "problems": project.problems,
        "not_checked": not_checked,
    }))
}

fn report_json(report: &sda_core::Report, threshold: Option<Severity>) -> Value {
    let findings: Vec<Value> = report
        .findings
        .iter()
        .filter(|f| threshold.map(|t| f.severity >= t).unwrap_or(true))
        .take(200)
        .map(|f| {
            json!({
                "rule": f.rule.to_string(),
                "severity": f.severity.as_str(),
                "confidence": f.confidence.as_str(),
                "phase": f.phase.as_str(),
                "location": f.location.display(),
                "message": f.message,
                "suppressed_by": f.suppressed_by,
            })
        })
        .collect();

    json!({
        "target": report.target,
        "total": report.summary.total,
        "shown": findings.len(),
        "by_severity": report.summary.by_severity,
        "by_verdict": report.summary.by_verdict,
        // Always present: what this run did not check.
        "not_checked": report.exclusions.iter().map(|e| json!({
            "provider": e.provider.to_string(),
            "reason": e.reason,
        })).collect::<Vec<_>>(),
        "findings": findings,
    })
}

// --- AI --------------------------------------------------------------------

fn ai_scan_model(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let p = PathBuf::from(&path);
    let scanner = sda_ai::ModelScanner::new();

    let mut notices = Vec::new();
    let reports = if p.is_dir() {
        let (target, n) = target_for(&path);
        notices = n;
        target
            .files_in(&[Language::ModelArtifact])
            .into_iter()
            .filter_map(|f| scanner.scan_file(&f.path).ok())
            .collect::<Vec<_>>()
    } else {
        vec![scanner.scan_file(&p).map_err(|e| e.to_string())?]
    };

    let not_checked: Vec<String> = notices.iter().map(|e| e.reason.clone()).collect();

    if reports.is_empty() {
        // "None found" and "some were excluded from scope" are different
        // statements, and a model artifact declared out of scope is precisely
        // the one an agent must not be told does not exist.
        if !not_checked.is_empty() {
            return Ok(json!({
                "artifacts": [],
                "not_checked": not_checked,
                "caveat": format!(
                    "No model artifacts were scanned at {path}, but the declared analysis \
                     scope excluded files; this is not the same as finding none."
                ),
            }));
        }
        return Ok(json!(format!("No model artifacts were found at {path}.")));
    }

    let out: Vec<Value> = reports
        .iter()
        .map(|r| {
            json!({
                "path": r.path,
                "format": r.format.as_str(),
                "executes_on_load": r.format.executes_on_load(),
                "size": r.size,
                "sha256": r.digest,
                "findings": r.findings.iter().map(|f| json!({
                    "rule": f.rule.to_string(),
                    "severity": f.severity.as_str(),
                    "message": f.message,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    Ok(json!({
        "artifacts": out,
        "not_checked": not_checked,
        "caveat": "Container analysis only. No inspection of a model file can reveal a backdoor \
                   in the weights; that requires a behavioural probe campaign, and even then \
                   absence of a hit is not evidence of absence.",
    }))
}

fn ai_probe_suite(args: &Value) -> Result<Value, String> {
    let mut suite = sda_ai::default_suite();
    if let Some(triggers) = args.get("triggers").and_then(|v| v.as_array()) {
        let t: Vec<String> = triggers.iter().filter_map(|v| v.as_str().map(String::from)).collect();
        suite.extend(sda_ai::suite_for_triggers(&t));
    }
    Ok(json!({
        "probes": suite,
        "instructions": "Send each probe's `prompt` to the model under test. Where the criterion \
                         is `divergence`, also send the `baseline` prompt and return both \
                         responses. Then call `ai.evaluate_probes`.",
    }))
}

fn ai_evaluate_probes(args: &Value) -> Result<Value, String> {
    let responses: Vec<sda_ai::ProbeResponse> = serde_json::from_value(
        args.get("responses").cloned().ok_or("missing required argument `responses`")?,
    )
    .map_err(|e| format!("`responses` is malformed: {e}"))?;

    let model_path = args
        .get("model_path")
        .and_then(|v| v.as_str())
        .unwrap_or("model under test");

    let suite = sda_ai::default_suite();
    let report = sda_ai::probe::evaluate_all(&suite, &responses);
    let findings = sda_ai::probe::findings_from(&report, model_path);

    Ok(json!({
        "caveat": report.caveat(),
        "fired": report.fired().count(),
        // Separate from `fired: 0`: an agent deciding whether a risk was tested
        // needs to know a probe was submitted but could not be evaluated.
        "measured": report.measured(),
        "inconclusive": report.inconclusive().map(|o| json!({
            "probe_id": o.probe_id,
            "why": o.verdict,
        })).collect::<Vec<_>>(),
        "unknown_probe_ids": report.unknown,
        "not_run": report.not_run,
        "findings": findings.iter().map(|f| json!({
            "rule": f.rule.to_string(),
            "severity": f.severity.as_str(),
            "message": f.message,
        })).collect::<Vec<_>>(),
    }))
}

// --- build and SWE ---------------------------------------------------------

fn build_detect(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let ctx = sda_build::BuildContext::probe(&path);
    Ok(json!({
        "summary": ctx.summary(),
        "supports_semantic_analysis": ctx.supports_semantic_analysis(),
        "build_systems": ctx.builds.iter().map(|b| json!({
            "system": b.system.as_str(),
            "next_step": b.next_step(),
        })).collect::<Vec<_>>(),
        "compilers": ctx.compilers.iter().map(|c| json!({
            "path": c.path.to_string_lossy(),
            "family": c.family.as_str(),
            "version": c.version,
        })).collect::<Vec<_>>(),
    }))
}

fn build_compile(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let ctx = sda_build::BuildContext::probe(&path);
    let detected = ctx.primary().ok_or("no build system was recognised")?;

    let profile = match args.get("profile").and_then(|v| v.as_str()) {
        Some("dynamic") => Some(sda_build::BuildProfile::for_dynamic_analysis()),
        Some("static") => Some(sda_build::BuildProfile::for_static_analysis()),
        _ => None,
    };

    let outcome = sda_build::build(
        detected,
        ctx.compilers.first(),
        profile.as_ref(),
        std::time::Duration::from_secs(900),
    )?;

    Ok(json!({
        "summary": outcome.summary(),
        "success": outcome.success,
        "errors": outcome.errors().count(),
        "diagnostics": outcome.diagnostics.iter().take(50).collect::<Vec<_>>(),
        // The load-bearing field: instrumentation that was asked for and refused.
        "instrumentation_not_applied": outcome.unsupported,
    }))
}

fn swe_iterate(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let root = PathBuf::from(&path);
    let context_lines = args.get("max_context_lines").and_then(|v| v.as_u64()).unwrap_or(4) as u32;

    if args.get("reset").and_then(|v| v.as_bool()).unwrap_or(false) {
        crate::swe::Session::reset(&root)?;
        return Ok(json!({ "reset": true, "instructions": "Session cleared. Call again to start." }));
    }

    // Resume, never start fresh. Each tool call is a separate process, and the
    // stall and thrash detectors compare against earlier iterations — a session
    // that reset every call could never fire either of them, and an agent would
    // iterate forever without being told it was going in circles.
    let mut session = crate::swe::Session::resume(&root);
    let resumed = session.len();

    let iteration =
        crate::swe::iterate(&root, &mut session, context_lines, std::time::Duration::from_secs(900))?;
    let stop = session.should_stop(u32::MAX);
    session.save(&root)?;

    Ok(json!({
        "iteration": iteration,
        "resumed_after": resumed,
        "stop": stop.map(|s| json!({
            "reason": s,
            "explanation": s.explain(),
            "succeeded": s.succeeded(),
        })),
        "instructions": "Apply a patch addressing `iteration.next`, then call `swe.iterate` again. \
                         Do not report success until this tool returns stop.reason == \"clean\". \
                         If it returns \"stalled\" or \"thrashing\", stop patching and reconsider: \
                         those mean your changes are not addressing the problem.",
    }))
}

fn fuzz_campaign(args: &Value) -> Result<Value, String> {
    let artifact = str_arg(args, "artifact")?;
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".").to_string();
    let artifact_path = PathBuf::from(&artifact);
    if !artifact_path.exists() {
        return Err(format!(
            "artifact `{artifact}` does not exist. Build it first — `build.compile` with \
             profile `dynamic` — and make sure it links the SDA probe instrumentation, or the \
             campaign will have no coverage feedback."
        ));
    }

    let runs = args.get("runs").and_then(|v| v.as_u64()).unwrap_or(1000);
    let seed = args.get("seed").and_then(|v| v.as_u64()).unwrap_or(0x5DA_5EED);
    let budget = args.get("budget_secs").and_then(|v| v.as_u64()).unwrap_or(60);

    let seeds = args
        .get("corpus")
        .and_then(|v| v.as_str())
        .map(|d| sda_engine::fuzz::load_corpus(std::path::Path::new(d)))
        .unwrap_or_default();

    let config = sda_engine::FuzzConfig {
        runs,
        seed,
        timeout: std::time::Duration::from_secs(2),
        max_duration: std::time::Duration::from_secs(budget),
        crash_dir: Some(PathBuf::from(&path).join(".sda").join("crashes")),
        max_input: 256,
        stop_on_crash: args.get("stop_on_crash").and_then(|v| v.as_bool()).unwrap_or(false),
    };

    let (report, observation) =
        sda_engine::fuzz_campaign(&artifact_path, &[], seeds, &config).map_err(|e| e.to_string())?;

    // The payoff: what the campaign reached is now evidence, so static findings
    // on those lines stop being `unreached`.
    // `project_setup`, not a hand-built config: this correlated a campaign's
    // coverage against findings the project had already deviated. `correlate`
    // refuses to re-raise a suppressed finding -- *correlating it would only
    // re-raise something the process already settled* -- and a config built
    // from `default()` never loads the register, so nothing was suppressed and
    // the refusal never fired. Measured in
    // `a_deviated_finding_is_not_re_raised_by_correlation`.
    let (target, registry, base) = project_setup(&path);
    let run_config = base.with_observation(observation);
    let correlated = analyze(&registry, &target, &run_config);

    Ok(json!({
        "summary": report.summary(),
        "runs": report.runs,
        "locations_reached": report.coverage.len(),
        "had_coverage_feedback": report.had_feedback(),
        "crashes": sda_engine::fuzz::findings_from(&report, &artifact).iter().map(|f| json!({
            "rule": f.rule.to_string(),
            "severity": f.severity.as_str(),
            "location": f.location.display(),
            "message": f.message,
            "reproduce": f.remediation,
        })).collect::<Vec<_>>(),
        "correlation": correlated.summary.by_verdict,
        // The correlation is over the source tree, which is a different
        // argument from the artifact and can be wrong by itself: a campaign
        // against a real binary with `path` pointing at nothing publishes an
        // empty verdict map, which reads as a run that correlated cleanly.
        "correlation_not_checked": correlated.exclusions.iter()
            .filter(|e| e.provider.as_str() == "sda.discovery")
            .map(|e| e.reason.clone())
            .collect::<Vec<_>>(),
        "caveat": if report.had_feedback() {
            "No crash found does not mean none exists: it means this campaign, with this corpus \
             and this budget, did not reach one."
        } else {
            "This campaign had NO coverage feedback — the target emitted no probe records, so \
             inputs were generated blindly. Link `sda-probe` or `shim/sda_probe.h` and rebuild \
             before reading the result as coverage of anything."
        },
    }))
}

/// What else names the symbols a file defines.
///
/// The caveat is a field of the response, not a line in the tool description.
/// An agent reads the payload and acts on it; a description is read once, by
/// whatever assembled the tool list, possibly weeks earlier. The test beside
/// `the_mcp_surface_reports_what_the_declared_scope_removed` makes the same
/// argument about a narrowed scan, and this is the same asymmetry: the caller
/// cannot see a terminal.
fn analysis_impact(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let file = str_arg(args, "file")?;

    let root = std::path::PathBuf::from(&path);
    let subject = root.join(&file);
    if !subject.exists() {
        return Err(format!("`{file}` does not exist under `{path}`"));
    }

    let target = sda_engine::discover::discover(
        &root,
        &sda_engine::discover::DiscoveryOptions::default(),
    );
    let files: Vec<std::path::PathBuf> = target
        .files_in(&[sda_core::Language::C])
        .iter()
        .map(|f| f.path.clone())
        .collect();

    let base = target.root.clone();
    let relative = move |p: &std::path::Path| {
        p.strip_prefix(&base).unwrap_or(p).to_string_lossy().replace('\\', "/")
    };
    let found = sda_engine::impact::of_file(&subject, &files, &relative);

    let mut not_checked = Vec::new();

    // This tool ignores the declared analysis scope on purpose — the opposite
    // choice from `analysis.hotspots`, which must not rank files the project
    // excluded. A caller in a vendored directory still reaches this code, and
    // leaving it out would push the floor *below* the truth, the one direction
    // this answer must never move. Said out loud, because an agent that also
    // calls `analysis.scan` will otherwise see a file here that the scan never
    // mentions and have no way to reconcile the two.
    if sda_rules::ProjectConfig::discover(std::path::Path::new(&path)).scope.is_some() {
        not_checked.push(
            "This project declares an analysis scope and this search ignored it. \
             `referenced_by` may name files `analysis.scan` will not report on, because a \
             caller in an excluded directory still reaches this code and omitting it would \
             make the floor lower than the truth."
                .to_string(),
        );
    }

    // First, because it says whether there is a list at all. An agent reading
    // `referenced_by: {}` has no way to tell "nothing names these symbols" from
    // "nothing was searched" without it.
    if let Some(n) = found.nothing_searched_notice() {
        not_checked.push(n.reason);
    }
    not_checked.push(found.floor_caveat().reason);
    if let Some(n) = found.unreadable_notice() {
        not_checked.push(n.reason);
    }

    Ok(json!({
        "file": file,
        "defines": found.symbols,
        "referenced_by": found.referenced_by,
        // Named `floor` rather than `caveat` so a caller that reads keys before
        // prose still meets the word that matters.
        "floor": true,
        "files_searched": found.searched,
        "not_checked": not_checked,
        "limits": "`referenced_by` is a floor. A call through a function pointer, a name the preprocessor assembles, a linker alias or a `dlsym` lookup reaches this code without spelling its name and is not here. Read it as `at least these`, never as `only these`.",
    }))
}

/// Files carrying findings, ranked by how often they change.
///
/// `history_available` is published beside the rows, and the counts are `null`
/// rather than `0` when it is false. A zero is a measurement; a null is the
/// absence of one, and the difference is the whole reason this tool can be
/// trusted on a CI checkout — which is shallow, where `git log` succeeds and
/// reports one commit naming every file in the tree.
fn analysis_hotspots(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "path")?;
    let days = args.get("days").and_then(Value::as_u64).unwrap_or(180) as u32;
    let top = args.get("top").and_then(Value::as_u64).unwrap_or(20) as usize;

    let root = std::path::PathBuf::from(&path);

    // `project_setup`, which is the whole of the project's declared position:
    // scope, the deviation register, the architecture. This assembled its own
    // and got none of them, so it analyzed and ranked files the project had
    // excluded, and counted findings the project had formally deviated.
    //
    // Calling the shared helper rather than repeating its steps is the actual
    // fix, twice over now. The defect was a second copy of the setup that had
    // learned neither thing.
    let (target, registry, config) = project_setup(&path);
    let report = sda_engine::run::analyze(&registry, &target, &config);

    // Suppressed findings are kept in the report, marked, because a compliance
    // record must show what was deviated. They must not rank: a deviation is a
    // recorded claim that a finding is accepted, and ranking on it points an
    // agent first at the code most recently agreed to be fine. See the CLI twin.
    let mut per_file: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut suppressed = 0usize;
    for f in &report.findings {
        if f.is_suppressed() {
            suppressed += 1;
            continue;
        }
        *per_file.entry(f.location.file.to_string_lossy().replace('\\', "/")).or_default() += 1;
    }

    let history = sda_engine::history::read(&root, days);
    let known = matches!(history, sda_engine::history::History::Read { .. });

    let mut rows: Vec<Value> = per_file
        .iter()
        .map(|(file, findings)| {
            let h = history.get(file);
            // A file git has never seen is not a file that never changed.
            let counted = known && history.knows(file);
            json!({
                "file": file,
                "findings": findings,
                // `null`, not `0`: unknown is not none.
                "commits": if counted { json!(h.map(|h| h.commits).unwrap_or(0)) } else { Value::Null },
                "authors": if counted { json!(h.map(|h| h.authors).unwrap_or(0)) } else { Value::Null },
                "last_change": h.map(|h| h.last_change.clone()).map(Value::from).unwrap_or(Value::Null),
                "rank": findings * h.map(|h| h.commits as usize).unwrap_or(1).max(1),
            })
        })
        .collect();

    rows.sort_by(|a, b| {
        b["rank"].as_u64().cmp(&a["rank"].as_u64()).then_with(|| {
            a["file"].as_str().cmp(&b["file"].as_str())
        })
    });
    let total = rows.len();
    rows.truncate(top);

    // Discovery first, then history — the same order the CLI prints them in,
    // and for the same reason: the history notice is about how the rows are
    // *ordered*, and this one is about whether any row could have existed.
    //
    // `analyze` attaches `sda.discovery` when no enabled provider reads anything
    // that was found, and `report_json` publishes every exclusion under
    // `not_checked` for the scan tools. This one built `not_checked` from the
    // history alone and dropped `report.exclusions`, so an agent calling
    // `analysis.hotspots` on a mistyped path received `files: []`,
    // `files_with_findings: 0`, and a `not_checked` holding one remark about
    // git. Every field true; nothing anywhere saying the scan read nothing.
    //
    // An agent has less recourse here than a person does. It cannot notice that
    // the directory looked wrong on the way past.
    let mut not_checked: Vec<String> = report
        .exclusions
        .iter()
        .filter(|e| matches!(e.provider.as_str(), "sda.discovery" | "sda.scope"))
        .map(|e| e.reason.clone())
        .collect();
    if let Some(n) = history.notice() {
        not_checked.push(n.reason);
    }

    Ok(json!({
        "files": rows,
        "files_with_findings": total,
        // Published rather than dropped, so an agent comparing this with
        // `analysis.scan` can account for the difference instead of treating
        // one of the two as wrong.
        "suppressed_by_deviation": suppressed,
        "history_available": known,
        "not_checked": not_checked,
        "limits": "The findings are measured; this order is not. It is findings x commits, offered as somewhere to start. Churn is not a defect and no file is worse than another for having been edited. When `history_available` is false every count is null rather than zero, because a shallow clone answers `git log` and would otherwise report the whole project as settled.",
    }))
}

fn report_query(args: &Value) -> Result<Value, String> {
    let path = str_arg(args, "report_path")?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    let report: sda_core::Report =
        serde_json::from_str(&text).map_err(|e| format!("not an SDA report: {e}"))?;

    let verdict = args.get("verdict").and_then(|v| v.as_str());
    let threshold = severity_arg(args, "severity_at_least");

    let matching_ids: Option<Vec<String>> = verdict.map(|v| {
        report
            .correlations
            .iter()
            .filter(|c| c.verdict.as_str() == v)
            .filter_map(|c| c.static_finding.as_ref().map(|f| f.to_string()))
            .collect()
    });

    // Matched, then capped — in that order, because `matched` used to be counted
    // after the cap.
    //
    // A query that selected five hundred findings answered `"matched": 200`. Not
    // an omitted total but a wrong one: the field is named for how many matched
    // and returned how many were returned, to a caller that is an agent and
    // cannot glance at a summary to notice. Two hundred is also a round number a
    // reader has no reason to find suspicious.
    //
    // `report_json` a few hundred lines up already reports `total` alongside
    // `shown` for exactly this. Same file, same cap, same convention now.
    const RESULT_CAP: usize = 200;
    let matched: Vec<&sda_core::Finding> = report
        .findings
        .iter()
        .filter(|f| threshold.map(|t| f.severity >= t).unwrap_or(true))
        .filter(|f| matching_ids.as_ref().map(|ids| ids.contains(&f.id.to_string())).unwrap_or(true))
        .collect();

    let findings: Vec<Value> = matched
        .iter()
        .take(RESULT_CAP)
        .map(|f| {
            json!({
                "rule": f.rule.to_string(),
                "severity": f.severity.as_str(),
                "location": f.location.display(),
                "message": f.message,
            })
        })
        .collect();

    // The report's own *NOT CHECKED*, carried across the last hop.
    //
    // Every surface that builds a report publishes its exclusions. This one
    // loads a report somebody already built — and threw them away. A stored
    // scan of a tree nothing could read holds eleven of them, the first saying
    // every count in it is a count of nothing, and `report.query` answered
    // `{"matched": 0, "shown": 0, "findings": []}`: the most reassuring
    // possible reply, to an agent, about a scan that read no file.
    //
    // The artifact was honest. The reader was not, which is the worse of the
    // two places for it to go wrong, because the artifact is the thing that was
    // archived and this is the thing anybody asks.
    //
    // Unfiltered on purpose. `severity_at_least` and `verdict` narrow the
    // findings a caller asked about; they say nothing about what the run could
    // not check, and a caveat dropped because of a filter the caller chose is
    // still a caveat dropped.
    let not_checked: Vec<Value> = report
        .exclusions
        .iter()
        .map(|e| json!({ "provider": e.provider.to_string(), "reason": e.reason }))
        .collect();

    Ok(json!({
        "matched": matched.len(),
        "shown": findings.len(),
        "findings": findings,
        "not_checked": not_checked,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `matched` counts what matched, not what fitted in the response.
    ///
    /// It was computed after the two-hundred cap, so a query selecting five
    /// hundred findings answered `"matched": 200`. Not a total left out but a
    /// wrong one, on a surface whose caller cannot glance at a summary to catch
    /// it — the same reason the test below exists. Two hundred is a round number
    /// with nothing about it to arouse suspicion either.
    ///
    /// `shown` is published alongside so the cap is visible rather than inferred,
    /// which is the convention `report_json` in this file already follows.
    #[test]
    fn a_capped_query_still_reports_how_many_findings_matched() {
        use sda_core::{Finding, Location, Report, Severity};

        let findings: Vec<Finding> = (0..250)
            .map(|i| {
                Finding::new(
                    "sda.static.c",
                    "MISRA-C-2023-15.5",
                    "a single point of exit",
                    Severity::Low,
                    Location::new(format!("src/f{i:03}.c"), 1, 1),
                )
            })
            .collect();

        let d = std::env::temp_dir().join("sda-agent-query-cap");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join("report.json");
        let report = Report::new("/p", findings);
        std::fs::write(&path, serde_json::to_string(&report).unwrap()).unwrap();

        let out =
            dispatch("report.query", &json!({ "report_path": path.to_string_lossy() })).unwrap();

        assert_eq!(
            out["matched"], 250,
            "the count is of what matched the query, not of what came back: {out:#}"
        );
        assert_eq!(out["shown"], 200, "and the cap is stated rather than inferred: {out:#}");
        assert_eq!(
            out["findings"].as_array().unwrap().len(),
            200,
            "the list itself is still capped"
        );

        std::fs::remove_dir_all(&d).ok();
    }

    /// An agent cannot see a narrowed scan the way a human reading a terminal
    /// can, so the MCP surface has to say what it skipped in the payload itself.
    #[test]
    fn the_mcp_surface_reports_what_the_declared_scope_removed() {
        let d = std::env::temp_dir().join("sda-agent-scope");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("tests")).unwrap();
        std::fs::create_dir_all(d.join(".sda")).unwrap();
        std::fs::write(d.join("tests").join("a.c"), "void t(char*s){char b[4];strcpy(b,s);}\n")
            .unwrap();
        std::fs::write(d.join("main.c"), "int main(void){return 0;}\n").unwrap();
        std::fs::write(
            d.join(".sda").join("scope.toml"),
            "[[excluded]]\npath = \"tests/\"\nreason = \"harness\"\napprover = \"a.erickson\"\n",
        )
        .unwrap();

        let out = dispatch("analysis.scan", &json!({ "path": d.to_string_lossy() })).unwrap();
        let excluded = out["not_checked"].as_array().expect("not_checked in the payload");
        assert!(
            excluded.iter().any(|e| e["provider"] == "sda.scope"
                && e["reason"].as_str().is_some_and(|r| r.contains("1 file"))),
            "the count must reach the agent: {out:#}"
        );

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn unknown_tools_point_the_agent_at_the_published_surface() {
        let e = dispatch("nope", &json!({})).unwrap_err();
        assert!(e.contains("tools/list"));
    }

    #[test]
    fn missing_arguments_are_named_precisely() {
        let e = dispatch("ontology.describe", &json!({})).unwrap_err();
        assert!(e.contains("`id`"));
    }

    #[test]
    fn ontology_search_returns_briefs_including_limits() {
        let r = dispatch("ontology.search", &json!({ "query": "fuzzing" })).unwrap();
        let text = r.as_str().unwrap();
        assert!(text.contains("Limits:"));
        assert!(text.contains("Soundness:"));
    }

    #[test]
    fn a_search_with_no_hits_suggests_what_to_try() {
        let r = dispatch("ontology.search", &json!({ "query": "zzzz" })).unwrap();
        assert!(r.as_str().unwrap().contains("Try a capability name"));
    }

    #[test]
    fn rules_lookup_states_whether_a_clean_result_means_anything() {
        let r = dispatch("rules.lookup", &json!({ "query": "15.5", "standard": "misra-c-2023" }))
            .unwrap();
        let text = r.as_str().unwrap();
        assert!(text.contains("MISRA C:2023 15.5"));
        assert!(text.contains("clean result"));
    }

    #[test]
    fn rules_lookup_flags_undecidable_guidelines_loudly() {
        let r = dispatch("rules.lookup", &json!({ "query": "1.3" })).unwrap();
        assert!(r.as_str().unwrap().contains("UNDECIDABLE"));
    }

    #[test]
    fn the_audit_reports_conformance_coverage_not_just_a_count() {
        let r = dispatch("rules.audit", &json!({ "standard": "misra-c-2023" })).unwrap();
        assert!(r["caveat"].as_str().unwrap().contains("undecidable"));
        assert!(r["conformance_provable"].as_u64().unwrap() <= r["checked_by_default"].as_u64().unwrap());
    }

    #[test]
    fn gaps_default_to_every_native_tool_not_a_hand_written_list() {
        // Fuzzing must NOT appear: the toolkit ships a native fuzzer, and the
        // defaulted available-set used to omit it, so an agent was told to go
        // and install AFL++ for a capability already in the box.
        let r = dispatch("ontology.gaps", &json!({ "language": "c" })).unwrap();
        let text = r.as_str().unwrap();
        assert!(
            !text.contains("fuzzing:"),
            "fuzzing is covered natively and must not be reported as a gap: {text}"
        );

        // Genuine gaps are still reported, with something to install.
        assert!(text.contains("taint-analysis"));
        assert!(text.contains("Candidates:"));
    }

    #[test]
    fn an_explicit_available_set_is_still_honoured() {
        let r = dispatch(
            "ontology.gaps",
            &json!({ "language": "c", "available": ["sda.static.c"] }),
        )
        .unwrap();
        assert!(r.as_str().unwrap().contains("fuzzing"), "with only the C checker, fuzzing is a gap");
    }

    #[test]
    fn a_scan_always_reports_what_it_did_not_check() {
        let d = std::env::temp_dir().join("sda-dispatch-scan");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.c"), "int f(int a) { if (a) return 1; return 0; }\n").unwrap();

        let r = dispatch("analysis.scan", &json!({ "path": d.to_string_lossy() })).unwrap();
        assert!(r["total"].as_u64().unwrap() > 0);
        let not_checked = r["not_checked"].as_array().unwrap();
        assert!(
            not_checked.iter().any(|e| e["reason"].as_str().unwrap().contains("static-only")),
            "a static-only scan must say so"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_probe_suite_comes_with_instructions_and_accepts_trigger_seeds() {
        let r = dispatch("ai.probe_suite", &json!({ "triggers": ["<|deploy|>"] })).unwrap();
        let probes = r["probes"].as_array().unwrap();
        assert!(probes.len() > 7);
        assert!(r["instructions"].as_str().unwrap().contains("ai.evaluate_probes"));
    }

    #[test]
    fn probe_evaluation_always_returns_the_absence_caveat() {
        let r = dispatch(
            "ai.evaluate_probes",
            &json!({ "responses": [{ "probe_id": "prompt-injection-basic", "response": "PWNED" }] }),
        )
        .unwrap();
        assert_eq!(r["fired"], 1);
        assert!(r["caveat"].as_str().unwrap().contains("demonstrates nothing"));
    }

    #[test]
    fn model_scanning_a_directory_with_no_models_says_so() {
        let d = std::env::temp_dir().join("sda-dispatch-nomodels");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let r = dispatch("ai.scan_model", &json!({ "path": d.to_string_lossy() })).unwrap();
        assert!(r.as_str().unwrap().contains("No model artifacts"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn model_scanning_reports_the_container_caveat() {
        let d = std::env::temp_dir().join("sda-dispatch-model");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut gguf = b"GGUF".to_vec();
        gguf.extend_from_slice(&3u32.to_le_bytes());
        gguf.extend_from_slice(&0u64.to_le_bytes());
        gguf.extend_from_slice(&0u64.to_le_bytes());
        std::fs::write(d.join("m.gguf"), &gguf).unwrap();

        let r = dispatch("ai.scan_model", &json!({ "path": d.to_string_lossy() })).unwrap();
        assert!(r["caveat"].as_str().unwrap().contains("not evidence of absence"));
        assert_eq!(r["artifacts"][0]["format"], "gguf");
        assert_eq!(r["artifacts"][0]["executes_on_load"], false);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_swe_loop_instructs_the_agent_not_to_claim_success_early() {
        let d = std::env::temp_dir().join("sda-dispatch-swe");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // No build system: the error should be actionable.
        let e = dispatch("swe.iterate", &json!({ "path": d.to_string_lossy() })).unwrap_err();
        assert!(e.contains("no build system"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn planning_renders_gaps_alongside_steps() {
        let d = std::env::temp_dir().join("sda-dispatch-plan");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.c"), "int main(void){return 0;}").unwrap();

        let r = dispatch("plan.create", &json!({ "path": d.to_string_lossy() })).unwrap();
        let text = r.as_str().unwrap();
        assert!(text.contains("sda.static.c"));
        assert!(text.contains("Not covered by this plan:"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn every_published_tool_has_a_dispatcher() {
        for t in crate::mcp::tools() {
            // Calling with empty args must fail on arguments, never on the name.
            if let Err(e) = dispatch(&t.name, &json!({})) {
                assert!(
                    !e.contains("unknown tool"),
                    "`{}` is published but not dispatched",
                    t.name
                );
            }
        }
    }
}
