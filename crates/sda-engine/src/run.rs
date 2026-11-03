//! Orchestration: select providers, run them, correlate, and build a report.

use crate::correlate::{self, CorrelationPolicy};
use crate::dynamic::Observation;
use sda_core::{
    AnalysisPhase, Exclusion, Finding, Registry, Report, RunOptions, SelectionPolicy, Severity,
};
use sda_rules::DeviationRegister;

/// Everything that shapes a run, in one place.
#[derive(Clone, Debug, Default)]
pub struct RunConfig {
    pub selection: SelectionPolicy,
    pub options: RunOptions,
    pub correlation: CorrelationPolicy,
    /// Approved departures from the guidelines.
    pub deviations: Option<DeviationRegister>,
    /// Runtime observation to correlate against. `None` means a static-only run,
    /// and the report says so rather than implying dynamic evidence exists.
    pub observation: Option<Observation>,
    /// Notices produced before the run — today, the analysis-scope exclusions
    /// from `discover::apply_scope`. They are computed against the file list, so
    /// they cannot be derived here, but they must reach the *NOT CHECKED*
    /// section or the scan silently narrowed itself.
    pub notices: Vec<Exclusion>,
    /// The declared shape of a hybrid system, from `.sda/architecture.toml`.
    ///
    /// `None` means the project made no claim, which is not the same as a claim
    /// that held: nothing here invents one, and the caller that knows the
    /// project ships a model says so in a notice.
    pub architecture: Option<sda_rules::ArchitectureDeclaration>,
}

impl RunConfig {
    pub fn with_external(mut self) -> Self {
        self.selection = self.selection.with_external();
        self
    }
    pub fn with_deviations(mut self, reg: DeviationRegister) -> Self {
        self.deviations = Some(reg);
        self
    }
    pub fn with_observation(mut self, obs: Observation) -> Self {
        self.observation = Some(obs);
        self
    }
    pub fn with_notices(mut self, notices: Vec<Exclusion>) -> Self {
        self.notices = notices;
        self
    }
    pub fn with_architecture(mut self, decl: sda_rules::ArchitectureDeclaration) -> Self {
        self.architecture = Some(decl);
        self
    }
}

/// Run every selected provider against `target` and assemble a report.
pub fn analyze(registry: &Registry, target: &sda_core::Target, config: &RunConfig) -> Report {
    let (providers, mut exclusions) = registry.select(&config.selection);
    // Scope exclusions first: they describe what was never handed to a provider,
    // which is the thing a reader most needs before reading a clean result.
    exclusions.splice(0..0, config.notices.iter().cloned());

    // A scan that found nothing to read must say so in the report.
    //
    // `discover::inventory` prints "no analyzable files found" and the CLI writes
    // it to stderr, where `--format json > report.json` throws it away. What
    // reaches the file is a report with no findings, no `languages`, and nine
    // `ext.*` notices about providers that were not enabled — which is
    // indistinguishable from a clean scan of a real codebase, and considerably
    // more reassuring than one.
    //
    // The ways to arrive here are ordinary: a mistyped path, a build directory,
    // a scan rooted one level too deep, a tree whose languages this does not
    // read. Every one produces zero findings from nothing read, which is the most
    // confident possible way to say nothing.
    //
    // The condition is *no enabled provider reads anything here*, not *no file
    // was discovered*. Discovery counts `.md` and `.txt` among plenty else, so a
    // documentation directory reports `1 md, 1 txt` on stderr — which reassures
    // the operator that two files were analysed — and then produces a report with
    // no findings and nothing to say. The empty-directory case is the obvious one
    // and the rarer one.
    //
    // Same defect as the configuration problems that were stderr-only until
    // earlier today, and the same fix: the artifact has to carry it, because the
    // artifact is what gets attached to a review and read six months later.
    let languages = target.languages();
    let read_by_something = providers.iter().any(|p| {
        let info = p.info();
        languages.iter().any(|l| info.handles(l))
    });
    if !read_by_something {
        // The mistyped path listed above needs its own sentence, and for a long
        // time did not get one: a root that does not exist produced `no file was
        // found under X`, which is what an empty directory deserves and reads as
        // a statement about a place that was looked inside. It is the difference
        // between *there is nothing here* and *you pointed me at nothing*, and
        // the two want opposite actions — the second is a wrong argument, and no
        // amount of checking which languages this toolkit reads will help.
        //
        // `try_exists` rather than `exists` because the third answer matters:
        // `exists` folds a permission error into `false` and would report a
        // directory we were not allowed to look at as one that is not there.
        let (what, advice) = if !target.files.is_empty() {
            (
                format!(
                    "{} file(s) were found under `{}` and no enabled provider reads any of \
                     their languages",
                    target.files.len(),
                    target.root.display()
                ),
                "check the path, and check that this toolkit reads the languages in it",
            )
        } else {
            match target.root.try_exists() {
                Ok(true) => (
                    format!("no file was found under `{}`", target.root.display()),
                    "check the path, and check that this toolkit reads the languages in it",
                ),
                Ok(false) => (
                    format!("`{}` does not exist", target.root.display()),
                    "check the path you passed. There was nothing there to scan, so this \
                     result is about the argument and not about any code",
                ),
                Err(e) => (
                    format!("`{}` could not be examined ({e})", target.root.display()),
                    "check the path and whether this process may read it",
                ),
            }
        };
        exclusions.insert(
            0,
            Exclusion {
                provider: "sda.discovery".into(),
                reason: format!(
                    "{what}, so nothing was checked and every count in this report is a count \
                     of nothing. A clean result here describes the scan, not the code — {advice}"
                ),
            },
        );
    }

    let mut static_findings = Vec::new();
    let mut dynamic_findings = Vec::new();

    // Dynamic providers that ran to completion. A tool that executed the program
    // and found nothing has told us something; reporting that run as
    // "static-only" is the same confusion this file has a table of, inverted —
    // a check that did happen, presented as one that did not.
    let mut executed_by: Vec<String> = Vec::new();

    for p in &providers {
        let info = p.info();
        match p.analyze(target, &config.options) {
            Ok(found) => {
                if info.kind == sda_core::AnalyzerKind::Dynamic {
                    executed_by.push(info.id.to_string());
                }
                // What the provider says it could not check. Drained here and
                // not in the CLI, so the workbench and both MCP paths get it
                // too — the drift this file has a test about, one surface over.
                exclusions.extend(p.take_notices());
                // A provider's own declared kind decides which side of the
                // correlation its findings land on, not the findings' phase
                // field, which a provider could set inconsistently.
                for f in found {
                    // One defect reported twice is a miscount, and a report
                    // that says two is wrong about the thing it exists to say.
                    // `cargo clippy --all-targets` compiles a binary once as
                    // itself and once as its test harness, and emits every
                    // diagnostic for both — identical rule, location and
                    // message, so identical fingerprint. The dynamic side
                    // already collapsed these; the static side did not, and a
                    // real clippy run over a nine-line program reported its one
                    // lint twice.
                    let side = if f.phase == AnalysisPhase::Dynamic {
                        &mut dynamic_findings
                    } else {
                        &mut static_findings
                    };
                    if !side.iter().any(|e: &sda_core::Finding| e.id == f.id) {
                        side.push(f);
                    }
                }
            }
            Err(e) => {
                // A provider that fails must not look like a provider that
                // found nothing.
                exclusions.push(Exclusion {
                    provider: info.id.clone(),
                    reason: format!("provider failed during analysis: {e}"),
                });
            }
        }
    }

    // Two of `RunOptions`' three knobs are honoured by nothing, and a knob that
    // is silently ignored is worse than one that does not exist.
    //
    // `timeout_secs` is documented as "wall-clock budget for the whole provider,
    // in seconds" and is read nowhere in the workspace — a caller who sets it
    // gets no budget and no indication of that. `settings`, with its `get`/`set`
    // accessors, is a whole provider-configuration mechanism nothing consumes;
    // the doc comment's own example, `("sda.dynamic", "max_runs")`, appears in
    // that comment and nowhere else.
    //
    // Neither is wired up here. A wall-clock budget across native providers
    // needs cancellation this engine does not have, and inventing a setting for
    // a provider that never asked for one would be worse than the gap. What can
    // be done honestly is refuse to accept the instruction in silence: the
    // difference between "your timeout did nothing" and nothing at all is the
    // whole of what this section is for.
    //
    // `disabled_rules`, the third, is read by three providers and works.
    if config.options.timeout_secs.is_some() {
        exclusions.push(Exclusion {
            provider: "sda.options".into(),
            reason: "a `timeout_secs` budget was set and no provider enforces one, so this run \
                     was unbounded. Nothing here was cut short — but nothing was limited either, \
                     and a run that outlives its budget will not be stopped"
                .into(),
        });
    }
    if !config.options.settings.is_empty() {
        exclusions.push(Exclusion {
            provider: "sda.options".into(),
            reason: format!(
                "{} provider setting(s) were supplied and no provider reads them, so every one \
                 was ignored. Whatever they were meant to change did not change",
                config.options.settings.len()
            ),
        });
    }

    // A supplied observation carries faults of its own — from our probe stream
    // or from a sanitizer-instrumented build launched outside this process.
    // Those are findings in their own right, whether or not a dynamic *provider*
    // ran, and they must exist before correlation can confirm anything.
    if let Some(obs) = &config.observation {
        let mut from_obs = crate::dynamic::findings_from(obs, &target.root.to_string_lossy());
        // The runtime side names positions in text it never read; the source is
        // right here, so the extents are recoverable.
        crate::dynamic::span_against_source(&mut from_obs, &target.root);
        for f in from_obs {
            if !dynamic_findings.iter().any(|d| d.id == f.id) {
                dynamic_findings.push(f);
            }
        }
    }

    // Deviations are applied before correlation so an approved departure is not
    // escalated by runtime evidence into something the process already accepted.
    if let Some(reg) = &config.deviations {
        // Today, as an ISO date. The register takes it as a parameter rather
        // than reading a clock itself, so a report can be reproduced from its
        // inputs — see `DeviationRegister::find`.
        let today = sda_core::report::now_rfc3339();
        let today = today.get(..10).unwrap_or("1970-01-01");

        reg.apply(&mut static_findings, today);
        for r in reg.rejected() {
            exclusions.push(Exclusion {
                provider: "sda.deviations".into(),
                reason: format!("deviation for `{}` rejected: {}", r.rule, r.reason),
            });
        }

        // An expired record stopped suppressing the moment it lapsed, which
        // means findings appear that a reader last saw accepted. Saying so is
        // the difference between a lapsed acceptance and an unexplained
        // regression.
        for d in reg.expired(today) {
            exclusions.push(Exclusion {
                provider: "sda.deviations".into(),
                reason: format!(
                    "deviation for `{}` expired on {} and no longer suppresses anything; \
                     the departure it covered is either visible again or gone, and the \
                     record needs re-approval or retirement",
                    d.rule,
                    d.expires.as_deref().unwrap_or("an unstated date")
                ),
            });
        }

        // A record that covers nothing is dead weight in a conformance
        // argument: it reads as an accepted departure that no longer exists.
        //
        // Only for records about files this run actually looked at. The first
        // version of this said nothing of the sort, and a scan of `crates`
        // duly reported all six `shim/sda_probe.h` records as unused — they are
        // not unused, they are about a file that scan never opened. Saying so
        // would have been this codebase's own cardinal error, printed by the
        // very section that exists to prevent it.
        let scanned: Vec<String> =
            target.files.iter().map(|f| f.path.to_string_lossy().to_string()).collect();
        // And only for records whose finding could have been produced at all.
        // A `clippy::needless_range_loop` record matches nothing in a
        // native-first run because clippy never ran — which says everything
        // about the run and nothing about the record.
        let external_ran =
            providers.iter().any(|p| p.info().origin == sda_core::ProviderOrigin::External);

        for d in reg.unused(&static_findings) {
            if !d.could_apply_to(&scanned) || (d.is_external() && !external_ran) {
                continue;
            }
            exclusions.push(Exclusion {
                provider: "sda.deviations".into(),
                reason: format!(
                    "deviation for `{}` matched no finding in this run, though this scan did \
                     read the files it names; retire it or confirm the departure is still there",
                    d.rule
                ),
            });
        }
    }

    // Deduction over the declared architecture, before correlation, because
    // `Adjudication::unadjudicated` is defined as correlation's input: a finding
    // a proof already settled must not be re-judged by the runtime correlator,
    // which would let `Unreached` ("we never tried") overwrite "this cannot
    // happen". These checks used to live only in `sda verify` and
    // `analysis.verify`, so a project could ship an `.sda/architecture.toml`
    // and get a clean `sda scan` that never mentioned interposition at all.
    let mut adjudicated: Vec<Finding> = Vec::new();
    let mut deduced: Vec<sda_core::Correlation> = Vec::new();
    if config.architecture.is_none()
        && target.languages().contains(&sda_core::Language::ModelArtifact)
    {
        // Said here and only here: a project that ships no model has nothing to
        // interpose, and a notice printed on every scan in the world is one
        // people learn to skip past — the same reason the probe runner is
        // registered conditionally. A project that *does* ship a model and
        // declares no dataflow has an unstated safety case, and a clean scan
        // must not be read as covering it.
        exclusions.push(Exclusion {
            provider: "sda.interposition".into(),
            reason: "this project ships a model artifact and has no `.sda/architecture.toml`, \
                     so whether the model's output can reach an effector without crossing a \
                     guard was not checked. Nothing was claimed and nothing was proved"
                .into(),
        });
    }
    if let Some(decl) = &config.architecture {
        let system = crate::interposition::from_declaration(decl);
        for problem in &system.problems {
            exclusions.push(Exclusion { provider: "sda.architecture".into(), reason: problem.clone() });
        }

        // Only findings that carry a real dataflow trace are offered as taint.
        // `interposition::verify` reads a trace to decide whether a flow crossed
        // a guard, and records a traceless finding that lands on an effector as
        // unevaluable — correct for a taint tool that could not answer, and
        // noise if every unrelated finding in the scan were handed to it, which
        // would bury the ones that genuinely could not be read.
        let taint: Vec<Finding> = static_findings
            .iter()
            .filter(|f| {
                f.evidence
                    .iter()
                    .any(|e| matches!(e, sda_core::Evidence::Trace { frames } if frames.len() >= 2))
            })
            .cloned()
            .collect();

        let interposition = crate::interposition::verify(&system.map, &system.flow, &taint);
        for line in &interposition.not_checked {
            exclusions.push(Exclusion { provider: "sda.interposition".into(), reason: line.clone() });
        }
        // The verdict itself, in the report rather than only on a terminal.
        exclusions.push(Exclusion {
            provider: "sda.interposition".into(),
            reason: crate::interposition::summarize(&interposition),
        });

        let ledger = interposition.merge_into(Default::default());
        let adjudication = crate::neurosymbolic::adjudicate(&static_findings, &ledger, &system.map);
        for line in &adjudication.not_checked {
            exclusions.push(Exclusion { provider: "sda.neurosymbolic".into(), reason: line.clone() });
        }
        static_findings = adjudication.unadjudicated();
        adjudicated = adjudication.adjudicated();
        deduced = adjudication.correlations;

        // The bypasses join the report *after* both engines, and pass through
        // neither. Adjudicating them would run the deduction over its own
        // output, and since they are located at the declaration rather than in
        // code, the only thing it can conclude is that the declaration belongs
        // to no declared component — a true statement about a file that is not
        // part of the system, reported as a gap in the analysis of one. And
        // correlating them would ask whether a line of TOML executed.
        adjudicated.extend(crate::interposition::findings_from(
            &interposition,
            ".sda/architecture.toml",
        ));
    }

    // Correlation needs a *witness or a measurement*, and those arrive by
    // different routes. The native engine supplies both; an external dynamic
    // tool — Valgrind, Miri — supplies only witnesses, and correlation used to
    // be reached only through the observation, so a real Memcheck invalid-write
    // sat beside the static finding it corroborated and confirmed nothing. That
    // left the toolkit's central claim unavailable to every external dynamic
    // tool it ships an adapter for.
    let witnessed = !dynamic_findings.is_empty();

    // Who executed the program is a fact about the run, not about whether
    // coverage happened to be supplied, and it belongs in the report either way.
    //
    // It used to be said only in the arm below that fires when there is no
    // observation at all. Supplying a coverage report *creates* an observation,
    // so the moment `--coverage` was added the sentence vanished — and a scan of
    // 105 real C files came back with 492 findings `refuted` and nothing anywhere
    // saying that Memcheck had run the program and found nothing. That is the row
    // this file already has in its table ("a quiet dynamic tool"), reintroduced
    // through the door the coverage seam opened.
    if !executed_by.is_empty() && !witnessed {
        exclusions.push(Exclusion {
            provider: "sda.dynamic".into(),
            reason: format!(
                "{} executed the program and reported no defects. That is not a clean bill of \
                 health: a dynamic tool reports only the defect classes it checks for, and it saw \
                 one execution of one input",
                executed_by.join(", ")
            ),
        });
    }
    let (findings, correlations) = match (&config.observation, witnessed) {
        (None, false) => {
            exclusions.push(Exclusion {
                provider: "sda.correlate".into(),
                reason: if executed_by.is_empty() {
                    // "reached this run", not "was supplied".
                    //
                    // A run given `--artifact broken.bin` that cannot execute it
                    // reports two things: `sda.dynamic` says the artifact could
                    // not be launched, and this said nothing was supplied. One
                    // of the two was false, and it was this one — the operator
                    // supplied exactly what was asked for and it failed.
                    //
                    // The distinction matters to whoever reads the report:
                    // "you did not supply one" is a prompt to go and build it,
                    // "yours did not run" is a prompt to go and fix it. The
                    // wording below is true of both, and `sda.dynamic` above
                    // carries the cause when there is one.
                    "no runtime observation reached this run, so no static finding was \
                     confirmed or refuted; this is a static-only result"
                        .into()
                } else {
                    // Which tools ran is stated above, unconditionally. What is
                    // specific to this arm is that nothing measured coverage, so
                    // no line's execution is known. Driven with real Valgrind
                    // against a program whose leak had been fixed: Memcheck ran,
                    // executed the program, reported nothing, and the report
                    // said "static-only result" without naming it.
                    "the program was executed but no coverage was measured, so which lines ran \
                     is unknown and nothing could be confirmed, refuted or shown unreached"
                        .to_string()
                },
            });
            // `witnessed` is false, so this extend is empty today. It stays
            // because the alternative is a report that silently drops runtime
            // findings the moment someone changes the arm's guard — the shape of
            // defect this file already has a table of.
            let mut all = static_findings;
            all.extend(dynamic_findings);
            (all, Vec::new())
        }
        (obs, _) => {
            if obs.is_none() {
                // The run did execute the program, so it is not static-only. But
                // no coverage was measured, and saying nothing here would let a
                // reader take the absence of `Refuted` for a lack of exercise
                // rather than a lack of instrumentation.
                exclusions.push(Exclusion {
                    provider: "sda.correlate".into(),
                    reason: "runtime evidence came only from external dynamic tools, which report \
                             defects but no coverage, so no line's execution was measured: \
                             findings could be confirmed but none could be refuted or shown \
                             unreached"
                        .into(),
                });
            }
            let result = correlate::correlate(
                &static_findings,
                &dynamic_findings,
                obs.as_ref(),
                &config.correlation,
            );
            (result.findings, result.correlations)
        }
    };

    // Findings a proof settled rejoin the report after correlation, carrying the
    // verdict deduction reached; they were withheld from `correlate`, not from
    // the report.
    let mut findings = findings;
    findings.extend(adjudicated);
    let mut correlations = correlations;
    correlations.extend(deduced);

    // Asked here rather than in the CLI, so the workbench and both MCP paths
    // report the same revision the command line does. Absent when the target is
    // not a checkout, which is honest: plenty of real targets are unpacked
    // tarballs or scratch directories.
    let vcs = crate::vcs::detect(&target.root);

    Report::new(target.root.to_string_lossy().to_string(), findings)
        .with_correlations(correlations)
        .with_exclusions(exclusions)
        .with_vcs(vcs)
        .finalize()
}

/// What a CI gate should do with a report.
///
/// Three outcomes rather than two, for the reason this whole codebase exists:
/// *measured and clean* and *could not measure* are different answers, and an
/// exit code is the most consumed clean result there is. Folding the second
/// into `Pass` is what made `sda scan ./srcc --fail-on low` print `no findings
/// at or above low` and exit 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// Measured, and nothing at or above the threshold.
    Pass,
    /// Measured, and something at or above it.
    Fail,
    /// Nothing was scanned, so there is no verdict to give either way.
    NotChecked,
}

impl Gate {
    /// Whether a CI step should stop here. `NotChecked` stops it too: a gate
    /// that could not run has not been passed.
    pub fn should_stop(self) -> bool {
        !matches!(self, Gate::Pass)
    }
}

/// What a CI gate should do with this report, and a sentence explaining why.
///
/// The README records this exact trap about somebody else's tool: the
/// standalone `verus` binary exits 0 on a failed proof, so *a CI gate on its
/// exit code would have passed it*. This gate had the same property for a
/// different input. A mistyped path produced zero findings, `no findings at or
/// above low`, and a green build — a sentence about code that was never read,
/// in the one output a pipeline actually consumes.
pub fn gate(report: &Report, threshold: Severity) -> (Gate, String) {
    // Asked before the count, because the count is what is meaningless.
    if let Some(e) = report.discovery_notice() {
        return (
            Gate::NotChecked,
            format!(
                "no verdict: nothing was scanned, so `no findings` would be a statement about \
                 this run and not about any code. {}",
                e.reason
            ),
        );
    }

    let n = report.summary.at_or_above(threshold);
    if n == 0 {
        let caveat = if report.correlations.is_empty() {
            " (static-only run: no finding was confirmed or refuted by execution)"
        } else {
            ""
        };
        (Gate::Pass, format!("no findings at or above {threshold}{caveat}"))
    } else {
        let confirmed = report.confirmed().len();
        let detail = if confirmed > 0 {
            format!(", {confirmed} of them confirmed by runtime evidence")
        } else {
            String::new()
        };
        (Gate::Fail, format!("{n} finding(s) at or above {threshold}{detail}"))
    }
}

/// Findings ordered for a human working through them: runtime-confirmed first,
/// then by severity. The ordering is the product decision that makes a long
/// report usable.
pub fn triage_order(report: &Report) -> Vec<&Finding> {
    let confirmed: Vec<&sda_core::FindingId> = report
        .correlations
        .iter()
        .filter(|c| c.verdict == sda_core::CorrelationVerdict::Confirmed)
        .filter_map(|c| c.static_finding.as_ref())
        .collect();

    let mut v: Vec<&Finding> = report.findings.iter().filter(|f| !f.is_suppressed()).collect();
    v.sort_by_key(|f| {
        let is_confirmed = confirmed.contains(&&f.id) || f.has_runtime_evidence();
        (!is_confirmed, f.triage_key())
    });
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_registry;
    use sda_core::{Language, Target, TargetFile};
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sda-run-{name}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn c_target(dir: &std::path::Path, src: &str) -> Target {
        let file = dir.join("main.c");
        fs::write(&file, src).unwrap();
        Target::new(dir).with_files(vec![TargetFile {
            path: file,
            language: Language::C,
            bytes: src.len() as u64,
        }])
    }

    #[test]
    fn a_default_run_finds_real_violations_with_no_setup() {
        let d = scratch("default");
        let t = c_target(
            &d,
            "int f(int a) {\n  if (a) return 1;\n  return 0;\n}\n",
        );
        let report = analyze(&default_registry(), &t, &RunConfig::default());
        assert!(report.summary.total > 0, "expected findings, got none");
        // 15.6 (unbraced if) and 15.5 (two exits) are both here.
        let rules: Vec<String> = report.findings.iter().map(|f| f.rule.to_string()).collect();
        assert!(rules.iter().any(|r| r.ends_with("15.6")), "rules: {rules:?}");
        fs::remove_dir_all(&d).ok();
    }

    /// `cargo clippy --all-targets` compiles a binary as itself and again as
    /// its test harness, and emits every diagnostic for both. A real run over a
    /// nine-line program reported its single lint twice, so the report's count
    /// — the number it exists to state — was double the truth.
    #[test]
    fn one_defect_reported_twice_by_a_provider_is_counted_once() {
        use sda_core::{
            Analyzer, AnalyzerKind, Availability, Capability, Finding, Location, ProviderInfo,
            ProviderOrigin, Severity,
        };

        struct Echoing;
        impl Analyzer for Echoing {
            fn info(&self) -> ProviderInfo {
                ProviderInfo {
                    id: "ext.doubling".into(),
                    name: "doubling".into(),
                    origin: ProviderOrigin::External,
                    kind: AnalyzerKind::Static,
                    languages: vec![Language::Rust],
                    capabilities: vec![Capability::StyleCompliance],
                    description: "emits the same diagnostic once per target".into(),
                    executable: None,
                    url: None,
                    requires_build: false,
                }
            }
            fn available(&self) -> Availability {
                Availability::Available
            }
            fn analyze(
                &self,
                _t: &Target,
                _o: &sda_core::RunOptions,
            ) -> sda_core::Result<Vec<Finding>> {
                let one = || {
                    Finding::new(
                        "ext.doubling",
                        "clippy::needless_range_loop",
                        "the loop indexes a slice it could iterate",
                        Severity::Medium,
                        Location::new("src/main.rs", 4, 14),
                    )
                };
                Ok(vec![one(), one()])
            }
        }

        let d = scratch("dedup");
        let mut registry = Registry::new();
        registry.register(std::sync::Arc::new(Echoing));
        let mut config = RunConfig::default();
        config.selection = config.selection.enable("ext.doubling");
        let report = analyze(&registry, &Target::new(&d), &config);

        let hits = report
            .findings
            .iter()
            .filter(|f| f.rule.as_str() == "clippy::needless_range_loop")
            .count();
        assert_eq!(hits, 1, "the same defect at the same place is one finding");
        fs::remove_dir_all(&d).ok();
    }

    /// The toolkit's central claim, made available to external dynamic tools.
    ///
    /// `correlate` was reached only when a native `Observation` existed, and only
    /// the probe engine produces one. So a real Valgrind witness sat beside the
    /// static finding it corroborated without confirming it: the phase was right,
    /// the CWEs matched, and no correlation ran at all. Driven end to end against
    /// Memcheck 3.24.0 before this test existed.
    #[test]
    fn an_external_dynamic_witness_confirms_without_a_native_observation() {
        use sda_core::{
            Analyzer, AnalyzerKind, Availability, Capability, Confidence, CorrelationVerdict,
            Evidence, Finding, Location, ProviderInfo, ProviderOrigin, RuntimeEvent,
            RuntimeEventKind, Severity, TaxonomyRef,
        };

        struct Suspecting;
        impl Analyzer for Suspecting {
            fn info(&self) -> ProviderInfo {
                ProviderInfo {
                    id: "ext.suspecting".into(),
                    name: "suspecting".into(),
                    origin: ProviderOrigin::External,
                    kind: AnalyzerKind::Static,
                    languages: vec![Language::C],
                    capabilities: vec![Capability::MemorySafety],
                    description: "suspects an out-of-bounds write".into(),
                    executable: None,
                    url: None,
                    requires_build: false,
                }
            }
            fn available(&self) -> Availability {
                Availability::Available
            }
            fn analyze(&self, _t: &Target, _o: &RunOptions) -> sda_core::Result<Vec<Finding>> {
                Ok(vec![
                    Finding::new(
                        "ext.suspecting",
                        "arrayIndexOutOfBounds",
                        "array index may leave the allocation",
                        Severity::Medium,
                        Location::new("src/leaky.c", 12, 5),
                    )
                    .confidence(Confidence::Medium)
                    .taxonomy(TaxonomyRef::cwe(787)),
                ])
            }
        }

        /// Stands in for `ext.valgrind`: a tool that ran the program and saw the
        /// fault. It reports no coverage, which is the whole difficulty.
        struct Witnessing;
        impl Analyzer for Witnessing {
            fn info(&self) -> ProviderInfo {
                ProviderInfo {
                    id: "ext.witnessing".into(),
                    name: "witnessing".into(),
                    origin: ProviderOrigin::External,
                    kind: AnalyzerKind::Dynamic,
                    languages: vec![Language::C],
                    capabilities: vec![Capability::MemorySafety],
                    description: "executes the program and reports faults".into(),
                    executable: None,
                    url: None,
                    requires_build: false,
                }
            }
            fn available(&self) -> Availability {
                Availability::Available
            }
            fn analyze(&self, _t: &Target, _o: &RunOptions) -> sda_core::Result<Vec<Finding>> {
                Ok(vec![
                    Finding::new(
                        "ext.witnessing",
                        "InvalidWrite",
                        "Invalid write of size 4",
                        Severity::High,
                        Location::new("src/leaky.c", 12, 3),
                    )
                    .phase(AnalysisPhase::Dynamic)
                    .confidence(Confidence::Certain)
                    .taxonomy(TaxonomyRef::cwe(787))
                    .evidence(Evidence::Runtime {
                        event: RuntimeEvent::new(RuntimeEventKind::MemoryError, "invalid write"),
                    }),
                ])
            }
        }

        let d = scratch("extdyn");
        let mut registry = Registry::new();
        registry.register(std::sync::Arc::new(Suspecting));
        registry.register(std::sync::Arc::new(Witnessing));
        let mut config = RunConfig::default();
        config.selection = config.selection.enable("ext.suspecting").enable("ext.witnessing");

        // No `--artifact`, so no native observation. This is the ordinary way a
        // user runs an external dynamic tool.
        assert!(config.observation.is_none());
        let report = analyze(&registry, &Target::new(&d), &config);

        assert_eq!(
            report
                .correlations
                .iter()
                .filter(|c| c.verdict == CorrelationVerdict::Confirmed)
                .count(),
            1,
            "a witnessed out-of-bounds write confirms the guideline that predicted it: {:?}",
            report.correlations
        );
        assert!(
            !report.exclusions.iter().any(|e| e.reason.contains("static-only")),
            "a run that executed the program is not a static-only result"
        );
        // But execution was never *measured*, so nothing may be refuted and no
        // line may be called unreached — the tool reports defects, not coverage.
        assert_eq!(report.correlations.iter().filter(|c| c.verdict == CorrelationVerdict::Refuted).count(), 0);
        assert_eq!(report.correlations.iter().filter(|c| c.verdict == CorrelationVerdict::Unreached).count(), 0);
        assert!(
            report.exclusions.iter().any(|e| e.reason.contains("coverage")),
            "and the report must say coverage was never measured: {:?}",
            report.exclusions
        );
        fs::remove_dir_all(&d).ok();
    }

    /// The other three verdicts, for a tool that counts no lines.
    ///
    /// An external dynamic tool could confirm and nothing else: with no
    /// execution counts, `correlate` receives `None` and `Refuted` and
    /// `Unreached` are unavailable by construction. Handing it coverage from a
    /// tool that *does* count lines — gcov here, lcov equally — completes the
    /// table without the native probe shim being involved anywhere.
    ///
    /// One run, three findings, three verdicts: the witnessed line is confirmed,
    /// the heavily-executed line is refuted, and the line measured at zero is
    /// unreached. All from an external witness plus an external coverage file.
    #[test]
    fn external_coverage_lets_an_external_dynamic_run_refute_and_reach() {
        use sda_core::{
            Analyzer, AnalyzerKind, Availability, Capability, Confidence, CorrelationVerdict,
            Evidence, Finding, Location, ProviderInfo, ProviderOrigin, RuntimeEvent,
            RuntimeEventKind, Severity, TaxonomyRef,
        };

        struct Predicting;
        impl Analyzer for Predicting {
            fn info(&self) -> ProviderInfo {
                ProviderInfo {
                    id: "ext.predicting".into(),
                    name: "predicting".into(),
                    origin: ProviderOrigin::External,
                    kind: AnalyzerKind::Static,
                    languages: vec![Language::C],
                    capabilities: vec![Capability::MemorySafety],
                    description: "suspects three out-of-bounds writes".into(),
                    executable: None,
                    url: None,
                    requires_build: false,
                }
            }
            fn available(&self) -> Availability {
                Availability::Available
            }
            fn analyze(&self, _t: &Target, _o: &RunOptions) -> sda_core::Result<Vec<Finding>> {
                let at = |line| {
                    Finding::new(
                        "ext.predicting",
                        "arrayIndexOutOfBounds",
                        "array index may leave the allocation",
                        Severity::Medium,
                        Location::new("src/leaky.c", line, 5),
                    )
                    .confidence(Confidence::Medium)
                    .taxonomy(TaxonomyRef::cwe(787))
                };
                Ok(vec![at(12), at(20), at(30)])
            }
        }

        struct Witnessing;
        impl Analyzer for Witnessing {
            fn info(&self) -> ProviderInfo {
                ProviderInfo {
                    id: "ext.witness2".into(),
                    name: "witness2".into(),
                    origin: ProviderOrigin::External,
                    kind: AnalyzerKind::Dynamic,
                    languages: vec![Language::C],
                    capabilities: vec![Capability::MemorySafety],
                    description: "executes the program and reports faults".into(),
                    executable: None,
                    url: None,
                    requires_build: false,
                }
            }
            fn available(&self) -> Availability {
                Availability::Available
            }
            fn analyze(&self, _t: &Target, _o: &RunOptions) -> sda_core::Result<Vec<Finding>> {
                Ok(vec![
                    Finding::new(
                        "ext.witness2",
                        "InvalidWrite",
                        "Invalid write of size 4",
                        Severity::High,
                        Location::new("src/leaky.c", 12, 3),
                    )
                    .phase(AnalysisPhase::Dynamic)
                    .confidence(Confidence::Certain)
                    .taxonomy(TaxonomyRef::cwe(787))
                    .evidence(Evidence::Runtime {
                        event: RuntimeEvent::new(RuntimeEventKind::MemoryError, "invalid write"),
                    }),
                ])
            }
        }

        // As gcov writes it: `#####` on line 30 is a measurement of zero, which
        // is what makes `unreached` a statement about the code rather than about
        // the instrument.
        let gcov = "        -:    0:Source:src/leaky.c\n\
                        1:   12:  buf[i] = 0;\n\
                      500:   20:  tick();\n\
                    #####:   30:  never();\n";
        let coverage = crate::coverage::parse(gcov).expect("a gcov listing with three records");
        assert_eq!(coverage.lines_measured, 3);
        assert_eq!(coverage.lines_executed, 2);

        let d = scratch("extcov");
        let mut registry = Registry::new();
        registry.register(std::sync::Arc::new(Predicting));
        registry.register(std::sync::Arc::new(Witnessing));
        let mut config = RunConfig::default();
        config.selection = config.selection.enable("ext.predicting").enable("ext.witness2");
        config = config.with_observation(coverage.observation);
        let report = analyze(&registry, &Target::new(&d), &config);

        let count = |v| report.correlations.iter().filter(|c| c.verdict == v).count();
        assert_eq!(count(CorrelationVerdict::Confirmed), 1, "{:?}", report.correlations);
        assert_eq!(
            count(CorrelationVerdict::Refuted),
            1,
            "line 20 executed 500 times with no fault there: {:?}",
            report.correlations
        );
        assert_eq!(
            count(CorrelationVerdict::Unreached),
            1,
            "line 30 was measured and never ran: {:?}",
            report.correlations
        );

        // And the run must stop apologising for coverage it now has.
        assert!(
            !report
                .exclusions
                .iter()
                .any(|e| e.reason.contains("no line's execution was measured")),
            "coverage was supplied, so the caveat about its absence is now false: {:?}",
            report.exclusions
        );
        fs::remove_dir_all(&d).ok();
    }

    /// The same claim, with coverage supplied — which is the case that lost it.
    ///
    /// `--coverage` creates an observation, which moves the run into the other
    /// arm of the correlation match, and the sentence naming the tool lived only
    /// in the first arm. A scan of 105 real C files came back with 492 findings
    /// `refuted` and nothing anywhere saying Memcheck had executed the program
    /// and found nothing: "refuted" then reads as stronger evidence than it is.
    #[test]
    fn a_quiet_dynamic_tool_is_named_even_when_coverage_was_supplied() {
        use sda_core::{
            Analyzer, AnalyzerKind, Availability, Capability, Finding, ProviderInfo,
            ProviderOrigin,
        };

        struct QuietWithCoverage;
        impl Analyzer for QuietWithCoverage {
            fn info(&self) -> ProviderInfo {
                ProviderInfo {
                    id: "ext.quiet2".into(),
                    name: "quiet".into(),
                    origin: ProviderOrigin::External,
                    kind: AnalyzerKind::Dynamic,
                    languages: vec![Language::C],
                    capabilities: vec![Capability::MemorySafety],
                    description: "runs the program and finds nothing".into(),
                    executable: None,
                    url: None,
                    requires_build: false,
                }
            }
            fn available(&self) -> Availability {
                Availability::Available
            }
            fn analyze(&self, _t: &Target, _o: &RunOptions) -> sda_core::Result<Vec<Finding>> {
                Ok(Vec::new())
            }
        }

        let d = scratch("quiet-with-coverage");
        let t = c_target(&d, "int main(void){ int *p = 0; return p == 0; }\n");

        // An observation, as `--coverage` would supply one.
        let mut obs = crate::dynamic::Observation::default();
        obs.coverage.insert(("main.c".to_string(), 1), 3);

        let mut registry = default_registry();
        registry.register(std::sync::Arc::new(QuietWithCoverage));
        let report = analyze(
            &registry,
            &t,
            &RunConfig::default().with_external().with_observation(obs),
        );

        let named = report
            .exclusions
            .iter()
            .find(|e| e.reason.contains("ext.quiet2"))
            .expect("the tool that executed the program must be named, coverage or not");
        assert!(
            named.reason.contains("not a clean bill of health"),
            "and a quiet run must not read as verification: {}",
            named.reason
        );
        fs::remove_dir_all(&d).ok();
    }

    /// A provider that ran, found things, and said its analysis was degraded
    /// must have the second half reach the report.
    ///
    /// This is the seam that drifts. `run::analyze` is the one place the CLI,
    /// the workbench and both MCP tools share, and a notice collected anywhere
    /// else would be visible on one surface and missing on the others — which is
    /// what `mcp_paths_agree.rs` exists about, one layer down. Found by running
    /// real cppcheck 2.21.0 over 184 files of llama.cpp: it said 321 times that
    /// it could not resolve an include or had checked 12 of 17 preprocessor
    /// configurations, all of it `information` severity among 1,453 findings,
    /// and *NOT CHECKED* was empty.
    #[test]
    fn what_a_provider_could_not_check_reaches_the_report() {
        use sda_core::{
            Analyzer, AnalyzerKind, Availability, Capability, Exclusion, Finding, ProviderInfo,
            ProviderOrigin,
        };

        struct Degraded;
        impl Analyzer for Degraded {
            fn info(&self) -> ProviderInfo {
                ProviderInfo {
                    id: "ext.degraded".into(),
                    name: "degraded".into(),
                    origin: ProviderOrigin::External,
                    kind: AnalyzerKind::Static,
                    languages: vec![Language::C],
                    capabilities: vec![Capability::StyleCompliance],
                    description: "ran, but on incomplete information".into(),
                    executable: None,
                    url: None,
                    requires_build: false,
                }
            }
            fn available(&self) -> Availability {
                Availability::Available
            }
            fn analyze(&self, _t: &Target, _o: &RunOptions) -> sda_core::Result<Vec<Finding>> {
                Ok(Vec::new())
            }
            fn take_notices(&self) -> Vec<Exclusion> {
                vec![Exclusion {
                    provider: "ext.degraded".into(),
                    reason: "`missingIncludeSystem` × 230: could not resolve these includes".into(),
                }]
            }
        }

        let d = scratch("provider-notices");
        let t = c_target(&d, "int main(void){return 0;}
");

        let mut registry = default_registry();
        registry.register(std::sync::Arc::new(Degraded));
        let report = analyze(&registry, &t, &RunConfig::default().with_external());

        let note = report
            .exclusions
            .iter()
            .find(|e| e.provider.as_str() == "ext.degraded")
            .expect("a provider's account of what it could not check must reach the report");
        assert!(
            note.reason.contains("230"),
            "and must keep the count, which is what makes it unmissable: {}",
            note.reason
        );
        fs::remove_dir_all(&d).ok();
    }

    /// A dynamic tool that ran and found nothing has told us something, and the
    /// report used to call that run "static-only" without naming the tool at
    /// all. Found by driving real Memcheck against a program whose leak had been
    /// fixed: Valgrind executed it, reported clean, and the report read as
    /// though no dynamic tool had been enabled.
    #[test]
    fn a_dynamic_tool_that_found_nothing_is_not_a_static_only_run() {
        use sda_core::{
            Analyzer, AnalyzerKind, Availability, Capability, Finding, ProviderInfo,
            ProviderOrigin,
        };

        struct QuietButPresent;
        impl Analyzer for QuietButPresent {
            fn info(&self) -> ProviderInfo {
                ProviderInfo {
                    id: "ext.quiet".into(),
                    name: "quiet".into(),
                    origin: ProviderOrigin::External,
                    kind: AnalyzerKind::Dynamic,
                    languages: vec![Language::C],
                    capabilities: vec![Capability::MemorySafety],
                    description: "runs the program and finds nothing".into(),
                    executable: None,
                    url: None,
                    requires_build: false,
                }
            }
            fn available(&self) -> Availability {
                Availability::Available
            }
            fn analyze(&self, _t: &Target, _o: &RunOptions) -> sda_core::Result<Vec<Finding>> {
                Ok(Vec::new())
            }
        }

        let d = scratch("quietdyn");
        let mut registry = Registry::new();
        registry.register(std::sync::Arc::new(QuietButPresent));
        let mut config = RunConfig::default();
        config.selection = config.selection.enable("ext.quiet");
        let report = analyze(&registry, &Target::new(&d), &config);

        // Two claims, and they are carried by different notices now: *which*
        // tool executed the program, and what correlation could do with that.
        // The invariant is that both reach the report — asserting on one
        // provider id made this fail when the first moved, which is a test
        // pinning an implementation rather than a property.
        let named = report
            .exclusions
            .iter()
            .find(|e| e.reason.contains("ext.quiet"))
            .expect("the tool that ran must be named");
        assert!(
            named.reason.contains("not a clean bill of health"),
            "and a quiet dynamic tool must not read as verification: {}",
            named.reason
        );

        let note = report
            .exclusions
            .iter()
            .find(|e| e.provider.as_str() == "sda.correlate")
            .expect("correlation must account for itself either way");
        assert!(
            !note.reason.contains("static-only"),
            "a run that executed the program is not static-only: {}",
            note.reason
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_static_only_run_says_so_instead_of_implying_verification() {
        let d = scratch("staticonly");
        let t = c_target(&d, "int f(void) { return 0; }\n");
        let report = analyze(&default_registry(), &t, &RunConfig::default());
        assert!(
            report
                .exclusions
                .iter()
                .any(|e| e.reason.contains("static-only")),
            "a report with no dynamic evidence must admit it"
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn deviations_suppress_findings_and_rejected_ones_are_reported() {
        let d = scratch("deviations");
        let t = c_target(&d, "int f(int a) {\n  if (a) return 1;\n  return 0;\n}\n");

        let reg = DeviationRegister::parse(
            "[[deviation]]\nrule = \"MISRA-C-2023-15.6\"\nscope = \"project\"\n\
             rationale = \"legacy driver, scheduled for rewrite in Q4\"\napprover = \"a.erickson\"\n\
             \n[[deviation]]\nrule = \"MISRA-C-2023-9.1\"\nscope = \"project\"\n\
             rationale = \"inconvenient\"\napprover = \"a.erickson\"\n",
        )
        .unwrap();

        let config = RunConfig::default().with_deviations(reg);
        let report = analyze(&default_registry(), &t, &config);

        assert!(report.summary.suppressed > 0, "the approved deviation must take effect");
        assert!(
            report.exclusions.iter().any(|e| e.reason.contains("Mandatory")),
            "the rejected Mandatory deviation must be visible in the report"
        );
        fs::remove_dir_all(&d).ok();
    }

    /// A lapsed acceptance stops hiding its finding, and the run says why.
    ///
    /// `DeviationRegister` knew how to answer `is_expired` and `expired()` from
    /// the beginning, and both were unit-tested. Neither was ever called: `apply`
    /// matched on rule and scope alone, so an acceptance that expired in 2020
    /// went on suppressing in 2026 — while the field's own documentation said it
    /// "no longer applies". This is the wiring, which is the part that was
    /// missing.
    #[test]
    fn an_expired_deviation_stops_suppressing_and_the_run_explains_itself() {
        let d = scratch("expired-deviation");
        let t = c_target(&d, "int f(int a) {\n  if (a) return 1;\n  return 0;\n}\n");

        let live = |expires: &str| {
            DeviationRegister::parse(&format!(
                "[[deviation]]\nrule = \"MISRA-C-2023-15.6\"\nscope = \"project\"\n\
                 expires = \"{expires}\"\n\
                 rationale = \"legacy driver, scheduled for rewrite\"\napprover = \"a.erickson\"\n"
            ))
            .unwrap()
        };

        let current =
            analyze(&default_registry(), &t, &RunConfig::default().with_deviations(live("2999-01-01")));
        assert!(current.summary.suppressed > 0, "an unexpired record still suppresses");

        let lapsed =
            analyze(&default_registry(), &t, &RunConfig::default().with_deviations(live("2000-01-01")));
        assert_eq!(
            lapsed.summary.suppressed, 0,
            "an expired record suppressed a finding, which is the defect this test exists for"
        );
        assert!(
            lapsed.exclusions.iter().any(|e| e.reason.contains("expired on 2000-01-01")),
            "a finding reappearing because an acceptance lapsed must be explained, or it \
             reads as an unexplained regression: {:?}",
            lapsed.exclusions.iter().map(|e| &e.reason).collect::<Vec<_>>()
        );
        fs::remove_dir_all(&d).ok();
    }

    /// An unused record is reported — but only when this run could have matched it.
    ///
    /// The first version of the notice had neither guard, and a scan of `crates`
    /// duly announced all six `shim/sda_probe.h` records as dead weight. They
    /// were about a file that scan never opened. A notice that reports an
    /// absence of evidence as evidence of absence is this codebase's cardinal
    /// error, printed by the very section that exists to prevent it.
    #[test]
    fn an_unused_deviation_is_reported_only_when_the_run_could_have_matched_it() {
        let d = scratch("unused-deviation");
        let t = c_target(&d, "int f(int a) {\n  if (a) return 1;\n  return 0;\n}\n");

        // Names a file this run never read.
        let elsewhere = DeviationRegister::parse(
            "[[deviation]]\nrule = \"MISRA-C-2023-15.6\"\nscope = \"file\"\n\
             path = \"not/in/this/scan.c\"\n\
             rationale = \"about another file entirely\"\napprover = \"a.erickson\"\n",
        )
        .unwrap();
        let report =
            analyze(&default_registry(), &t, &RunConfig::default().with_deviations(elsewhere));
        assert!(
            !report.exclusions.iter().any(|e| e.reason.contains("matched no finding")),
            "a record about an unscanned file is not dead weight: {:?}",
            report.exclusions.iter().map(|e| &e.reason).collect::<Vec<_>>()
        );

        // Names a rule that cannot fire on a file this run *did* read.
        let here = DeviationRegister::parse(
            "[[deviation]]\nrule = \"MISRA-C-2023-17.2\"\nscope = \"project\"\n\
             rationale = \"no recursion here, so nothing to suppress\"\napprover = \"a.erickson\"\n",
        )
        .unwrap();
        let report = analyze(&default_registry(), &t, &RunConfig::default().with_deviations(here));
        assert!(
            report.exclusions.iter().any(|e| e.reason.contains("matched no finding")),
            "a record covering nothing, in files this run read, is worth retiring: {:?}",
            report.exclusions.iter().map(|e| &e.reason).collect::<Vec<_>>()
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn gate_reports_why_it_passed_or_failed() {
        let d = scratch("gate");
        let t = c_target(&d, "int f(void) { return 0; }\n");
        let report = analyze(&default_registry(), &t, &RunConfig::default());
        let (outcome, why) = gate(&report, Severity::Critical);
        assert_eq!(outcome, Gate::Pass);
        assert!(why.contains("static-only"), "a passing static-only gate must not read as verified");
        fs::remove_dir_all(&d).ok();
    }

    /// The third outcome, at the level the CLI reads it from.
    ///
    /// `Pass` and `Fail` were the whole vocabulary, so a scan that read nothing
    /// had to be one of them, and it was `Pass`. The CLI test beside this one
    /// covers the exit code; this covers the distinction the exit code is made
    /// of, so the two cannot drift apart.
    #[test]
    fn a_gate_over_a_scan_that_read_nothing_gives_no_verdict() {
        let d = scratch("gate-nothing");
        fs::write(d.join("notes.txt"), "not source\n").unwrap();
        let t = crate::discover::discover(&d, &crate::discover::DiscoveryOptions::default());

        let report = analyze(&default_registry(), &t, &RunConfig::default());
        let (outcome, why) = gate(&report, Severity::Critical);

        assert_eq!(
            outcome,
            Gate::NotChecked,
            "nothing here is readable, so there is no verdict to give: {why}"
        );
        assert!(outcome.should_stop(), "a gate that could not run has not been passed");
        assert!(
            !why.contains("no findings at or above"),
            "that sentence is about code, and none was read: {why}"
        );
        fs::remove_dir_all(&d).ok();
    }


    /// The two gates agree about stopping, in all three cases.
    ///
    /// `Report::fails_gate` lives in `sda-core` and `run::gate` in
    /// `sda-engine`, which depends on it -- so the predicate cannot be shared
    /// and has to be duplicated. `HANDOFF.md` recorded them as a harmless
    /// duplicate because *the two agree*, which was true when both were
    /// `count > 0` and stopped being true the moment one of them learned that
    /// a scan which read nothing has no verdict to give.
    ///
    /// A duplicate is only harmless while something compares the copies.
    #[test]
    fn the_two_gates_agree_about_stopping() {
        let d = scratch("two-gates");
        std::fs::write(d.join("notes.txt"), "not source
").unwrap();

        // Read nothing: both must stop.
        let t = crate::discover::discover(&d, &crate::discover::DiscoveryOptions::default());
        let nothing = analyze(&default_registry(), &t, &RunConfig::default());
        assert_eq!(
            gate(&nothing, Severity::Critical).0.should_stop(),
            nothing.fails_gate(Severity::Critical),
            "a scan that read nothing stops both gates or neither"
        );
        assert!(nothing.fails_gate(Severity::Critical), "and the answer is that it stops");

        // Read something, nothing severe: both must continue.
        let clean = analyze(
            &default_registry(),
            &c_target(&d, "int32_t f(int32_t x) { return x; }
"),
            &RunConfig::default(),
        );
        assert_eq!(
            gate(&clean, Severity::Critical).0.should_stop(),
            clean.fails_gate(Severity::Critical),
            "a measured clean run stops neither"
        );
        assert!(!clean.fails_gate(Severity::Critical), "and the answer is that it passes");

        // Read something, and it has findings: both must stop.
        let dirty = analyze(
            &default_registry(),
            &c_target(&d, "int f(int x) {
  if (x) { goto d; }
  return 0;
d:
  return 1;
}
"),
            &RunConfig::default(),
        );
        assert_eq!(
            gate(&dirty, Severity::Low).0.should_stop(),
            dirty.fails_gate(Severity::Low),
            "findings stop both"
        );
        assert!(dirty.fails_gate(Severity::Low), "and the answer is that it stops");

        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn triage_puts_runtime_confirmed_findings_first() {
        let d = scratch("triage");
        let t = c_target(&d, "int f(int a) {\n  if (a) return 1;\n  return 0;\n}\n");

        let obs = crate::dynamic::parse_probe_stream(
            &format!(
                "{{\"t\":\"fault\",\"f\":\"{}\",\"l\":2,\"k\":\"bounds\",\"m\":\"oob\"}}\n",
                "main.c"
            ),
            "r1",
        );
        let config = RunConfig::default().with_observation(obs);
        let report = analyze(&default_registry(), &t, &config);

        // The findings on that line are style guidelines — an unbraced `if`, a
        // second exit point — and a bounds fault is not those coming true. So
        // nothing is confirmed, and the fault is reported as `unpredicted`: a
        // gap in the rule set rather than a vindicated suspicion.
        assert!(
            report.confirmed().is_empty(),
            "a bounds fault must not confirm unrelated style guidelines"
        );

        let order = triage_order(&report);
        assert!(
            order[0].has_runtime_evidence(),
            "the observed defect is still what a human should see first"
        );
        assert_eq!(order[0].severity, Severity::Critical);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_provider_error_becomes_an_exclusion_not_a_clean_result() {
        // This used to point the real C provider at a file that does not exist,
        // which failed the whole provider. That is no longer how a missing file
        // behaves — it is skipped and named, per file, so the analysis of every
        // other file survives, which is what
        // `an_unreadable_file_does_not_discard_the_others.rs` covers.
        //
        // The path this test is *about* — a provider that genuinely fails — was
        // left with no coverage by that change, because no stub in this module
        // returns `Err`. So it gets one.
        use sda_core::{
            Analyzer, AnalyzerKind, Availability, Capability, Finding, ProviderInfo,
            ProviderOrigin,
        };

        struct Failing;
        impl Analyzer for Failing {
            fn info(&self) -> ProviderInfo {
                ProviderInfo {
                    id: "ext.failing".into(),
                    name: "failing".into(),
                    origin: ProviderOrigin::External,
                    kind: AnalyzerKind::Static,
                    languages: vec![Language::C],
                    capabilities: vec![Capability::MemorySafety],
                    description: "a tool that cannot run here".into(),
                    executable: None,
                    url: None,
                    requires_build: false,
                }
            }
            fn available(&self) -> Availability {
                Availability::Available
            }
            fn analyze(&self, _t: &Target, _o: &RunOptions) -> sda_core::Result<Vec<Finding>> {
                Err(sda_core::Error::io(
                    "the tool".to_string(),
                    std::io::Error::other("it fell over"),
                ))
            }
        }

        let d = scratch("provider-error");
        let mut registry = Registry::new();
        registry.register(std::sync::Arc::new(Failing));
        let mut config = RunConfig::default();
        config.selection = config.selection.enable("ext.failing");

        let report = analyze(&registry, &Target::new(&d), &config);
        assert!(
            report.exclusions.iter().any(|e| e.reason.contains("provider failed")),
            "a provider that fails must not look like one that found nothing: {:?}",
            report.exclusions
        );
        fs::remove_dir_all(&d).ok();
    }
}
