//! The deterministic planner.
//!
//! Given what a project contains and what is installed, decide what to run and
//! in what order — and, just as importantly, say what will *not* be covered.
//!
//! Deterministic on purpose. An agent can revise this plan, but the baseline is
//! reproducible: the same project on the same machine yields the same plan, so a
//! compliance run can be repeated and a difference in results means a difference
//! in the code rather than in the model's mood that morning.

use sda_core::{Language, Target};
use sda_ontology::Ontology;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// One thing to do.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Step {
    pub order: u32,
    /// Provider id or a build action.
    pub action: String,
    /// Why this step is in the plan — written for a human reading the plan.
    pub rationale: String,
    /// What has to exist first: an earlier step, or something only the operator
    /// can provide. Stated to the reader, not enforced; `blocked` is the check.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// Whether this step needs a tool that is not installed.
    #[serde(default)]
    pub blocked: bool,
}

/// Something the plan will not establish, and why.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Gap {
    pub what: String,
    pub why: String,
    /// What the operator could do to close it.
    pub remedy: String,
}

/// The plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub target: String,
    pub languages: Vec<Language>,
    pub steps: Vec<Step>,
    /// What this plan cannot cover. Never omitted.
    pub gaps: Vec<Gap>,
}

impl Plan {
    pub fn runnable(&self) -> impl Iterator<Item = &Step> {
        self.steps.iter().filter(|s| !s.blocked)
    }

    /// Record the files the declared scope removed, as things this plan will
    /// not cover.
    ///
    /// Scope has to be applied *before* planning — a plan built over files the
    /// scan will not read proposes work on nothing, and the CLI copy of this
    /// command did exactly that: on a project excluding `legacy/`, whose only
    /// C++ lived there, it promised `Languages: c, cpp` and a `sda.static.cpp`
    /// step that the scan would never run.
    ///
    /// Applying it silently is the other half. A plan narrower than the tree it
    /// names, with nothing saying why, is a plan a reader will compare against
    /// their own directory listing and mistrust. `Not covered by this plan` is
    /// exactly where that belongs, and the rule's reason and approver are
    /// already carried in the notice.
    pub fn noting_scope(mut self, notices: &[sda_core::Exclusion]) -> Self {
        for n in notices.iter().filter(|n| n.provider.as_str() == "sda.scope") {
            self.gaps.push(Gap {
                what: "files outside the declared analysis scope".into(),
                why: n.reason.clone(),
                remedy: "nothing, if the exclusion is still right. It is declared in \
                         `.sda/scope.toml` with a reason and an approver; remove the rule \
                         there to bring these files back into every command at once"
                    .into(),
            });
        }
        self
    }

    /// A plain-language rendering, which is what an agent or a human actually reads.
    pub fn render(&self) -> String {
        let mut s = format!("Plan for {}\n", self.target);
        let langs: Vec<&str> = self.languages.iter().map(|l| l.as_str()).collect();
        // `Languages: ` with nothing after the colon is a blank where an answer
        // goes, and a blank reads as a rendering fault rather than as a result.
        // Say which of the two it is.
        let shown = if langs.is_empty() { "none recognised".to_string() } else { langs.join(", ") };
        s.push_str(&format!("Languages: {shown}\n\n"));

        s.push_str("Steps:\n");
        // An empty plan has to say it is empty.
        //
        // `Steps:` followed by nothing reads as *there is nothing to do*, and
        // the truth is *nothing here can be done*. Measured on a directory of
        // `.md` and `.txt`: the header printed, no step followed, and the only
        // thing under `Not covered` was a remark about runtime evidence — a
        // caveat about a different subject entirely. An agent calling
        // `plan.create` reads this same text and has no other signal.
        if self.steps.is_empty() {
            // Two sentences, not one sentence with a hole in it. The hole took a
            // noun phrase — `the language(s) found here (json, txt)` — and the
            // empty case filled it with a clause, so the message that exists to
            // stop an empty plan being misread printed as *No analysis step
            // applies to no recognised language was found*. A garbled sentence
            // does not get read carefully, and this is the one sentence here
            // that has to be.
            s.push_str(&if langs.is_empty() {
                "  none. No recognised language was found here, so no analysis step applies \
                 and this plan would check nothing. That is a fact about what can run here, \
                 not about the code\n"
                    .to_string()
            } else {
                format!(
                    "  none. No analysis step applies to the language(s) found here ({}), so \
                     this plan would check nothing. That is a fact about what can run here, \
                     not about the code\n",
                    langs.join(", ")
                )
            });
        }
        for step in &self.steps {
            let mark = if step.blocked { "[blocked]" } else { "" };
            s.push_str(&format!("  {}. {} {mark}\n     {}\n", step.order, step.action, step.rationale));
            if !step.requires.is_empty() {
                s.push_str(&format!("     needs: {}\n", step.requires.join(", ")));
            }
        }
        if !self.gaps.is_empty() {
            s.push_str("\nNot covered by this plan:\n");
            for g in &self.gaps {
                s.push_str(&format!("  - {}: {}\n    Remedy: {}\n", g.what, g.why, g.remedy));
            }
        }
        s
    }
}

/// What the planner is allowed to assume.
#[derive(Clone, Debug, Default)]
pub struct PlanInputs {
    /// Provider ids that are installed and usable.
    pub available: BTreeSet<String>,
    /// Whether external tools may be used at all.
    pub allow_external: bool,
    /// Whether a built artifact exists for dynamic analysis.
    pub has_artifact: bool,
    /// Whether a compilation database exists.
    pub has_compile_commands: bool,
    /// Standards the project must comply with.
    pub standards: Vec<sda_rules::Standard>,
}

/// Build a plan for `target`.
pub fn plan(target: &Target, inputs: &PlanInputs) -> Plan {
    let ontology = Ontology::load();
    let languages = target.languages();
    let mut steps = Vec::new();
    let mut gaps = Vec::new();
    let mut order = 1u32;

    // 1. Native static analysis always leads: it needs nothing and runs in
    //    milliseconds, so there is never a reason to defer it.
    for lang in &languages {
        let provider = match lang {
            Language::C => "sda.static.c",
            Language::Cpp => "sda.static.cpp",
            Language::Rust => "sda.static.rust",
            Language::ModelArtifact => "sda.ai.artifact",
            _ => continue,
        };
        steps.push(Step {
            order,
            action: provider.into(),
            rationale: format!(
                "Native {} analysis. No build, no configuration, no external dependency; this is \
                 the baseline every other step is compared against.",
                lang.as_str()
            ),
            requires: Vec::new(),
            blocked: false,
        });
        order += 1;
    }

    // 2. Semantics-level checks need a compilation database.
    let has_c_family = languages.iter().any(|l| matches!(l, Language::C | Language::Cpp));
    if has_c_family {
        if inputs.has_compile_commands && inputs.allow_external {
            steps.push(Step {
                order,
                action: "ext.clang-tidy".into(),
                rationale: "A compilation database is present, so type-aware checks can run. This \
                            is the route for guidelines the native engine records as needing \
                            semantics."
                    .into(),
                requires: vec!["compile_commands.json".into()],
                blocked: !inputs.available.contains("ext.clang-tidy"),
            });
            order += 1;
        } else {
            let n = sda_rules::Catalog::load(sda_rules::Standard::MisraC2023)
                .by_coverage(sda_rules::Coverage::Semantics)
                .len();
            gaps.push(Gap {
                what: format!("{n} MISRA C guidelines requiring type information"),
                why: if !inputs.has_compile_commands {
                    "no compile_commands.json, so no tool can resolve types".into()
                } else {
                    "external tools are disabled, and no native provider resolves types".into()
                },
                // Telling someone to produce a database they already have is
                // advice they will follow and learn nothing from; name only the
                // step actually outstanding.
                remedy: if inputs.has_compile_commands {
                    "a compilation database is already present; enable a type-aware provider \
                     (`--with ext.clang-tidy`)"
                        .into()
                } else {
                    "generate a compilation database (`sda build compile-commands`) and \
                     enable a type-aware provider (`--with ext.clang-tidy`)"
                        .to_string()
                },
            });
        }
    }

    // 3. Dynamic analysis, which is what makes the run statodynamic at all.
    if inputs.has_artifact {
        steps.push(Step {
            order,
            action: "sda.dynamic".into(),
            rationale: "Execute the built artifact under the native dynamic engine to collect \
                        coverage and runtime faults. Without this the run is static-only and no \
                        finding can be confirmed or refuted."
                .into(),
            requires: vec!["built artifact".into()],
            blocked: false,
        });
        order += 1;
        steps.push(Step {
            order,
            action: "sda.correlate".into(),
            rationale: "Correlate static findings against runtime evidence: confirm what \
                        happened, refute what repeatedly did not, and flag what never executed."
                .into(),
            requires: vec!["sda.dynamic".into()],
            blocked: false,
        });
        order += 1;
    } else {
        gaps.push(Gap {
            what: "all runtime evidence".into(),
            why: "no built artifact was supplied, so nothing was executed. Every static finding \
                  in this run is unconfirmed, and no statement can be made about which code paths \
                  are exercised"
                .into(),
            remedy: "build the target with `sda build compile --profile dynamic` and re-run with \
                     `--artifact <path>`"
                .into(),
        });
    }

    // 4. AI model artifacts.
    if languages.contains(&Language::ModelArtifact) {
        steps.push(Step {
            order,
            action: "sda.ai.probe".into(),
            rationale: "Model artifacts are present. The container scan establishes what loading \
                        them does; only a probe campaign can say anything about what the weights \
                        do."
                .into(),
            requires: vec!["sda.ai.artifact".into(), "a running inference endpoint".into()],
            blocked: !inputs.available.contains("sda.ai.probe"),
        });

        gaps.push(Gap {
            what: "backdoor and sleeper-agent absence".into(),
            why: "no probe campaign can establish absence: the space of possible triggers is \
                  unbounded, and a model trained to conceal a behaviour conceals it from probes too"
                .into(),
            remedy: "treat model provenance as the primary control — signed weights from a known \
                     producer, with a recorded digest — and use probing as a filter, not a proof"
                .into(),
        });
    }

    // 5. Capability gaps from the ontology.
    for lang in &languages {
        if !lang.natively_supported() && *lang != Language::ModelArtifact {
            continue;
        }
        let available = if inputs.allow_external {
            inputs.available.clone()
        } else {
            inputs.available.iter().filter(|id| id.starts_with("sda.")).cloned().collect()
        };
        for cap in ontology.gaps(lang, &available) {
            // Only report gaps something could actually fill.
            let candidates = ontology.recommend(cap, lang);
            if candidates.is_empty() {
                continue;
            }
            let names: Vec<&str> = candidates.iter().take(3).map(|t| t.id.as_str()).collect();
            gaps.push(Gap {
                what: format!("{} for {}", cap.as_str(), lang.as_str()),
                why: "no available provider offers this capability".into(),
                remedy: format!("install and enable one of: {}", names.join(", ")),
            });
        }
    }

    Plan { target: target.root.to_string_lossy().to_string(), languages, steps, gaps }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::TargetFile;

    fn target(langs: &[Language]) -> Target {
        Target::new("/proj").with_files(
            langs
                .iter()
                .enumerate()
                .map(|(i, l)| TargetFile {
                    path: format!("/proj/f{i}").into(),
                    language: l.clone(),
                    bytes: 1,
                })
                .collect(),
        )
    }

    fn native_available() -> BTreeSet<String> {
        ["sda.static.c", "sda.static.cpp", "sda.static.rust", "sda.ai.artifact", "sda.dynamic"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    #[test]
    fn native_static_analysis_always_leads_the_plan() {
        let p = plan(&target(&[Language::C]), &PlanInputs::default());
        assert_eq!(p.steps[0].action, "sda.static.c");
        assert!(!p.steps[0].blocked);
        assert!(p.steps[0].requires.is_empty(), "the first step must need nothing");
    }

    #[test]
    fn a_plan_without_an_artifact_states_that_nothing_was_executed() {
        let p = plan(&target(&[Language::C]), &PlanInputs::default());
        let gap = p.gaps.iter().find(|g| g.what.contains("runtime evidence")).unwrap();
        assert!(gap.why.contains("unconfirmed"));
        assert!(gap.remedy.contains("--artifact"));
        assert!(gap.remedy.contains("sda build compile --profile dynamic"), "{}", gap.remedy);
    }

    #[test]
    fn supplying_an_artifact_adds_the_dynamic_and_correlation_steps() {
        let inputs = PlanInputs {
            has_artifact: true,
            available: native_available(),
            ..Default::default()
        };
        let p = plan(&target(&[Language::C]), &inputs);
        let actions: Vec<&str> = p.steps.iter().map(|s| s.action.as_str()).collect();
        assert!(actions.contains(&"sda.dynamic"));
        assert!(actions.contains(&"sda.correlate"));
        assert!(!p.gaps.iter().any(|g| g.what.contains("runtime evidence")));
    }

    #[test]
    fn correlation_is_ordered_after_the_dynamic_run_that_feeds_it() {
        let inputs = PlanInputs { has_artifact: true, ..Default::default() };
        let p = plan(&target(&[Language::C]), &inputs);
        let dynamic = p.steps.iter().find(|s| s.action == "sda.dynamic").unwrap();
        let corr = p.steps.iter().find(|s| s.action == "sda.correlate").unwrap();
        assert!(corr.order > dynamic.order);
        assert!(corr.requires.contains(&"sda.dynamic".to_string()));
    }

    /// `render` is the only form an agent or a person receives, and a running
    /// inference endpoint is something only the operator can provide.
    #[test]
    fn the_rendered_plan_says_what_a_step_needs() {
        let p = plan(&target(&[Language::ModelArtifact]), &PlanInputs::default());
        let text = p.render();
        assert!(text.contains("needs: sda.ai.artifact, a running inference endpoint"), "{text}");
        let leading = p.steps.iter().find(|s| s.requires.is_empty()).unwrap();
        assert!(
            !text.contains(&format!("{}\n     needs:", leading.action)),
            "a step that needs nothing prints no empty line for it: {text}"
        );
    }

    /// The remedy must name the step actually outstanding. A project that had
    /// just run `sda build compile-commands` was still being told to generate a
    /// compilation database.
    #[test]
    fn the_remedy_does_not_ask_for_a_database_that_already_exists() {
        let semantics = |p: &Plan| -> String {
            p.gaps
                .iter()
                .find(|g| g.what.contains("type information"))
                .map(|g| g.remedy.clone())
                .expect("the semantics gap must be reported")
        };

        let without = plan(&target(&[Language::C]), &PlanInputs::default());
        assert!(semantics(&without).contains("sda build compile-commands"));

        let with = plan(
            &target(&[Language::C]),
            &PlanInputs { has_compile_commands: true, ..Default::default() },
        );
        let r = semantics(&with);
        assert!(r.contains("already present"), "got: {r}");
        assert!(
            !r.contains("sda build compile-commands"),
            "it must not ask for work already done: {r}"
        );
    }

    #[test]
    fn missing_compile_commands_is_reported_with_the_guideline_count_at_stake() {
        let p = plan(&target(&[Language::C]), &PlanInputs::default());
        let gap = p.gaps.iter().find(|g| g.what.contains("type information")).unwrap();
        assert!(gap.what.chars().next().unwrap().is_ascii_digit(), "state how many: {}", gap.what);
        assert!(gap.remedy.contains("compile-commands"));
    }

    #[test]
    fn a_type_aware_step_appears_once_a_database_and_externals_are_allowed() {
        let inputs = PlanInputs {
            has_compile_commands: true,
            allow_external: true,
            available: ["ext.clang-tidy".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let p = plan(&target(&[Language::C]), &inputs);
        let step = p.steps.iter().find(|s| s.action == "ext.clang-tidy").unwrap();
        assert!(!step.blocked);
    }

    #[test]
    fn an_uninstalled_tool_appears_as_blocked_rather_than_vanishing() {
        let inputs = PlanInputs {
            has_compile_commands: true,
            allow_external: true,
            available: BTreeSet::new(),
            ..Default::default()
        };
        let p = plan(&target(&[Language::C]), &inputs);
        let step = p.steps.iter().find(|s| s.action == "ext.clang-tidy").unwrap();
        assert!(step.blocked);
        assert_eq!(p.runnable().count(), p.steps.len() - 1);
    }

    #[test]
    fn model_artifacts_add_probing_and_an_honest_statement_about_backdoors() {
        let p = plan(&target(&[Language::ModelArtifact]), &PlanInputs::default());
        assert!(p.steps.iter().any(|s| s.action == "sda.ai.artifact"));
        let gap = p.gaps.iter().find(|g| g.what.contains("sleeper-agent")).unwrap();
        assert!(gap.why.contains("unbounded"));
        assert!(gap.remedy.contains("provenance"));
    }

    #[test]
    fn a_mixed_project_plans_every_language() {
        let p = plan(&target(&[Language::C, Language::Rust, Language::ModelArtifact]), &PlanInputs::default());
        let actions: Vec<&str> = p.steps.iter().map(|s| s.action.as_str()).collect();
        assert!(actions.contains(&"sda.static.c"));
        assert!(actions.contains(&"sda.static.rust"));
        assert!(actions.contains(&"sda.ai.artifact"));
    }

    #[test]
    fn capability_gaps_name_a_specific_remedy() {
        let p = plan(&target(&[Language::C]), &PlanInputs::default());
        let fuzz = p.gaps.iter().find(|g| g.what.starts_with("fuzzing"));
        assert!(fuzz.is_some(), "fuzzing is uncovered with no tools installed");
        assert!(fuzz.unwrap().remedy.contains("ext."));
    }

    #[test]
    fn the_rendered_plan_shows_steps_and_gaps() {
        let text = plan(&target(&[Language::C]), &PlanInputs::default()).render();
        assert!(text.contains("Steps:"));
        assert!(text.contains("Not covered by this plan:"));
        assert!(text.contains("Remedy:"));
    }

    /// A plan with no steps says so, rather than printing a bare header.
    ///
    /// `Steps:` followed by nothing reads as "there is nothing to do"; the truth
    /// is "nothing here can be done". Measured on a directory of `.md` and
    /// `.txt`, where the only thing under `Not covered` was a remark about
    /// runtime evidence — a caveat about a different subject.
    #[test]
    fn an_empty_plan_says_why_it_is_empty() {
        let plan = Plan {
            target: "/p".into(),
            languages: vec![Language::Other("md".into())],
            steps: Vec::new(),
            gaps: Vec::new(),
        };
        let text = plan.render();

        assert!(
            text.contains("No analysis step applies"),
            "an empty step list has to be stated, not inferred: {text}"
        );
        assert!(
            text.contains("not about the code"),
            "and the direction of the statement is the point: {text}"
        );
    }

    /// And the same plan with *no* languages at all, which is the branch that
    /// was broken and the branch nothing rendered.
    ///
    /// `an_empty_plan_says_why_it_is_empty` builds its fixture with one
    /// language, so it only ever took the other path. The zero-language path
    /// filled a noun-phrase slot — `the language(s) found here (json, txt)` —
    /// with a clause, and printed:
    ///
    /// > No analysis step applies to no recognised language was found, so this
    /// > plan would check nothing
    ///
    /// which is the sentence whose entire job is to stop an empty plan being
    /// read as a clean one. A garbled sentence does not get read carefully.
    /// Reached by `sda plan` on a path that does not exist, and equally by any
    /// directory holding nothing with an extension.
    #[test]
    fn a_plan_for_no_languages_at_all_still_forms_a_sentence() {
        let plan = Plan {
            target: "/p".into(),
            languages: Vec::new(),
            steps: Vec::new(),
            gaps: Vec::new(),
        };
        let text = plan.render();

        assert!(
            !text.contains("applies to no recognised language was found"),
            "two clauses spliced into one slot; this is the defect: {text}"
        );
        assert!(
            text.contains("No recognised language was found here, so no analysis step applies"),
            "the empty case needs its own sentence, not a hole in the other one: {text}"
        );
        assert!(
            text.contains("not about the code"),
            "and the direction of the statement survives the rewrite: {text}"
        );
        // A label with nothing after it reads as a rendering fault rather than
        // as the answer it is.
        assert!(
            text.contains("Languages: none recognised"),
            "an empty list has to say it is empty: {text}"
        );
        assert!(
            !text.contains("Languages: \n"),
            "a blank after the colon says nothing about which of the two happened: {text}"
        );
    }

    /// A plan with steps does not carry that line.
    #[test]
    fn a_plan_with_steps_does_not_explain_an_emptiness_it_does_not_have() {
        let plan = Plan {
            target: "/p".into(),
            languages: vec![Language::C],
            steps: vec![Step {
                order: 1,
                action: "sda.static.c".into(),
                rationale: "native C analysis".into(),
                requires: Vec::new(),
                blocked: false,
            }],
            gaps: Vec::new(),
        };
        assert!(
            !plan.render().contains("No analysis step applies"),
            "a line that appears on every plan is one people stop reading"
        );
    }

    #[test]
    fn planning_is_deterministic() {
        let t = target(&[Language::C, Language::Rust]);
        let a = plan(&t, &PlanInputs::default());
        let b = plan(&t, &PlanInputs::default());
        assert_eq!(a.render(), b.render());
    }
}

