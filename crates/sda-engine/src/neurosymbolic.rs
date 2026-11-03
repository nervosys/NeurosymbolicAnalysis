//! Adjudicating findings across the symbolic/neural seam.
//!
//! [`correlate`] fuses static suspicion with runtime observation. This module
//! adds the third kind of evidence — proof — and the one structural rule that
//! keeps the three from being averaged into a number nobody can defend.
//!
//! The map of the system is declared, never inferred ([`SystemMap`]): which
//! paths are ordinary code, which are a learned model, which are the environment.
//! Given that map and a [`VerificationLedger`], each static finding gets one of:
//!
//! | where it is | what the ledger says | verdict |
//! |---|---|---|
//! | symbolic | an obligation settling its rule was discharged, soundly | `Proved` |
//! | symbolic | an obligation settling its rule failed | `Confirmed` |
//! | symbolic | an obligation settling its rule rests on a weak assumption | `Assumed` |
//! | neural | nothing; no proof reaches inside the weights | `Assumed` |
//! | anywhere | nothing bearing on it | *untouched*, for [`correlate`] to judge |
//!
//! **The third row is the load-bearing one.** A discharged obligation whose
//! proof was granted an assumption that only a probe campaign supports is not a
//! proof of the system property — it is a proof conditional on something nobody
//! proved. Promoting it to `Proved` would be exactly the averaging that
//! [`sda_core::verification`] exists to prevent, dressed up as rigour: the
//! strongest verdict the toolkit can issue, awarded to a claim resting on
//! evidence that "demonstrates nothing" by its own subsystem's admission. So the
//! soundness of the assumptions is checked transitively, and a proof that cannot
//! pay for its premises is demoted rather than trusted.
//!
//! **Order of operations.** Deduction runs before correlation, and only
//! [`Adjudication::unadjudicated`] is handed on to [`correlate`]. Running both
//! over the same findings and merging the answers would let `Unreached` — "we
//! never tried" — overwrite `Proved` — "there is no such execution" — whenever a
//! proved line also happens to be cold.
//!
//! Findings this module has no opinion about are returned unchanged and without
//! a correlation record. Saying nothing is a real answer here; manufacturing an
//! `Inconclusive` for every unmapped file would bury the ones that mean
//! something.

use sda_core::verification::{
    Boundary, NeuralProfile, ObligationStatus, ProofObligation, VerificationLedger,
};
use sda_core::{Correlation, CorrelationVerdict, Evidence, Finding};

/// What a component is for, where that changes what must be proved about it.
///
/// Separate from [`Boundary`], which says what kind of artifact it is. A guard
/// is symbolic *and* load-bearing; an effector is symbolic *and* the place where
/// being wrong stops being an internal matter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    #[default]
    Ordinary,
    /// Constrains what a model's output is allowed to do. The safety case rests
    /// on these, so [`crate::interposition`] asks whether they can be bypassed.
    Guard,
    /// Where an output leaves the system — an actuator, a payment, a message
    /// sent. A defect that never reaches one of these is contained.
    Effector,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Ordinary => "ordinary",
            Role::Guard => "guard",
            Role::Effector => "effector",
        }
    }
}

/// One named part of the system, and which side of the seam it is on.
#[derive(Clone, Debug)]
pub struct Component {
    /// Matches [`ProofObligation::component`].
    pub name: String,
    /// Path prefix owning this component, matched on segment boundaries.
    pub path: String,
    pub boundary: Boundary,
    /// What kind of network this is, for a neural component.
    ///
    /// Carried rather than a bare parameter count, because size does not decide
    /// what a prover can do: a four-million-parameter CNN is in reach, an MLP of
    /// the same size is not, and a transformer of the same size is a third
    /// answer again. [`NeuralProfile::tractability`] holds that reasoning.
    ///
    /// `None` on a neural component is reported, not assumed away.
    pub profile: Option<NeuralProfile>,
    pub role: Role,
}

impl Component {
    pub fn new(name: impl Into<String>, path: impl Into<String>, boundary: Boundary) -> Self {
        Component {
            name: name.into(),
            path: path.into(),
            boundary,
            profile: None,
            role: Role::Ordinary,
        }
    }
    pub fn symbolic(name: impl Into<String>, path: impl Into<String>) -> Self {
        Component::new(name, path, Boundary::Symbolic)
    }
    pub fn neural(name: impl Into<String>, path: impl Into<String>) -> Self {
        Component::new(name, path, Boundary::Neural)
    }
    /// Mark this component as constraining what a model's output may do.
    pub fn guard(mut self) -> Self {
        self.role = Role::Guard;
        self
    }
    /// Mark this component as a place where output leaves the system.
    pub fn effector(mut self) -> Self {
        self.role = Role::Effector;
        self
    }
    /// Describe a neural component, so the report can say precisely what could
    /// be proved about it and what it would take.
    pub fn profiled(mut self, profile: NeuralProfile) -> Self {
        self.profile = Some(profile);
        self
    }
    /// True when a catalogued tool could actually be run against this component.
    ///
    /// False for an undescribed neural component, which is the honest answer:
    /// nothing can be run against a model whose architecture nobody stated.
    pub fn is_deductively_tractable(&self) -> bool {
        match self.boundary {
            Boundary::Neural => {
                self.profile.as_ref().is_some_and(|p| p.tractability().is_reachable())
            }
            _ => true,
        }
    }

    fn owns(&self, path: &str) -> bool {
        let p = path.replace('\\', "/");
        let prefix = self.path.replace('\\', "/");
        let prefix = prefix.trim_end_matches('/');
        p == prefix || p.starts_with(&format!("{prefix}/"))
    }
}

/// The declared structure of a hybrid system.
///
/// Order matters: the first component owning a path wins, so a specific
/// subdirectory can be declared neural inside an otherwise symbolic tree.
#[derive(Clone, Debug, Default)]
pub struct SystemMap {
    pub components: Vec<Component>,
}

impl SystemMap {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, c: Component) -> Self {
        self.components.push(c);
        self
    }
    pub fn component_for(&self, path: &str) -> Option<&Component> {
        self.components.iter().find(|c| c.owns(path))
    }
    /// Declared component names, for [`VerificationLedger::vacuous`].
    pub fn names(&self) -> Vec<&str> {
        self.components.iter().map(|c| c.name.as_str()).collect()
    }
}

/// Static findings adjudicated against proof, plus what could not be adjudicated.
#[derive(Clone, Debug, Default)]
pub struct Adjudication {
    /// Every input finding, with severity and confidence adjusted where a
    /// verdict was reached.
    pub findings: Vec<Finding>,
    pub correlations: Vec<Correlation>,
    /// Lines for the report's unsuppressible `NOT CHECKED` section.
    pub not_checked: Vec<String>,
}

impl Adjudication {
    pub fn count(&self, v: CorrelationVerdict) -> usize {
        self.correlations.iter().filter(|c| c.verdict == v).count()
    }

    /// Findings this module reached no verdict on — the input to [`correlate`].
    ///
    /// The ordering is not arbitrary. Deduction runs first because it can settle
    /// a finding outright, and running the runtime correlator over an already
    /// proved finding would let a weaker verdict overwrite a stronger one: a
    /// line proved unreachable-by-defect that also happens to be cold would come
    /// back `Unreached`, replacing "this cannot happen" with "we never tried".
    /// Feeding the two engines the same findings and merging their answers is
    /// the averaging failure again, one layer up.
    ///
    /// [`correlate`]: crate::correlate::correlate
    pub fn unadjudicated(&self) -> Vec<Finding> {
        let judged: std::collections::BTreeSet<&str> = self
            .correlations
            .iter()
            .filter_map(|c| c.static_finding.as_ref())
            .map(|i| i.as_str())
            .collect();
        self.findings.iter().filter(|f| !judged.contains(f.id.as_str())).cloned().collect()
    }

    /// Findings a verdict was reached on, already adjusted.
    pub fn adjudicated(&self) -> Vec<Finding> {
        let judged: std::collections::BTreeSet<&str> = self
            .correlations
            .iter()
            .filter_map(|c| c.static_finding.as_ref())
            .map(|i| i.as_str())
            .collect();
        self.findings.iter().filter(|f| judged.contains(f.id.as_str())).cloned().collect()
    }
}

/// Adjudicate `findings` against `ledger`, over the system described by `map`.
pub fn adjudicate(
    findings: &[Finding],
    ledger: &VerificationLedger,
    map: &SystemMap,
) -> Adjudication {
    let mut out = Adjudication::default();

    for f in findings {
        // A suppressed finding has an approved deviation. Re-adjudicating it
        // would reopen something the process already settled — the same reason
        // `correlate` skips them.
        if f.is_suppressed() {
            out.findings.push(f.clone());
            continue;
        }

        let path = f.location.file.to_string_lossy().replace('\\', "/");
        let Some(component) = map.component_for(&path) else {
            out.findings.push(f.clone());
            continue;
        };

        if component.boundary == Boundary::Neural {
            let rationale = format!(
                "`{path}` is inside the learned component `{}`. No proof reaches inside the \
                 weights, and a probe campaign that stayed quiet is not a refutation, so this \
                 finding is recorded as unadjudicated rather than resolved either way.",
                component.name
            );
            out.correlations.push(
                Correlation::new(CorrelationVerdict::Assumed, rationale.clone())
                    .about(f.id.clone()),
            );
            out.findings.push(adjust(f, CorrelationVerdict::Assumed, &rationale));
            continue;
        }

        // A proof settles a finding only if someone asserted that it does.
        let relevant: Vec<&ProofObligation> = ledger
            .obligations
            .iter()
            .filter(|o| o.component == component.name && o.settles(f.rule.as_str()))
            .collect();

        if let Some(failed) = relevant
            .iter()
            .find(|o| matches!(o.status, ObligationStatus::Failed { .. }))
        {
            let counterexample = match &failed.status {
                ObligationStatus::Failed { counterexample: Some(cx) } => {
                    format!(" Counterexample: {cx}.")
                }
                _ => String::new(),
            };
            let rationale = format!(
                "obligation `{}` settling `{}` failed: `{}` could not be established.{} A prover \
                 that fails to discharge an obligation has produced a defect report, not a gap.",
                failed.id,
                f.rule,
                failed.statement,
                counterexample
            );
            out.correlations.push(
                Correlation::new(CorrelationVerdict::Confirmed, rationale.clone())
                    .about(f.id.clone())
                    .evidence(Evidence::proof((*failed).clone())),
            );
            out.findings.push(adjust(f, CorrelationVerdict::Confirmed, &rationale));
            continue;
        }

        let Some(discharged) = relevant.iter().find(|o| o.status.is_discharged()) else {
            // Nothing bearing on this finding. Leave it for `correlate`.
            out.findings.push(f.clone());
            continue;
        };

        // The rule this module exists for: a proof is only as good as the
        // premises it was granted — and `unpaid_premises` follows proved-by
        // links all the way down, because a lemma that is itself granted
        // something unproved passes that debt up to everything citing it.
        let unpaid: Vec<&str> = ledger
            .unpaid_premises(&discharged.id)
            .into_iter()
            .map(|a| a.statement.as_str())
            .collect();

        if unpaid.is_empty() {
            let rationale = format!(
                "obligation `{}` settling `{}` was discharged{}, and every assumption it rests on \
                 is deductively supported. The predicted defect does not occur on any execution \
                 — a strictly stronger statement than `refuted`, which only reports that the \
                 executions actually taken did not exhibit it.",
                discharged.id,
                f.rule,
                discharged.prover.as_deref().map(|p| format!(" by `{p}`")).unwrap_or_default()
            );
            out.correlations.push(
                Correlation::new(CorrelationVerdict::Proved, rationale.clone())
                    .about(f.id.clone())
                    .evidence(Evidence::Proof {
                        obligation: (*discharged).clone(),
                        assumptions: ledger
                            .assumptions_for(&discharged.id)
                            .into_iter()
                            .map(|a| a.id.clone())
                            .collect(),
                    }),
            );
            out.findings.push(adjust(f, CorrelationVerdict::Proved, &rationale));
        } else {
            let rationale = format!(
                "obligation `{}` settling `{}` was discharged, but it was granted {} premise(s) \
                 that nothing proves: {}. The proof therefore establishes the property *given* \
                 those premises, which is not the same claim, so this is recorded as \
                 unadjudicated rather than proved.",
                discharged.id,
                f.rule,
                unpaid.len(),
                unpaid.join("; ")
            );
            out.correlations.push(
                Correlation::new(CorrelationVerdict::Assumed, rationale.clone())
                    .about(f.id.clone())
                    .evidence(Evidence::Proof {
                        obligation: (*discharged).clone(),
                        assumptions: ledger
                            .assumptions_for(&discharged.id)
                            .into_iter()
                            .map(|a| a.id.clone())
                            .collect(),
                    }),
            );
            out.findings.push(adjust(f, CorrelationVerdict::Assumed, &rationale));
        }
    }

    out.not_checked = ledger.not_checked_lines(&map.names());

    // Why no prover ran against each model, stated rather than left as an
    // absence. A report that simply omits neural verification looks exactly like
    // one where it passed.
    //
    // The line names which of the reasons applies, because they call for
    // different responses: an underspecified component is closed by declaring an
    // input region or a horizon, a composite by decomposing it, and the other
    // two are not closable today and should stop being carried as pending work.
    for c in &map.components {
        if c.boundary != Boundary::Neural {
            continue;
        }
        match &c.profile {
            Some(p) => out.not_checked.extend(p.not_checked_line(&c.name)),
            None => out.not_checked.push(format!(
                "sda.undescribed[{}]: declared neural, with no architecture stated. Nothing can \
                 be run against a model nobody described, and an undescribed model is not a \
                 small one",
                c.name
            )),
        }
    }

    // Files outside every declared component, collected and then said once.
    //
    // This used to push one paragraph per distinct path. On a sixty-one file
    // project with a declaration covering one directory, sixty of the seventy-
    // seven NOT CHECKED lines were this notice, near-identical, and everything
    // else in the section was buried under them. On a real tree it is thousands.
    //
    // The same defect, and the same fix, as `ExternalCoverage::provenance_of_many`
    // a crate away — which was written because fifty-nine gcov paragraphs hid the
    // two entries that mattered. This one scales per *source file* rather than
    // per coverage file, so it is worse.
    //
    // A `BTreeSet` rather than the `Vec::contains` this used: that was a linear
    // scan of a growing vector for every finding, and these runs reach eighty
    // thousand findings. Sorted order also makes the report stable between runs.
    let unmapped: std::collections::BTreeSet<String> = findings
        .iter()
        .map(|f| f.location.file.to_string_lossy().replace('\\', "/"))
        .filter(|path| map.component_for(path).is_none())
        .collect();

    // Few enough to name: naming them is what makes the notice actionable, and a
    // handful of lines buries nothing.
    const NAME_EACH_UP_TO: usize = 3;
    if unmapped.len() <= NAME_EACH_UP_TO {
        for path in &unmapped {
            out.not_checked.push(format!(
                "sda.unmapped: `{path}` belongs to no declared component, so no proof or \
                 assumption could be attributed to it"
            ));
        }
    } else if let Some(first) = unmapped.iter().next() {
        // Past that, the count is the finding. One file outside the declaration
        // is an oversight; six hundred means the declaration describes a corner
        // of the tree, and the interposition proof is about that corner.
        out.not_checked.push(format!(
            "sda.unmapped: {} file(s) with findings belong to no declared component, the first \
             of them `{first}`, so no proof or assumption could be attributed to any of them. A \
             declaration covering part of a tree proves something about that part",
            unmapped.len()
        ));
    }
    out
}

/// The summary paragraph for the neurosymbolic section of a report.
pub fn summarize(a: &Adjudication, ledger: &VerificationLedger, property: &str) -> String {
    let proved = a.count(CorrelationVerdict::Proved);
    let confirmed = a.count(CorrelationVerdict::Confirmed);
    let assumed = a.count(CorrelationVerdict::Assumed);
    let mut s = format!(
        "Neurosymbolic adjudication: {proved} finding(s) proved impossible, {confirmed} confirmed \
         by a failed obligation, {assumed} left unadjudicated behind a boundary or an unpaid \
         premise.\n  {}",
        ledger.conditional_claim(property)
    );
    if !a.not_checked.is_empty() {
        s.push_str(&format!(
            "\n  {} item(s) in NOT CHECKED — read them before reading the numbers above.",
            a.not_checked.len()
        ));
    }
    s
}

fn adjust(f: &Finding, verdict: CorrelationVerdict, rationale: &str) -> Finding {
    let mut out = f.clone();
    out.severity = verdict.adjust_severity(out.severity);
    out.confidence = verdict.adjust_confidence(out.confidence);
    out.evidence.push(Evidence::note(format!("[{}] {rationale}", verdict.as_str())));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::verification::{Architecture, Assumption, AssumptionSupport, SearchStrategy};
    use sda_core::{Location, Severity};

    fn finding(path: &str, rule: &str) -> Finding {
        Finding::new(
            "sda.static.rust",
            rule,
            "clamp may exceed the rated range",
            Severity::High,
            Location::new(path, 12, 5),
        )
    }

    fn map() -> SystemMap {
        SystemMap::new()
            .with(Component::symbolic("guard::clamp", "src/guard"))
            .with(Component::neural("policy", "models/policy"))
    }

    fn discharged() -> ProofObligation {
        ProofObligation::new(
            "guard::clamp/ensures/0",
            "output is within the actuator's rated range",
            "guard::clamp",
            Boundary::Symbolic,
            ObligationStatus::Discharged,
        )
        .proved_by("ext.verus")
        .settling("RUST-RANGE-01")
    }

    #[test]
    fn a_soundly_discharged_obligation_proves_the_finding_impossible() {
        let ledger = VerificationLedger::new().with_obligation(discharged());
        let a = adjudicate(&[finding("src/guard/clamp.rs", "RUST-RANGE-01")], &ledger, &map());
        assert_eq!(a.count(CorrelationVerdict::Proved), 1);
        assert_eq!(a.findings[0].severity, Severity::Info, "proved removes, it does not soften");
        assert!(a.correlations[0].rationale.contains("stronger statement than `refuted`"));
    }

    #[test]
    fn a_proof_granted_a_probe_backed_premise_is_not_promoted_to_proved() {
        let ledger = VerificationLedger::new().with_obligation(discharged()).with_assumption(
            Assumption::new(
                "policy::in-domain",
                "the policy network's output stays inside the guard's assumed domain",
                Boundary::Neural,
                AssumptionSupport::Inductive {
                    evidence: vec!["probe.domain-drift".into()],
                    trials: 400,
                    counterexamples: 0,
                    search: SearchStrategy::Adversarial,
                },
            )
            .underwrites("guard::clamp/ensures/0"),
        );
        let f = finding("src/guard/clamp.rs", "RUST-RANGE-01");
        let before = f.severity;
        let a = adjudicate(&[f], &ledger, &map());
        assert_eq!(a.count(CorrelationVerdict::Proved), 0, "400 quiet probes are not a proof");
        assert_eq!(a.count(CorrelationVerdict::Assumed), 1);
        assert_eq!(a.findings[0].severity, before, "nothing was learned, so nothing moves");
        assert!(a.correlations[0].rationale.contains("premise(s) that nothing proves"));
    }

    #[test]
    fn the_same_proof_with_its_premise_paid_for_is_promoted() {
        let ledger = VerificationLedger::new()
            .with_obligation(discharged())
            .with_obligation(ProofObligation::new(
                "guard::clamp/total",
                "clamp terminates and cannot panic",
                "guard::clamp",
                Boundary::Symbolic,
                ObligationStatus::Discharged,
            ))
            .with_assumption(
                Assumption::new(
                    "policy::in-domain",
                    "every model output passes through the guard",
                    Boundary::Symbolic,
                    AssumptionSupport::RuntimeGuard {
                        location: None,
                        totality_obligation: Some("guard::clamp/total".into()),
                    },
                )
                .underwrites("guard::clamp/ensures/0"),
            );
        let a = adjudicate(&[finding("src/guard/clamp.rs", "RUST-RANGE-01")], &ledger, &map());
        assert_eq!(a.count(CorrelationVerdict::Proved), 1, "the premise is a proved lemma now");
    }

    #[test]
    fn a_failed_obligation_confirms_the_finding() {
        let mut o = discharged();
        o.status = ObligationStatus::Failed { counterexample: Some("input = NaN".into()) };
        let ledger = VerificationLedger::new().with_obligation(o);
        let a = adjudicate(&[finding("src/guard/clamp.rs", "RUST-RANGE-01")], &ledger, &map());
        assert_eq!(a.count(CorrelationVerdict::Confirmed), 1);
        assert_eq!(a.findings[0].severity, Severity::Critical, "escalated");
        assert!(a.correlations[0].rationale.contains("input = NaN"));
    }

    #[test]
    fn a_proof_about_a_different_rule_does_not_settle_this_one() {
        let ledger = VerificationLedger::new().with_obligation(discharged());
        let a = adjudicate(&[finding("src/guard/clamp.rs", "RUST-UNSAFE-07")], &ledger, &map());
        assert!(
            a.correlations.is_empty(),
            "an obligation settles the rules it names, not whatever is nearby"
        );
        assert_eq!(a.findings[0].severity, Severity::High, "left for the correlation engine");
    }

    #[test]
    fn a_finding_inside_the_model_is_unadjudicated_rather_than_resolved() {
        let ledger = VerificationLedger::new().with_obligation(discharged());
        let a = adjudicate(&[finding("models/policy/head.onnx", "AI-BACKDOOR-01")], &ledger, &map());
        assert_eq!(a.count(CorrelationVerdict::Assumed), 1);
        assert!(a.correlations[0].rationale.contains("No proof reaches inside the weights"));
        assert_eq!(a.findings[0].severity, Severity::High, "unchanged: nothing was learned");
    }

    #[test]
    fn an_unmapped_file_is_reported_rather_than_judged() {
        let ledger = VerificationLedger::new().with_obligation(discharged());
        let a = adjudicate(&[finding("src/util/parse.rs", "RUST-RANGE-01")], &ledger, &map());
        assert!(a.correlations.is_empty());
        assert!(a.not_checked.iter().any(|l| l.contains("belongs to no declared component")));
    }

    /// Many unmapped files become one entry that still carries the number.
    ///
    /// One paragraph per distinct path was the old behaviour, and on a
    /// sixty-one file project with a declaration covering one directory it made
    /// sixty of the seventy-seven *NOT CHECKED* lines this notice — burying the
    /// rest of the section, which is the section that exists to be read.
    ///
    /// The same defect `ExternalCoverage::provenance_of_many` was written for,
    /// where fifty-nine gcov paragraphs hid the two entries that mattered. The
    /// count is kept because at scale the count *is* the finding: one unmapped
    /// file is an oversight, six hundred means the declaration describes a corner
    /// of the tree and the proof is about that corner.
    #[test]
    fn many_unmapped_files_are_counted_rather_than_listed_one_by_one() {
        let ledger = VerificationLedger::new().with_obligation(discharged());
        let findings: Vec<Finding> =
            (0..60).map(|i| finding(&format!("src/f{i:02}.c"), "RUST-RANGE-01")).collect();
        let a = adjudicate(&findings, &ledger, &map());

        let unmapped: Vec<&String> =
            a.not_checked.iter().filter(|l| l.contains("sda.unmapped")).collect();
        assert_eq!(
            unmapped.len(),
            1,
            "sixty near-identical paragraphs bury every other entry: {unmapped:?}"
        );
        assert!(
            unmapped[0].contains("60 file(s)"),
            "and the number must survive the collapse, because at this scale it is the \
             finding: {}",
            unmapped[0]
        );
        assert!(
            unmapped[0].contains("src/f00.c"),
            "naming one gives the reader somewhere to start: {}",
            unmapped[0]
        );
    }

    /// A handful are still named one by one, because naming them is actionable.
    ///
    /// The collapse is for the case where the list is the problem. Three files
    /// outside the declaration is an oversight a reader can go and fix, and three
    /// lines bury nothing.
    #[test]
    fn a_few_unmapped_files_are_still_named_individually() {
        let ledger = VerificationLedger::new().with_obligation(discharged());
        let findings: Vec<Finding> =
            (0..3).map(|i| finding(&format!("src/f{i}.c"), "RUST-RANGE-01")).collect();
        let a = adjudicate(&findings, &ledger, &map());

        let unmapped: Vec<&String> =
            a.not_checked.iter().filter(|l| l.contains("sda.unmapped")).collect();
        assert_eq!(unmapped.len(), 3, "each is worth naming at this size: {unmapped:?}");
        for i in 0..3 {
            assert!(
                unmapped.iter().any(|l| l.contains(&format!("src/f{i}.c"))),
                "every one of them by name: {unmapped:?}"
            );
        }
    }

    /// Repeated findings in one file are one file, however many there are.
    ///
    /// The old code deduplicated by comparing the formatted line against every
    /// line already collected — a linear scan of a growing vector, per finding,
    /// on runs that reach eighty thousand findings. A set does the same job and
    /// also fixes the order, so two runs of the same scan produce the same
    /// report.
    #[test]
    fn repeated_findings_in_one_file_count_as_one_file() {
        let ledger = VerificationLedger::new().with_obligation(discharged());
        let findings: Vec<Finding> =
            (0..40).map(|_| finding("src/only.c", "RUST-RANGE-01")).collect();
        let a = adjudicate(&findings, &ledger, &map());

        let unmapped: Vec<&String> =
            a.not_checked.iter().filter(|l| l.contains("sda.unmapped")).collect();
        assert_eq!(unmapped.len(), 1, "one file, forty findings: {unmapped:?}");
        assert!(
            unmapped[0].contains("src/only.c"),
            "and at this size it is still named: {}",
            unmapped[0]
        );
    }

    #[test]
    fn a_component_with_no_obligations_reaches_not_checked() {
        let ledger = VerificationLedger::new().with_obligation(discharged());
        let a = adjudicate(&[], &ledger, &map());
        assert!(
            a.not_checked.iter().any(|l| l.contains("sda.vacuous[policy]")),
            "the model carries no obligations and must not read as verified: {:?}",
            a.not_checked
        );
    }

    #[test]
    fn the_summary_leads_with_the_conditional_claim_not_the_counts() {
        let ledger = VerificationLedger::new().with_obligation(discharged()).with_assumption(
            Assumption::new(
                "policy::in-domain",
                "the policy network stays in domain",
                Boundary::Neural,
                AssumptionSupport::Undischarged,
            )
            .underwrites("guard::clamp/ensures/0"),
        );
        let a = adjudicate(&[finding("src/guard/clamp.rs", "RUST-RANGE-01")], &ledger, &map());
        let s = summarize(&a, &ledger, "actuator command is always in range");
        assert!(s.contains("PROVIDED"), "{s}");
        assert!(s.contains("NOT CHECKED"));
    }

    #[test]
    fn a_suppressed_finding_is_not_reopened_by_a_proof() {
        let mut f = finding("src/guard/clamp.rs", "RUST-RANGE-01");
        f.suppressed_by = Some("deviation D-14".into());
        let ledger = VerificationLedger::new().with_obligation(discharged());
        let a = adjudicate(&[f], &ledger, &map());
        assert!(a.correlations.is_empty());
    }

    #[test]
    fn an_llm_scale_component_is_reported_as_beyond_every_prover() {
        let m = SystemMap::new()
            .with(Component::neural("policy", "models/policy").profiled(
                NeuralProfile::new(Architecture::Transformer)
                    .with_parameters(7_000_000_000)
                    .over_region("L-inf ball on the embeddings, epsilon = 0.01"),
            ))
            .with(Component::symbolic("guard::clamp", "src/guard"));
        let a = adjudicate(&[], &VerificationLedger::new().with_obligation(discharged()), &m);
        let line = a
            .not_checked
            .iter()
            .find(|l| l.contains("sda.intractable[policy]"))
            .expect("an unprovable component must say so");
        assert!(line.contains("7000000000 parameters"));
        assert!(
            line.contains("no volume of trials makes it otherwise"),
            "the point is that sampling does not substitute for the missing proof"
        );
    }

    #[test]
    fn a_small_network_a_verifier_could_run_against_gets_no_intractability_line() {
        let m = SystemMap::new().with(
            Component::neural("perception", "models/perception").profiled(
                NeuralProfile::new(Architecture::Cnn)
                    .with_parameters(90_000)
                    .over_region("L-inf ball, epsilon = 0.03"),
            ),
        );
        let a = adjudicate(&[], &VerificationLedger::new(), &m);
        assert!(
            !a.not_checked.iter().any(|l| l.contains("sda.intractable")
                || l.contains("sda.underspecified")
                || l.contains("sda.research-only")),
            "a verifier can be pointed at this one: {:?}",
            a.not_checked
        );
        assert!(
            a.not_checked.iter().any(|l| l.contains("sda.vacuous[perception]")),
            "still unspecified, though — tractable is not the same as checked"
        );
    }

    #[test]
    fn the_same_size_gives_different_answers_for_different_architectures() {
        let region = "L-inf ball, epsilon = 0.03";
        let m = SystemMap::new()
            .with(Component::neural("vision", "models/vision").profiled(
                NeuralProfile::new(Architecture::Cnn).with_parameters(4_000_000).over_region(region),
            ))
            .with(Component::neural("policy", "models/policy").profiled(
                NeuralProfile::new(Architecture::Mlp).with_parameters(4_000_000).over_region(region),
            ))
            .with(Component::neural("text", "models/text").profiled(
                NeuralProfile::new(Architecture::Transformer)
                    .with_parameters(4_000_000)
                    .over_region(region),
            ));
        let a = adjudicate(&[], &VerificationLedger::new(), &m);
        let lines = a.not_checked.join("\n");
        // `sda.vacuous` applies to all three — none carries an obligation — so
        // the CNN's distinguishing property is the absence of a *reachability*
        // line, not the absence of every line.
        assert!(
            !lines.contains("sda.intractable[vision]")
                && !lines.contains("sda.research-only[vision]")
                && !lines.contains("sda.underspecified[vision]"),
            "the CNN is in reach at this size: {lines}"
        );
        assert!(lines.contains("sda.intractable[policy]"), "the MLP of the same size is not");
        assert!(lines.contains("sda.research-only[text]"), "and the transformer is neither");
    }

    #[test]
    fn a_recurrent_component_asks_for_its_horizon_rather_than_being_refused() {
        let m = SystemMap::new().with(Component::neural("gesture", "models/gesture").profiled(
            NeuralProfile::new(Architecture::Rnn).with_parameters(80_000).over_region("a box"),
        ));
        let a = adjudicate(&[], &VerificationLedger::new(), &m);
        assert!(
            a.not_checked.iter().any(|l| l.contains("sda.underspecified[gesture]")),
            "an unrolling bound is something the user can supply: {:?}",
            a.not_checked
        );
    }

    #[test]
    fn a_generative_model_is_pointed_at_its_analysable_half() {
        let m = SystemMap::new().with(Component::neural("vae", "models/vae").profiled(
            NeuralProfile::new(Architecture::Autoencoder).with_parameters(300_000),
        ));
        let a = adjudicate(&[], &VerificationLedger::new(), &m);
        let line = a
            .not_checked
            .iter()
            .find(|l| l.contains("sda.composite[vae]"))
            .expect("a VAE is not one function");
        assert!(line.contains("decoder"), "the decoder is where a bound is actually available");
    }

    #[test]
    fn an_undescribed_neural_component_is_reported_not_assumed_small() {
        let m = SystemMap::new().with(Component::neural("policy", "models/policy"));
        let a = adjudicate(&[], &VerificationLedger::new(), &m);
        assert!(
            a.not_checked.iter().any(|l| l.contains("sda.undescribed[policy]")),
            "nothing can be run against a model nobody described"
        );
    }

    #[test]
    fn the_search_behind_a_trial_count_is_reported_with_it() {
        let quiet = |search| {
            Assumption::new(
                "policy::in-domain",
                "the policy stays in domain",
                Boundary::Neural,
                AssumptionSupport::Inductive {
                    evidence: vec![],
                    trials: 10_000,
                    counterexamples: 0,
                    search,
                },
            )
            .not_checked_line()
        };
        let random = quiet(SearchStrategy::Random);
        let adversarial = quiet(SearchStrategy::Adversarial);
        assert!(random.contains("10000 random trial(s)"));
        assert!(random.contains("nothing about the ones an attacker would pick"));
        assert!(adversarial.contains("still not a bound"));
        assert_ne!(random, adversarial, "the count alone is not the evidence");
    }

    #[test]
    fn a_component_path_matches_on_segment_boundaries() {
        let m = map();
        assert!(m.component_for("src/guard/clamp.rs").is_some());
        assert!(
            m.component_for("src/guardian/clamp.rs").is_none(),
            "`src/guard` must not own `src/guardian`"
        );
    }
}
