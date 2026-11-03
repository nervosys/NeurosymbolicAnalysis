//! Deductive and inductive verification, and the boundary between them.
//!
//! A hybrid neurosymbolic system is two kinds of artifact wired together, and
//! they do not admit the same kind of evidence:
//!
//! * The **symbolic** part — the rule engine, the planner, the parser, the guard
//!   that decides what a model's output is allowed to do — is ordinary code. A
//!   theorem prover can discharge obligations about it that hold over *every*
//!   execution. That is [`Modality::Deductive`].
//! * The **neural** part is reachable only by running it and judging what came
//!   back. A probe that fires demonstrates a behaviour; a probe that stays quiet
//!   demonstrates nothing, because the space of triggers is unbounded. That is
//!   [`Modality::Inductive`], and `sda_ai::probe` has said so in prose since
//!   before this module existed.
//!
//! The failure mode this module exists to prevent is **averaging**: producing one
//! system-level confidence that blends a discharged SMT obligation with a probe
//! suite that happened to stay quiet. That is the same error the toolkit already
//! refuses to make one level down, where "no runtime defect" must not be read as
//! "correct" without asking whether the code ever ran. Combining the modalities
//! by mixing them destroys exactly the information that made each one worth
//! collecting.
//!
//! The combination that does work is **assume-guarantee across a stated
//! boundary**. Prove the symbolic shell. Let the neural component enter the proof
//! as a named [`Assumption`] rather than as verified code. Then require every
//! such assumption to be discharged one of three ways — by a runtime guard that
//! is itself proved total, by inductive evidence carrying its own caveat, or by
//! appearing in the report's `NOT CHECKED` section. Never silently. The
//! system-level claim that comes out is not "P holds" but "P holds **provided**
//! these assumptions hold", with the assumptions enumerated and their support
//! named — which is a weaker sentence and a true one.
//!
//! [`VerificationLedger`] is where that bookkeeping lives, and
//! [`VerificationLedger::conditional_claim`] is the sentence it exists to be able
//! to write.

use crate::finding::Location;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// How a claim was established, and therefore what its silence is worth.
///
/// This is orthogonal to static/dynamic. Abstract interpretation is static and
/// deductive; a fuzzing campaign is dynamic and inductive; a bounded model
/// checker is static and deductive *up to its bound* and inductive-shaped
/// beyond it, which is why [`ProofObligation::prover`] is recorded and the
/// report prints that tool's limits alongside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Modality {
    /// Established by proof. Holds for every execution admitted by the model,
    /// conditional on the assumptions the proof was granted.
    Deductive,
    /// Established by observation over sampled executions or inputs. Holds for
    /// what was observed, and generalises only as far as the sample justifies —
    /// which, for a model that could be concealing a behaviour, is not far.
    Inductive,
}

impl Modality {
    pub fn as_str(&self) -> &'static str {
        match self {
            Modality::Deductive => "deductive",
            Modality::Inductive => "inductive",
        }
    }

    /// What a *positive* result in this modality establishes.
    ///
    /// The ontology's `Soundness` answers "what is a clean result worth", which
    /// is a question about silence. A discharged proof is not silence — it is a
    /// positive claim — and needed its own sentence.
    pub fn success_means(&self) -> &'static str {
        match self {
            Modality::Deductive => {
                "the stated property holds on every execution, given the stated assumptions"
            }
            Modality::Inductive => {
                "the property held on every input tried, which is not a claim about the ones \
                 that were not"
            }
        }
    }

    /// What the *absence* of a result in this modality establishes.
    pub fn silence_means(&self) -> &'static str {
        match self {
            Modality::Deductive => {
                "nothing was proved, which is not a defect and not a clean bill of health: an \
                 unspecified component verifies vacuously"
            }
            Modality::Inductive => {
                "nothing was observed; the trigger space is unbounded and a concealed behaviour \
                 conceals itself from this suite too"
            }
        }
    }
}

/// Which side of the neurosymbolic seam a claim or assumption sits on.
///
/// Recorded rather than inferred, because the whole point of the ledger is that
/// a reader can see at a glance how much of a system-level claim rests on code
/// that was proved and how much rests on a model that was merely sampled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Boundary {
    /// Ordinary code: the rule engine, the planner, the guard.
    Symbolic,
    /// A learned model. Nothing here is provable at LLM scale; small networks
    /// admit neural property verification over a stated input region and
    /// nothing wider.
    Neural,
    /// Outside the system: the operating system, the hardware, the caller's
    /// contract. Assumptions here are the ones people forget they made.
    Environment,
}

impl Boundary {
    pub fn as_str(&self) -> &'static str {
        match self {
            Boundary::Symbolic => "symbolic",
            Boundary::Neural => "neural",
            Boundary::Environment => "environment",
        }
    }
}

/// What became of a proof obligation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ObligationStatus {
    /// The prover discharged it.
    Discharged,
    /// The prover ran and could not discharge it. This is a finding, not a gap:
    /// a failed obligation is the closest thing to a static defect report that
    /// deductive verification produces.
    Failed { counterexample: Option<String> },
    /// Granted without proof. Every one of these becomes an [`Assumption`] and
    /// appears in `NOT CHECKED`; an `assume` that nobody reads is how a proof
    /// becomes a decoration.
    Assumed,
    /// The prover never ran — not installed, timed out, or out of its fragment.
    /// Distinct from `Assumed`, and the distinction matters for the same reason
    /// `unreached` differs from `refuted`: nobody made a judgement here at all.
    NotAttempted { reason: String },
}

impl ObligationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObligationStatus::Discharged => "discharged",
            ObligationStatus::Failed { .. } => "failed",
            ObligationStatus::Assumed => "assumed",
            ObligationStatus::NotAttempted { .. } => "not-attempted",
        }
    }
    pub fn is_discharged(&self) -> bool {
        matches!(self, ObligationStatus::Discharged)
    }
}

/// One thing a prover was asked to establish.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofObligation {
    /// Stable id, e.g. `guard::clamp_output/ensures/0`.
    pub id: String,
    /// What is being claimed, in the source language of the specification.
    pub statement: String,
    /// The component it constrains — a module path, a function, a model name.
    pub component: String,
    pub boundary: Boundary,
    pub status: ObligationStatus,
    /// Provider id of the tool that ruled on it, e.g. `ext.verus`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prover: Option<String>,
    /// Where the specification is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// Rule ids this obligation settles, e.g. `MISRA-C-2023-21.6`.
    ///
    /// Asserted by whoever wrote the specification, never inferred. The
    /// correlation engine already refuses to let a runtime fault confirm a
    /// static finding on proximity alone — it demands the two be the same class
    /// of thing — and a proof gets no easier ride. An obligation that proves an
    /// output is in range does not thereby settle an unrelated advisory three
    /// lines away, and a `Proved` verdict handed out on location alone would be
    /// the strongest claim this toolkit makes, awarded for a coincidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discharges: Vec<String>,
}

impl ProofObligation {
    pub fn new(
        id: impl Into<String>,
        statement: impl Into<String>,
        component: impl Into<String>,
        boundary: Boundary,
        status: ObligationStatus,
    ) -> Self {
        ProofObligation {
            id: id.into(),
            statement: statement.into(),
            component: component.into(),
            boundary,
            status,
            prover: None,
            location: None,
            discharges: Vec::new(),
        }
    }
    pub fn proved_by(mut self, prover: impl Into<String>) -> Self {
        self.prover = Some(prover.into());
        self
    }
    pub fn at(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }
    /// Assert that discharging this obligation settles a named rule.
    pub fn settling(mut self, rule: impl Into<String>) -> Self {
        self.discharges.push(rule.into());
        self
    }
    /// True if this obligation was asserted to settle `rule`.
    pub fn settles(&self, rule: &str) -> bool {
        self.discharges.iter().any(|r| r == rule)
    }
}

/// How the trials behind inductive support were chosen.
///
/// A trial count is a quantity; the search that produced it is what makes the
/// quantity mean anything. Over a bounded input region, enough trials can
/// approach a real bound. Over natural language they cannot approach one at all,
/// and the difference between random and adversarial sampling is the difference
/// between weak evidence and slightly less weak evidence — never between weak
/// evidence and a proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SearchStrategy {
    /// Drawn from the expected input distribution. Says what typical use does,
    /// which is the least informative thing about a safety property.
    #[default]
    Random,
    /// Chosen by something trying to break the assumption — a red-team suite, a
    /// coverage-guided fuzzer, a gradient attack.
    Adversarial,
    /// Every input in a stated finite region was tried. The only inductive
    /// support that is actually a proof, and only about that region.
    ExhaustiveOverRegion,
}

impl SearchStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            SearchStrategy::Random => "random",
            SearchStrategy::Adversarial => "adversarial",
            SearchStrategy::ExhaustiveOverRegion => "exhaustive-over-region",
        }
    }
    /// What this search makes of a run with no counterexample.
    pub fn clean_run_means(&self) -> &'static str {
        match self {
            SearchStrategy::Random => {
                "sampled from the expected distribution, so it says what typical inputs do and \
                 nothing about the ones an attacker would pick"
            }
            SearchStrategy::Adversarial => {
                "searched by something trying to break it, which is the strongest inductive \
                 evidence available and still not a bound"
            }
            SearchStrategy::ExhaustiveOverRegion => {
                "exhaustive over the stated region, which settles that region and says nothing \
                 outside it"
            }
        }
    }
}

/// How an assumption is paid for.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "support", rename_all = "kebab-case")]
pub enum AssumptionSupport {
    /// Discharged by another obligation that was itself proved. The strongest
    /// case: the assumption is not really an assumption, it is a lemma.
    Proved { obligation: String },
    /// Enforced at runtime by a guard, which must itself be proved total —
    /// otherwise the guard is one more unverified component and the assumption
    /// has only moved.
    RuntimeGuard {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        location: Option<Location>,
        /// Obligation id establishing that the guard cannot be bypassed or
        /// panic. `None` means the guard is trusted, which is worth seeing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        totality_obligation: Option<String>,
    },
    /// Supported by observation only: a probe campaign, a test suite, a fuzzing
    /// run. Counts are recorded because "we tested it" is not a quantity.
    Inductive {
        /// Ids of the probes or tests that bear on this assumption.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        evidence: Vec<String>,
        /// How many actually ran and were evaluable. Probes that could not be
        /// evaluated are not tests that passed.
        trials: usize,
        /// How many contradicted the assumption.
        counterexamples: usize,
        /// How the trials were chosen.
        ///
        /// Recorded because the count alone is close to meaningless over an
        /// unbounded input space: ten thousand samples drawn from the expected
        /// distribution and ten thousand drawn by an adversary looking for the
        /// failure are different evidence, and only the second is worth much
        /// against a model that could be concealing a behaviour.
        #[serde(default)]
        search: SearchStrategy,
    },
    /// Nothing supports it. Legitimate, and the report says so out loud.
    Undischarged,
}

impl AssumptionSupport {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssumptionSupport::Proved { .. } => "proved",
            AssumptionSupport::RuntimeGuard { .. } => "runtime-guard",
            AssumptionSupport::Inductive { .. } => "inductive",
            AssumptionSupport::Undischarged => "undischarged",
        }
    }

    /// The modality of this support, if it has one. `Undischarged` has none —
    /// that is what makes it undischarged rather than weak.
    pub fn modality(&self) -> Option<Modality> {
        match self {
            AssumptionSupport::Proved { .. } | AssumptionSupport::RuntimeGuard { .. } => {
                Some(Modality::Deductive)
            }
            AssumptionSupport::Inductive { .. } => Some(Modality::Inductive),
            AssumptionSupport::Undischarged => None,
        }
    }

    /// True when this support carries a deductive guarantee end to end.
    ///
    /// A runtime guard whose totality was never established does not: it is a
    /// check that might itself fail, and calling it deductive would launder an
    /// assumption into a proof.
    pub fn is_sound(&self) -> bool {
        match self {
            AssumptionSupport::Proved { .. } => true,
            AssumptionSupport::RuntimeGuard { totality_obligation, .. } => {
                totality_obligation.is_some()
            }
            AssumptionSupport::Inductive { .. } | AssumptionSupport::Undischarged => false,
        }
    }

    /// Review order: the weakest support a reviewer should read first.
    fn rank(&self) -> u8 {
        match self {
            AssumptionSupport::Undischarged => 0,
            AssumptionSupport::RuntimeGuard { .. } => 1,
            AssumptionSupport::Inductive { .. } => 2,
            AssumptionSupport::Proved { .. } => 3,
        }
    }
}

/// Something a proof was granted rather than shown.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assumption {
    pub id: String,
    /// The granted claim, stated so a reviewer can disagree with it.
    pub statement: String,
    pub boundary: Boundary,
    pub support: AssumptionSupport,
    /// Obligation ids that would become unproved if this assumption were false.
    /// This is what makes the ledger navigable in the direction a reviewer
    /// actually reads it: "if I do not believe this, what do I lose?".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supports: Vec<String>,
}

impl Assumption {
    pub fn new(
        id: impl Into<String>,
        statement: impl Into<String>,
        boundary: Boundary,
        support: AssumptionSupport,
    ) -> Self {
        Assumption {
            id: id.into(),
            statement: statement.into(),
            boundary,
            support,
            supports: Vec::new(),
        }
    }
    pub fn underwrites(mut self, obligation: impl Into<String>) -> Self {
        self.supports.push(obligation.into());
        self
    }
    /// Underwrite several obligations at once — one premise carrying a family of
    /// proofs, which is the usual shape when the premise is architectural.
    pub fn underwrites_all<I, T>(mut self, obligations: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.supports.extend(obligations.into_iter().map(Into::into));
        self
    }
    /// One line for the `NOT CHECKED` section.
    pub fn not_checked_line(&self) -> String {
        let support = match &self.support {
            AssumptionSupport::Proved { obligation } => format!("proved by `{obligation}`"),
            AssumptionSupport::RuntimeGuard { totality_obligation: Some(o), .. } => {
                format!("enforced by a runtime guard proved total by `{o}`")
            }
            AssumptionSupport::RuntimeGuard { totality_obligation: None, .. } => {
                "enforced by a runtime guard that was not proved total — the guard is itself \
                 unverified"
                    .to_string()
            }
            AssumptionSupport::Inductive { trials, counterexamples: 0, search, .. } => format!(
                "{trials} {} trial(s) found no counterexample: {}",
                search.as_str(),
                search.clean_run_means()
            ),
            AssumptionSupport::Inductive { trials, counterexamples, search, .. } => format!(
                "{counterexamples} of {trials} {} trial(s) contradicted it — the assumption is \
                 false as stated",
                search.as_str()
            ),
            AssumptionSupport::Undischarged => "nothing supports it".to_string(),
        };
        format!(
            "sda.assumption[{}]: `{}` is assumed at the {} boundary ({support})",
            self.id,
            self.statement,
            self.boundary.as_str()
        )
    }
}

/// Every obligation and assumption for one system, and the claims they license.
///
/// The ledger is deliberately not a score. It has no method returning a number
/// between zero and one, because any such number would be the averaging this
/// module exists to prevent.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VerificationLedger {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<ProofObligation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assumptions: Vec<Assumption>,
}

impl VerificationLedger {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_obligation(mut self, o: ProofObligation) -> Self {
        self.obligations.push(o);
        self
    }
    pub fn with_assumption(mut self, a: Assumption) -> Self {
        self.assumptions.push(a);
        self
    }
    pub fn obligation(&self, id: &str) -> Option<&ProofObligation> {
        self.obligations.iter().find(|o| o.id == id)
    }

    pub fn discharged(&self) -> impl Iterator<Item = &ProofObligation> {
        self.obligations.iter().filter(|o| o.status.is_discharged())
    }
    pub fn failed(&self) -> impl Iterator<Item = &ProofObligation> {
        self.obligations.iter().filter(|o| matches!(o.status, ObligationStatus::Failed { .. }))
    }
    /// Obligations nobody ruled on. These are gaps, not results, and they are
    /// counted apart from the ones that were assumed on purpose.
    pub fn not_attempted(&self) -> impl Iterator<Item = &ProofObligation> {
        self.obligations
            .iter()
            .filter(|o| matches!(o.status, ObligationStatus::NotAttempted { .. }))
    }

    /// Assumptions that underwrite `obligation`, directly by naming it.
    pub fn assumptions_for<'a>(&'a self, obligation: &str) -> Vec<&'a Assumption> {
        self.assumptions.iter().filter(|a| a.supports.iter().any(|o| o == obligation)).collect()
    }

    /// Every unpaid premise an obligation rests on, following proved-by links
    /// all the way down.
    ///
    /// [`AssumptionSupport::is_sound`] answers a local question — is *this*
    /// premise paid for — and a local answer is not enough once proofs cite each
    /// other. An obligation whose only assumption is discharged by a lemma looks
    /// sound; if that lemma in turn rests on something nothing proves, the
    /// original claim rests on it too, and reporting the first as proved would
    /// hide the premise one link further away than anyone looked.
    ///
    /// Cycles terminate: an obligation already on the path is not re-entered.
    pub fn unpaid_premises(&self, obligation: &str) -> Vec<&Assumption> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut out: Vec<&Assumption> = Vec::new();
        self.walk_premises(obligation, &mut seen, &mut out);
        out
    }

    fn walk_premises<'a>(
        &'a self,
        obligation: &str,
        seen: &mut BTreeSet<&'a str>,
        out: &mut Vec<&'a Assumption>,
    ) {
        let Some(o) = self.obligations.iter().find(|o| o.id == obligation) else { return };
        if !seen.insert(o.id.as_str()) {
            return;
        }
        for a in self.assumptions_for(&o.id) {
            if !a.support.is_sound() {
                if !out.iter().any(|x| x.id == a.id) {
                    out.push(a);
                }
                continue;
            }
            // Sound *here*, but its own support cites another obligation, and
            // that obligation may have premises of its own.
            let next = match &a.support {
                AssumptionSupport::Proved { obligation } => Some(obligation.as_str()),
                AssumptionSupport::RuntimeGuard { totality_obligation, .. } => {
                    totality_obligation.as_deref()
                }
                _ => None,
            };
            if let Some(next) = next {
                self.walk_premises(next, seen, out);
            }
        }
    }

    /// Assumptions whose support is not deductive end to end — everything a
    /// reviewer has to take on trust, weakest first.
    pub fn weak_assumptions(&self) -> Vec<&Assumption> {
        let mut v: Vec<&Assumption> =
            self.assumptions.iter().filter(|a| !a.support.is_sound()).collect();
        v.sort_by_key(|a| a.support.rank());
        v
    }

    /// An assumption naming an obligation that is not in the ledger, or that is
    /// itself not discharged. A proof resting on a lemma nobody proved is not a
    /// proof, and this is the check that catches it.
    pub fn broken_support(&self) -> Vec<&Assumption> {
        self.assumptions
            .iter()
            .filter(|a| {
                let referenced = match &a.support {
                    AssumptionSupport::Proved { obligation } => Some(obligation),
                    AssumptionSupport::RuntimeGuard { totality_obligation, .. } => {
                        totality_obligation.as_ref()
                    }
                    _ => None,
                };
                match referenced {
                    Some(id) => !self.obligation(id).is_some_and(|o| o.status.is_discharged()),
                    None => false,
                }
            })
            .collect()
    }

    /// Components that carry no obligations at all.
    ///
    /// A component nobody specified proves everything asked of it, because
    /// nothing was asked. This is the deductive analogue of a clean scan over an
    /// empty file set, and reporting it is the same commitment: a tool must say
    /// what it did not check. Callers pass the components they believe are in
    /// scope; the ledger cannot know them.
    pub fn vacuous<'a>(&self, in_scope: &[&'a str]) -> Vec<&'a str> {
        let specified: BTreeSet<&str> =
            self.obligations.iter().map(|o| o.component.as_str()).collect();
        in_scope.iter().copied().filter(|c| !specified.contains(c)).collect()
    }

    /// The lines this ledger contributes to the report's unsuppressible section.
    pub fn not_checked_lines(&self, in_scope: &[&str]) -> Vec<String> {
        let mut lines = Vec::new();
        // Matched in place rather than filtered through `not_attempted` and then
        // re-matched to recover the reason. The second match needs an arm it can
        // never reach, and writing `unreachable!` there is a panic in a library
        // — which is exactly what `sda scan crates` flagged when this module was
        // first written. This version has no arm to be wrong about.
        for o in &self.obligations {
            if let ObligationStatus::NotAttempted { reason } = &o.status {
                lines.push(format!(
                    "sda.obligation[{}]: `{}` was never ruled on ({reason}) — no judgement was \
                     made, which is not the same as granting it",
                    o.id, o.statement
                ));
            }
        }
        for a in self.weak_assumptions() {
            lines.push(a.not_checked_line());
        }
        for a in self.broken_support() {
            lines.push(format!(
                "sda.assumption[{}]: claims deductive support from an obligation that is missing \
                 or undischarged — the proof it underwrites does not stand",
                a.id
            ));
        }
        for c in self.vacuous(in_scope) {
            lines.push(format!(
                "sda.vacuous[{c}]: in scope and carries no proof obligation — it verifies \
                 trivially, and a trivial verification is not a result"
            ));
        }
        lines
    }

    /// The system-level sentence the ledger licenses.
    ///
    /// Never "P holds". Always "P holds provided ...", with the provisos named,
    /// or a plain refusal when an obligation failed outright.
    pub fn conditional_claim(&self, property: &str) -> String {
        if let Some(f) = self.failed().next() {
            return format!(
                "`{property}` is NOT established: obligation `{}` failed. A failed obligation is a \
                 defect report, not a gap.",
                f.id
            );
        }
        let discharged = self.discharged().count();
        if discharged == 0 {
            return format!(
                "`{property}` is NOT established: no obligation bearing on it was discharged. {}",
                Modality::Deductive.silence_means()
            );
        }
        let weak = self.weak_assumptions();
        if weak.is_empty() {
            return format!(
                "`{property}` holds on every execution: {discharged} obligation(s) discharged and \
                 every assumption is deductively supported."
            );
        }
        let named: Vec<&str> = weak.iter().map(|a| a.statement.as_str()).collect();
        format!(
            "`{property}` holds on every execution PROVIDED: {}. {discharged} obligation(s) were \
             discharged; the {} proviso(s) above were not proved and are listed in NOT CHECKED.",
            named.join("; "),
            weak.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard_proved() -> ProofObligation {
        ProofObligation::new(
            "guard::clamp/ensures/0",
            "output is within the actuator's rated range",
            "guard::clamp",
            Boundary::Symbolic,
            ObligationStatus::Discharged,
        )
        .proved_by("ext.verus")
    }

    #[test]
    fn a_proof_resting_on_a_probe_suite_says_so_in_its_own_claim() {
        let ledger = VerificationLedger::new().with_obligation(guard_proved()).with_assumption(
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
        let claim = ledger.conditional_claim("actuator command is always in range");
        assert!(
            claim.contains("PROVIDED"),
            "an inductively supported proof is conditional: {claim}"
        );
        assert!(claim.contains("assumed domain"));
        let nc = ledger.not_checked_lines(&["guard::clamp"]);
        assert!(nc.iter().any(|l| l.contains("400 adversarial trial(s) found no counterexample")));
    }

    #[test]
    fn an_assumption_paid_for_by_a_proved_lemma_is_not_a_proviso() {
        let ledger = VerificationLedger::new()
            .with_obligation(guard_proved())
            .with_obligation(ProofObligation::new(
                "guard::clamp/total",
                "clamp terminates and cannot panic",
                "guard::clamp",
                Boundary::Symbolic,
                ObligationStatus::Discharged,
            ))
            .with_assumption(Assumption::new(
                "guard::reachable",
                "every model output passes through the guard",
                Boundary::Symbolic,
                AssumptionSupport::RuntimeGuard {
                    location: None,
                    totality_obligation: Some("guard::clamp/total".into()),
                },
            ));
        assert!(ledger.weak_assumptions().is_empty());
        assert!(ledger.broken_support().is_empty());
        let claim = ledger.conditional_claim("actuator command is always in range");
        assert!(!claim.contains("PROVIDED"), "nothing was taken on trust: {claim}");
        assert!(claim.contains("holds on every execution"));
    }

    #[test]
    fn a_guard_nobody_proved_total_is_not_deductive_support() {
        let a = Assumption::new(
            "guard::reachable",
            "every model output passes through the guard",
            Boundary::Symbolic,
            AssumptionSupport::RuntimeGuard { location: None, totality_obligation: None },
        );
        assert!(!a.support.is_sound(), "an unproved guard has only moved the assumption");
        assert_eq!(a.support.modality(), Some(Modality::Deductive));
        assert!(a.not_checked_line().contains("not proved total"));
    }

    #[test]
    fn support_naming_an_undischarged_obligation_is_reported_as_broken() {
        let ledger = VerificationLedger::new()
            .with_obligation(ProofObligation::new(
                "lemma::monotone",
                "the scoring function is monotone",
                "score",
                Boundary::Symbolic,
                ObligationStatus::Assumed,
            ))
            .with_assumption(Assumption::new(
                "rank::sound",
                "ranking preserves order",
                Boundary::Symbolic,
                AssumptionSupport::Proved { obligation: "lemma::monotone".into() },
            ));
        assert_eq!(ledger.broken_support().len(), 1, "the lemma was assumed, not proved");
        assert!(
            ledger.not_checked_lines(&["score"]).iter().any(|l| l.contains("does not stand")),
            "a proof resting on an unproved lemma must not read as a proof"
        );
    }

    #[test]
    fn a_premise_two_links_away_is_still_a_premise() {
        // `top` rests on a lemma that is proved. That lemma rests on something
        // nothing proves. `top` therefore rests on it too.
        let ledger = VerificationLedger::new()
            .with_obligation(ProofObligation::new(
                "top",
                "the command is in range",
                "guard::clamp",
                Boundary::Symbolic,
                ObligationStatus::Discharged,
            ))
            .with_obligation(ProofObligation::new(
                "lemma",
                "the guard is interposed",
                "guard::clamp",
                Boundary::Symbolic,
                ObligationStatus::Discharged,
            ))
            .with_assumption(
                Assumption::new(
                    "interposed",
                    "every output crosses the guard",
                    Boundary::Symbolic,
                    AssumptionSupport::Proved { obligation: "lemma".into() },
                )
                .underwrites("top"),
            )
            .with_assumption(
                Assumption::new(
                    "faithful",
                    "the declared dataflow matches the code",
                    Boundary::Symbolic,
                    AssumptionSupport::Undischarged,
                )
                .underwrites("lemma"),
            );

        assert!(
            ledger.assumptions_for("top").iter().all(|a| a.support.is_sound()),
            "the direct check sees nothing wrong, which is exactly the trap"
        );
        let unpaid = ledger.unpaid_premises("top");
        assert_eq!(unpaid.len(), 1);
        assert_eq!(unpaid[0].id, "faithful", "the premise one link further away than anyone looked");
    }

    #[test]
    fn a_cycle_between_proofs_terminates() {
        let ledger = VerificationLedger::new()
            .with_obligation(ProofObligation::new(
                "a",
                "a",
                "c",
                Boundary::Symbolic,
                ObligationStatus::Discharged,
            ))
            .with_obligation(ProofObligation::new(
                "b",
                "b",
                "c",
                Boundary::Symbolic,
                ObligationStatus::Discharged,
            ))
            .with_assumption(
                Assumption::new(
                    "a-needs-b",
                    "b",
                    Boundary::Symbolic,
                    AssumptionSupport::Proved { obligation: "b".into() },
                )
                .underwrites("a"),
            )
            .with_assumption(
                Assumption::new(
                    "b-needs-a",
                    "a",
                    Boundary::Symbolic,
                    AssumptionSupport::Proved { obligation: "a".into() },
                )
                .underwrites("b"),
            );
        assert!(ledger.unpaid_premises("a").is_empty());
    }

    #[test]
    fn a_component_nobody_specified_is_reported_rather_than_counted_as_verified() {
        let ledger = VerificationLedger::new().with_obligation(guard_proved());
        let vacuous = ledger.vacuous(&["guard::clamp", "planner::expand"]);
        assert_eq!(vacuous, vec!["planner::expand"]);
        assert!(
            ledger
                .not_checked_lines(&["guard::clamp", "planner::expand"])
                .iter()
                .any(|l| l.contains("verifies trivially")),
            "vacuous verification is the deductive analogue of a clean scan over no files"
        );
    }

    #[test]
    fn a_failed_obligation_refuses_the_claim_outright() {
        let ledger = VerificationLedger::new().with_obligation(ProofObligation::new(
            "guard::clamp/ensures/0",
            "output is within the actuator's rated range",
            "guard::clamp",
            Boundary::Symbolic,
            ObligationStatus::Failed { counterexample: Some("input = NaN".into()) },
        ));
        let claim = ledger.conditional_claim("actuator command is always in range");
        assert!(claim.contains("NOT established"));
        assert!(claim.contains("defect report, not a gap"));
    }

    #[test]
    fn an_unattempted_obligation_is_not_an_assumed_one() {
        let ledger = VerificationLedger::new().with_obligation(ProofObligation::new(
            "guard::clamp/ensures/0",
            "output is within the actuator's rated range",
            "guard::clamp",
            Boundary::Symbolic,
            ObligationStatus::NotAttempted { reason: "verus not installed".into() },
        ));
        assert_eq!(ledger.not_attempted().count(), 1);
        assert_eq!(ledger.discharged().count(), 0);
        assert!(
            ledger
                .not_checked_lines(&["guard::clamp"])
                .iter()
                .any(|l| l.contains("never ruled on")),
            "nobody judged this; that is not the same as granting it"
        );
    }

    #[test]
    fn the_two_modalities_say_different_things_about_silence() {
        assert_ne!(Modality::Deductive.silence_means(), Modality::Inductive.silence_means());
        assert!(Modality::Deductive.silence_means().contains("vacuously"));
        assert!(Modality::Inductive.silence_means().contains("unbounded"));
    }
}

/// The architecture of a learned component.
///
/// Recorded because **parameter count is the wrong question**. What decides
/// whether any prover can say something about a network is its *operator set*:
/// piecewise-linear operators (affine, ReLU, max-pool) admit exact bound
/// propagation and complete search, while softmax, `tanh`, products of two
/// input-dependent tensors, and unbounded recurrence each cost either precision
/// or decidability. A four-layer transformer is far harder than a
/// twenty-times-larger convolutional net, and a size ceiling applied to both
/// would be wrong about one of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "architecture", rename_all = "kebab-case")]
pub enum Architecture {
    /// Fully connected, piecewise-linear activations. The best-supported case
    /// by a wide margin: everything is affine between kinks.
    Mlp,
    /// Convolutional. Convolution is affine and max-pooling is piecewise-linear,
    /// so the same methods apply at larger sizes than an MLP would allow.
    Cnn,
    /// Recurrent (LSTM, GRU, vanilla). Two costs: the recurrence must be
    /// unrolled to a stated number of steps before anything can be proved — the
    /// same shape of caveat as CBMC's unwinding bound — and the gate
    /// nonlinearities are not piecewise-linear, so bounds loosen with depth.
    Rnn,
    /// Self-attention. Hard for a specific reason worth stating: attention
    /// multiplies two tensors that both depend on the input, and bound
    /// propagation over a product of two intervals is far looser than over an
    /// affine map. Softmax compounds it.
    Transformer,
    /// Selective state-space (Mamba and relatives). Input-dependent gating over
    /// a recurrence: it inherits the RNN's unrolling requirement and the
    /// transformer's input-dependent-product problem at once.
    StateSpace,
    /// Encoder/decoder with a sampled latent (VAE). The sampling step is not a
    /// function of its input, so it is not something a prover can be pointed at.
    Autoencoder,
    /// Generator/discriminator pair. Each half is an ordinary feed-forward
    /// network; the pair is not one network.
    Gan,
    /// Anything else, named. Treated as unknown rather than guessed at.
    Other { name: String },
}

impl Architecture {
    pub fn as_str(&self) -> &str {
        match self {
            Architecture::Mlp => "mlp",
            Architecture::Cnn => "cnn",
            Architecture::Rnn => "rnn",
            Architecture::Transformer => "transformer",
            Architecture::StateSpace => "state-space",
            Architecture::Autoencoder => "autoencoder",
            Architecture::Gan => "gan",
            Architecture::Other { name } => name,
        }
    }

    /// True when the architecture is built from operators that are affine or
    /// piecewise-linear throughout. These are the networks a complete verifier
    /// can decide rather than merely bound.
    pub fn is_piecewise_linear(&self) -> bool {
        matches!(self, Architecture::Mlp | Architecture::Cnn)
    }

    /// True when nothing can be proved until the number of steps is fixed.
    pub fn needs_sequence_bound(&self) -> bool {
        matches!(self, Architecture::Rnn | Architecture::StateSpace)
    }

    /// True when the component is a composite whose parts are individually
    /// tractable but whose whole is not a single function.
    pub fn is_composite(&self) -> bool {
        matches!(self, Architecture::Autoencoder | Architecture::Gan)
    }

    /// Rough parameter count above which no catalogued method reaches, by order
    /// of magnitude.
    ///
    /// Deliberately coarse, and deliberately not a hard limit — it is calibrated
    /// on published competition-scale results and it moves. It exists so a
    /// report can say "this is out of reach, and roughly why" instead of staying
    /// silent, not so anyone can compute a margin from it.
    pub fn reach_ceiling(&self) -> u64 {
        match self {
            // Bound propagation with branch and bound handles convolutional
            // networks of this order; an MLP of the same size is harder per
            // parameter because it is less structured.
            Architecture::Cnn => 5_000_000,
            Architecture::Mlp => 1_000_000,
            // Only after unrolling, and only for short horizons.
            Architecture::Rnn => 200_000,
            // Published transformer verification covers a few layers at small
            // hidden dimensions. This is generous.
            Architecture::Transformer => 10_000_000,
            // Nothing catalogued reaches these at any size; the number is a
            // formality, and the reason is given in words instead.
            Architecture::StateSpace
            | Architecture::Autoencoder
            | Architecture::Gan
            | Architecture::Other { .. } => 0,
        }
    }
}

/// What could be established about a learned component, and what it would take.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "tractability", rename_all = "kebab-case")]
pub enum Tractability {
    /// A catalogued verifier can be pointed at this, over the stated region.
    /// Still a *local* claim about that region, never a global one.
    Reachable { tools: Vec<String> },
    /// Within reach in principle, but a required input was not declared. A gap
    /// in the specification rather than in the tooling — and the only one of
    /// these cases a user can close today without new research.
    Underspecified { missing: Vec<String> },
    /// The composite is not a single function. Its deterministic parts are
    /// analysable; declare them as their own components.
    Decompose { parts: Vec<String>, note: String },
    /// Only research prototypes exist, and their guarantees are narrower than
    /// they first appear.
    ResearchOnly { note: String },
    /// Beyond every catalogued method, for a stated reason.
    OutOfReach { reason: String },
}

impl Tractability {
    /// True only when a tool could actually be run. Every other case means the
    /// component's claims are inductive today.
    pub fn is_reachable(&self) -> bool {
        matches!(self, Tractability::Reachable { .. })
    }
}

/// Everything needed to decide what can be proved about one learned component.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NeuralProfile {
    pub architecture: Architecture,
    /// `None` is treated as out of reach, not as small. An unmeasured model is
    /// not a small one, and this is the only place a missing value could have
    /// been read optimistically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<u64>,
    /// Steps the recurrence is unrolled to, where the architecture needs one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_bound: Option<u32>,
    /// The input region a property is claimed over — an epsilon-ball, a box, a
    /// declared set of latents.
    ///
    /// Every neural verifier proves something about a *region*. Without one
    /// there is no question to ask, which is why its absence is reported as an
    /// underspecification rather than as a tooling gap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_region: Option<String>,
}

impl NeuralProfile {
    pub fn new(architecture: Architecture) -> Self {
        NeuralProfile { architecture, parameters: None, sequence_bound: None, input_region: None }
    }
    pub fn with_parameters(mut self, n: u64) -> Self {
        self.parameters = Some(n);
        self
    }
    pub fn unrolled_to(mut self, steps: u32) -> Self {
        self.sequence_bound = Some(steps);
        self
    }
    pub fn over_region(mut self, region: impl Into<String>) -> Self {
        self.input_region = Some(region.into());
        self
    }

    /// What can be established about this component today.
    pub fn tractability(&self) -> Tractability {
        let arch = &self.architecture;

        if arch.is_composite() {
            let parts = match arch {
                Architecture::Autoencoder => vec!["encoder".to_string(), "decoder".to_string()],
                _ => vec!["generator".to_string(), "discriminator".to_string()],
            };
            return Tractability::Decompose {
                parts,
                note: "each half is an ordinary feed-forward network and can be bounded over a \
                       stated region of its own input; the pair is not a single function, and a \
                       sampling step between them is not a function at all. Declare the \
                       deterministic half you care about as its own component."
                    .to_string(),
            };
        }

        if let Architecture::Other { name } = arch {
            return Tractability::OutOfReach {
                reason: format!(
                    "`{name}` is not a classified architecture here, so nothing is claimed about \
                     what could verify it. Naming it as one of the known kinds, or leaving it \
                     frankly inductive, are both better than a guess"
                ),
            };
        }

        if matches!(arch, Architecture::StateSpace) {
            return Tractability::OutOfReach {
                reason: "a selective state-space model combines an unrolled recurrence with \
                         input-dependent gating, and no catalogued verifier handles the \
                         combination at any size"
                    .to_string(),
            };
        }

        // Size is checked before underspecification, and the order matters for
        // what the report *advises*. Telling someone to declare an input region
        // for a seven-billion-parameter transformer implies the gap is closable
        // by declaring one. It is not: no region makes that network tractable,
        // and an actionable-looking line that leads nowhere is worse than a
        // blunt one.
        if let Some(n) = self.parameters
            && n > arch.reach_ceiling() {
                return Tractability::OutOfReach {
                    reason: format!(
                        "{n} parameters, above the ~{} that published results reach for a {}",
                        arch.reach_ceiling(),
                        arch.as_str()
                    ),
                };
            }

        let mut missing = Vec::new();
        if self.parameters.is_none() {
            missing.push("parameter count".to_string());
        }
        if self.input_region.is_none() {
            missing.push(
                "input region to prove over (every neural verifier bounds a region, not a \
                 network)"
                    .to_string(),
            );
        }
        if arch.needs_sequence_bound() && self.sequence_bound.is_none() {
            missing.push(
                "sequence bound to unroll the recurrence to, which fixes the horizon the result \
                 covers exactly the way an unwinding bound does for a model checker"
                    .to_string(),
            );
        }
        if !missing.is_empty() {
            return Tractability::Underspecified { missing };
        }

        let n = self.parameters.unwrap_or(u64::MAX);
        if matches!(arch, Architecture::Transformer) {
            return Tractability::ResearchOnly {
                note: "transformer verification exists, but it is research code, it covers a few \
                       layers at small hidden dimensions, and it bounds perturbations of the \
                       *embeddings*. A guarantee over an embedding ball is not a guarantee over \
                       the tokens that map into it, so it does not establish what a reader will \
                       assume it does"
                    .to_string(),
            };
        }

        // Complete methods decide; bound propagation only bounds. Both are
        // offered, strongest first, and the ontology carries what each costs.
        let mut tools = Vec::new();
        if arch.is_piecewise_linear() && n <= 100_000 {
            tools.push("ext.marabou".to_string());
            tools.push("ext.nnenum".to_string());
        }
        tools.push("ext.abcrown".to_string());
        Tractability::Reachable { tools }
    }

    /// The `NOT CHECKED` line for this component, or `None` when a verifier
    /// could actually be run against it.
    pub fn not_checked_line(&self, component: &str) -> Option<String> {
        let arch = self.architecture.as_str();
        let line = match self.tractability() {
            Tractability::Reachable { .. } => return None,
            Tractability::Underspecified { missing } => format!(
                "sda.underspecified[{component}]: a {arch} a verifier could be pointed at, but \
                 the run declares no {}. Nothing was proved about it, and that is a gap in the \
                 specification rather than in the tooling",
                missing.join(", and no ")
            ),
            Tractability::Decompose { parts, note } => format!(
                "sda.composite[{component}]: a {arch} is not one function. {note} Its parts are: \
                 {}",
                parts.join(", ")
            ),
            Tractability::ResearchOnly { note } => format!(
                "sda.research-only[{component}]: no production verifier covers a {arch}. {note}"
            ),
            Tractability::OutOfReach { reason } => format!(
                "sda.intractable[{component}]: {reason}. Every claim about this component is \
                 inductive, and no volume of trials makes it otherwise"
            ),
        };
        Some(line)
    }
}

#[cfg(test)]
mod architecture_tests {
    use super::*;

    fn profile(a: Architecture) -> NeuralProfile {
        NeuralProfile::new(a).with_parameters(50_000).over_region("L-inf ball, epsilon = 0.03")
    }

    #[test]
    fn a_small_piecewise_linear_network_can_be_decided_not_merely_bounded() {
        for arch in [Architecture::Mlp, Architecture::Cnn] {
            let t = profile(arch.clone()).tractability();
            let Tractability::Reachable { tools } = t else {
                panic!("a 50k-parameter {} should be reachable, got {t:?}", arch.as_str());
            };
            assert!(
                tools.contains(&"ext.marabou".to_string()),
                "a complete method applies at this size, and it is a stronger result than a bound"
            );
        }
    }

    #[test]
    fn size_alone_does_not_decide_it_architecture_does() {
        let region = "L-inf ball, epsilon = 0.03";
        // A 4M-parameter CNN is within reach; a 4M-parameter MLP is not, and a
        // 4M-parameter transformer is a different answer again.
        let cnn = NeuralProfile::new(Architecture::Cnn)
            .with_parameters(4_000_000)
            .over_region(region)
            .tractability();
        let mlp = NeuralProfile::new(Architecture::Mlp)
            .with_parameters(4_000_000)
            .over_region(region)
            .tractability();
        let transformer = NeuralProfile::new(Architecture::Transformer)
            .with_parameters(4_000_000)
            .over_region(region)
            .tractability();
        assert!(cnn.is_reachable());
        assert!(matches!(mlp, Tractability::OutOfReach { .. }));
        assert!(
            matches!(transformer, Tractability::ResearchOnly { .. }),
            "the same parameter count gives three different answers; that is the point"
        );
    }

    #[test]
    fn a_recurrent_network_is_underspecified_until_the_horizon_is_fixed() {
        let unbounded = NeuralProfile::new(Architecture::Rnn)
            .with_parameters(80_000)
            .over_region("L-inf ball on each step, epsilon = 0.01");
        let Tractability::Underspecified { missing } = unbounded.tractability() else {
            panic!("an unrolled horizon is required before anything can be proved");
        };
        assert!(missing.iter().any(|m| m.contains("unwinding bound")));

        let bounded = unbounded.unrolled_to(16);
        assert!(bounded.tractability().is_reachable(), "with a horizon it is an ordinary network");
        assert!(bounded.not_checked_line("perception").is_none());
    }

    #[test]
    fn a_transformer_result_is_reported_as_being_about_embeddings() {
        let t = profile(Architecture::Transformer).tractability();
        let Tractability::ResearchOnly { note } = t else { panic!("expected research-only") };
        assert!(
            note.contains("not a guarantee over the tokens"),
            "the gap between an embedding ball and text is the part a reader will get wrong"
        );
    }

    #[test]
    fn a_mamba_is_out_of_reach_for_a_stated_reason_rather_than_by_size() {
        let t = NeuralProfile::new(Architecture::StateSpace)
            .with_parameters(1_000)
            .over_region("a box")
            .tractability();
        let Tractability::OutOfReach { reason } = t else { panic!("expected out-of-reach") };
        assert!(reason.contains("input-dependent gating"));
        assert!(!reason.contains("1000"), "size is not the reason, and must not be given as one");
    }

    #[test]
    fn a_generative_pair_is_decomposed_rather_than_refused() {
        for (arch, part) in
            [(Architecture::Autoencoder, "decoder"), (Architecture::Gan, "generator")]
        {
            let t = profile(arch.clone()).tractability();
            let Tractability::Decompose { parts, .. } = t else {
                panic!("a {} should decompose", arch.as_str());
            };
            assert!(parts.contains(&part.to_string()));
        }
        let line = profile(Architecture::Autoencoder).not_checked_line("vae").unwrap();
        assert!(line.contains("sampling step between them is not a function at all"));
    }

    #[test]
    fn an_oversized_model_is_out_of_reach_before_it_is_underspecified() {
        // No input region declared either, but saying "declare a region" here
        // would advertise a fix that does not exist.
        let t = NeuralProfile::new(Architecture::Transformer)
            .with_parameters(7_000_000_000)
            .tractability();
        let Tractability::OutOfReach { reason } = t else {
            panic!("size is not closable by declaring a region: {t:?}");
        };
        assert!(reason.contains("7000000000 parameters"));
    }

    #[test]
    fn an_undeclared_region_is_a_specification_gap_not_a_tooling_one() {
        let t = NeuralProfile::new(Architecture::Mlp).with_parameters(20_000).tractability();
        let Tractability::Underspecified { missing } = t else {
            panic!("no region means no question to ask");
        };
        assert!(missing.iter().any(|m| m.contains("bounds a region, not a network")));
        let line = NeuralProfile::new(Architecture::Mlp)
            .with_parameters(20_000)
            .not_checked_line("perception")
            .unwrap();
        assert!(line.contains("gap in the specification rather than in the tooling"));
    }

    #[test]
    fn an_unmeasured_model_is_not_treated_as_a_small_one() {
        let t = NeuralProfile::new(Architecture::Mlp).over_region("a box").tractability();
        assert!(matches!(t, Tractability::Underspecified { .. }));
    }

    #[test]
    fn an_unclassified_architecture_is_reported_rather_than_guessed_at() {
        let t = NeuralProfile::new(Architecture::Other { name: "diffusion-unet".into() })
            .with_parameters(1_000)
            .over_region("a box")
            .tractability();
        let Tractability::OutOfReach { reason } = t else { panic!("expected out-of-reach") };
        assert!(reason.contains("diffusion-unet"));
        assert!(reason.contains("better than a guess"));
    }
}
