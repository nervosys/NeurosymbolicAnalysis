//! Whether every path from a model to an effector passes through the guard.
//!
//! At language-model scale the guard carries the whole safety case, and the
//! whole safety case rests on one premise: that a model's output cannot reach an
//! effector without going through it. Until now that premise was an
//! [`AssumptionSupport::RuntimeGuard`] — trusted, with nothing behind it.
//!
//! It does not have to be. Interposition is not a claim about what the model
//! does; it is a claim about the *shape of the program*, and reachability over a
//! dataflow graph is decidable. So this module proves it, over a declared
//! [`FlowGraph`], and produces a discharged or failed [`ProofObligation`] for
//! each model/effector pair.
//!
//! **What that does and does not buy, stated plainly.** It does not make
//! interposition unconditional. It replaces one large premise — *the guard is
//! interposed* — with a smaller and much more checkable one: *this dataflow
//! declaration matches the code*. That residual premise is emitted as
//! [`FAITHFULNESS`], and it stays [`AssumptionSupport::Undischarged`] on
//! purpose. Reporting the swap as a proof of interposition would be laundering
//! of exactly the kind [`crate::neurosymbolic`] refuses elsewhere.
//!
//! **Taint findings refute; they never confirm.** A taint flow running from a
//! model to an effector without crossing a guard is a counterexample, and it
//! fails the obligation outright — the declaration was wrong, or the code
//! changed under it. A taint run that finds nothing establishes nothing, because
//! the catalogued taint providers are heuristic and their silence is worth what
//! the ontology says it is worth. This is the same asymmetry `sda_ai::probe`
//! has always stated about probes, applied to a different instrument: it can
//! demonstrate a bypass, never its absence.
//!
//! **A taint finding with no dataflow trace cannot refute anything, and that is
//! the common case.** Refutation needs the *path*, not the endpoint: a finding
//! that names only where tainted data landed cannot say whether it crossed a
//! guard on the way. Real Semgrep OSS 1.176.0 emits exactly that — a sink
//! location and nothing else — even when run with `--dataflow-traces`, whose own
//! help text says it "only affects text and SARIF output". It does affect the
//! text output, which prints `Taint comes from:` and the intermediate variables;
//! the SARIF carries no `codeFlows` at all. The fixture at
//! `tests/fixtures/semgrep-1.176.0-taint.sarif` was captured from that run.
//!
//! So a traceless finding that lands on an effector is reported as
//! [`Interposition::unevaluable_taint`] and reaches `NOT CHECKED`. Skipping it
//! silently — which is what this module did when it was first written — turns a
//! taint report that could not participate into a proof that looks clean, and
//! that is the `ext.modelscan` failure with a different tool attached.

use crate::neurosymbolic::{Component, Role, SystemMap};
use sda_core::verification::{
    Architecture, Assumption, AssumptionSupport, Boundary, NeuralProfile, ObligationStatus,
    ProofObligation, VerificationLedger,
};
use sda_core::{Evidence, Finding};
use sda_rules::ArchitectureDeclaration;
use std::collections::BTreeSet;

/// Id of the assumption every interposition proof rests on.
pub const FAITHFULNESS: &str = "flow::declaration-faithful";

/// Ceiling on enumerated paths per model/effector pair.
///
/// A declared architecture graph is small by construction — components, not
/// functions — so hitting this means the declaration has grown into something
/// that is no longer being read by a human either. It is reported rather than
/// silently truncated: a partial enumeration that concluded "interposed" would
/// be a proof over the paths that happened to be visited first.
pub const MAX_PATHS: usize = 4096;

/// One declared dataflow edge between components.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Edge {
    pub from: String,
    pub to: String,
}

/// The declared dataflow between components.
#[derive(Clone, Debug, Default)]
pub struct FlowGraph {
    pub edges: Vec<Edge>,
}

impl FlowGraph {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn edge(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.edges.push(Edge { from: from.into(), to: to.into() });
        self
    }
    fn successors<'a>(&'a self, of: &str) -> impl Iterator<Item = &'a str> {
        self.edges.iter().filter(move |e| e.from == of).map(|e| e.to.as_str())
    }
    /// Component names appearing in an edge but not declared in the map. A typo
    /// here silently removes a path from the analysis, so it is reported.
    fn undeclared(&self, map: &SystemMap) -> Vec<String> {
        let known: BTreeSet<&str> = map.names().into_iter().collect();
        let mut out: BTreeSet<String> = BTreeSet::new();
        for e in &self.edges {
            for n in [&e.from, &e.to] {
                if !known.contains(n.as_str()) {
                    out.insert(n.clone());
                }
            }
        }
        out.into_iter().collect()
    }
}

/// A path from a model to an effector that never crosses a guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bypass {
    pub model: String,
    pub effector: String,
    /// The component names in order, model first.
    pub path: Vec<String>,
    /// Set when a taint finding produced this rather than the declared graph.
    pub witness: Option<String>,
}

impl Bypass {
    pub fn describe(&self) -> String {
        let how = match &self.witness {
            Some(w) => format!("observed by taint analysis (`{w}`)"),
            None => "present in the declared dataflow".to_string(),
        };
        format!(
            "`{}` reaches the effector `{}` without crossing a guard, {how}: {}",
            self.model,
            self.effector,
            self.path.join(" -> ")
        )
    }
}

/// The result of checking interposition.
#[derive(Clone, Debug, Default)]
pub struct Interposition {
    /// One per model/effector pair with at least one declared path.
    pub obligations: Vec<ProofObligation>,
    /// The residual premise, always present when anything was proved.
    pub assumptions: Vec<Assumption>,
    pub bypasses: Vec<Bypass>,
    /// Taint findings that landed on an effector carrying no dataflow trace.
    ///
    /// These neither refuted nor supported anything, and the distinction from
    /// "no taint finding was reported" is the whole point: one means the tool
    /// looked and found nothing, the other means the tool cannot answer the
    /// question that was asked of it.
    pub unevaluable_taint: Vec<String>,
    pub not_checked: Vec<String>,
}

impl Interposition {
    pub fn is_interposed(&self) -> bool {
        !self.obligations.is_empty()
            && self.obligations.iter().all(|o| o.status.is_discharged())
            && self.bypasses.is_empty()
    }
    /// Fold into a ledger, so the interposition proof is adjudicated by the same
    /// machinery as every other obligation.
    pub fn merge_into(&self, mut ledger: VerificationLedger) -> VerificationLedger {
        ledger.obligations.extend(self.obligations.iter().cloned());
        ledger.assumptions.extend(self.assumptions.iter().cloned());
        ledger
    }
}

/// Prove — or refute — that every model reaches every effector through a guard.
///
/// `taint` are findings from a taint provider, which may refute the declared
/// graph. Pass an empty slice when none ran; the result then rests on the
/// declaration alone, and says so.
pub fn verify(map: &SystemMap, flow: &FlowGraph, taint: &[Finding]) -> Interposition {
    let mut out = Interposition::default();

    let models: Vec<&Component> =
        map.components.iter().filter(|c| c.boundary == Boundary::Neural).collect();
    let effectors: Vec<&Component> =
        map.components.iter().filter(|c| c.role == Role::Effector).collect();

    for name in flow.undeclared(map) {
        out.not_checked.push(format!(
            "sda.flow-undeclared[{name}]: named in a dataflow edge but not declared as a \
             component. The edge was still followed, but nothing is known about what that name \
             is, and a typo here removes a path from the analysis silently"
        ));
    }

    if effectors.is_empty() {
        out.not_checked.push(
            "sda.no-effector: no component is declared an effector, so interposition was not \
             checked. This is not a clean result — it is the absence of a question"
                .to_string(),
        );
        return out;
    }
    // The mirror of the check above, and it was missing. Interposition is a
    // claim about a guard sitting between a *model* and an effector; with no
    // component declared `boundary = "neural"` there is no model, the loop below
    // never runs, and `obligations` stays empty — which `summarize` used to
    // render as "no model reaches a declared effector by any declared path". A
    // sentence about models and paths, in a declaration that names no model.
    //
    // A reader cannot tell that from the reassuring version of the same words,
    // where a model was declared and genuinely reaches nothing. Returning early
    // also keeps `sda.no-guard` below from firing, which would otherwise say
    // "every path from a model to an effector is therefore a bypass" about a
    // system with no models in it — vacuous, and vacuous entries are what teach
    // people to skim this section.
    if models.is_empty() {
        out.not_checked.push(
            "sda.no-model: no component is declared with `boundary = \"neural\"`, so there is \
             no model output for a guard to be interposed on and interposition was not checked. \
             This is not a clean result — it is the absence of a question. A component that is a \
             model and is declared symbolic reaches here, and nothing else in the run will say so"
                .to_string(),
        );
        return out;
    }

    if map.components.iter().all(|c| c.role != Role::Guard) {
        out.not_checked.push(
            "sda.no-guard: no component is declared a guard. Every path from a model to an \
             effector is therefore a bypass, and the safety case has nothing to rest on"
                .to_string(),
        );
    }

    for model in &models {
        for effector in &effectors {
            let (paths, truncated) = enumerate(flow, &model.name, &effector.name);
            if truncated {
                out.not_checked.push(format!(
                    "sda.flow-truncated[{} -> {}]: more than {MAX_PATHS} paths; enumeration \
                     stopped, so interposition was NOT established for this pair. A partial \
                     enumeration that concluded `interposed` would be a proof about the paths \
                     visited first",
                    model.name, effector.name
                ));
                continue;
            }
            if paths.is_empty() {
                // The third way `obligations` can come back empty, and the only
                // one that was silent. `summarize` now tells the reader that
                // NOT CHECKED names which part of the declaration is missing,
                // and that promise has to hold here too or it is one more claim
                // this tool cannot cash.
                //
                // Vacuously true is not the same as verified — the same
                // distinction `sda.vacuous` already draws for a component with
                // no proof obligation. A model and an effector declared in one
                // system with nothing connecting them is far more often a flow
                // edge nobody wrote than a real absence of reach.
                out.not_checked.push(format!(
                    "sda.flow-disconnected[{} -> {}]: both are declared and no declared path \
                     connects them, so there is no flow for a guard to sit on. If the model \
                     genuinely cannot reach the effector this is correct and vacuous; if a flow \
                     edge is missing, the proof is over a graph the program does not have",
                    model.name, effector.name
                ));
                continue;
            }

            let guarded = |p: &Vec<String>| {
                p.iter().any(|n| {
                    map.components.iter().any(|c| c.name == *n && c.role == Role::Guard)
                })
            };
            let bypass = paths.iter().find(|p| !guarded(p));

            let id = format!("flow::{}->{}/interposed", model.name, effector.name);
            let statement = format!(
                "every declared dataflow path from `{}` to `{}` crosses a guard",
                model.name, effector.name
            );
            match bypass {
                Some(p) => {
                    let b = Bypass {
                        model: model.name.clone(),
                        effector: effector.name.clone(),
                        path: p.clone(),
                        witness: None,
                    };
                    out.obligations.push(
                        ProofObligation::new(
                            &id,
                            &statement,
                            &effector.name,
                            Boundary::Symbolic,
                            ObligationStatus::Failed { counterexample: Some(b.describe()) },
                        )
                        .proved_by("sda.interposition"),
                    );
                    out.bypasses.push(b);
                }
                None => out.obligations.push(
                    ProofObligation::new(
                        &id,
                        &statement,
                        &effector.name,
                        Boundary::Symbolic,
                        ObligationStatus::Discharged,
                    )
                    .proved_by("sda.interposition"),
                ),
            }
        }
    }

    // Taint that could have refuted and could not be read. Reported before the
    // refutations, because a reader who stops early must still see that the
    // instrument they supplied was blind.
    let mut untraced_briefly: Vec<String> = Vec::new();
    for f in taint {
        if f.evidence.iter().any(|e| matches!(e, Evidence::Trace { frames } if frames.len() >= 2))
        {
            continue;
        }
        let path = f.location.file.to_string_lossy().replace('\\', "/");
        let Some(c) = map.component_for(&path) else { continue };
        if c.role != Role::Effector {
            continue;
        }
        untraced_briefly.push(format!("`{}` at {}", f.rule, f.location.display()));
        out.unevaluable_taint.push(format!(
            "sda.taint-untraced[{}]: landed on the effector `{}` at {} with no dataflow trace. \
             Refutation needs the path, not the endpoint — without it nothing can say whether a \
             guard was crossed, so this finding neither refuted nor supported interposition",
            f.rule,
            c.name,
            f.location.display()
        ));
    }
    // One line each while a reader can act on them, a count past that.
    //
    // Same bound as `sda.unmapped` in `neurosymbolic`, for the same reason: this
    // is one entry per *taint finding*, so a real CodeQL report sets the length
    // of the section that exists to be read. Measured at four on a three-file
    // fixture; the ceiling is however many findings the report carries.
    //
    // The detail is not lost — `unevaluable_taint` keeps every line for a
    // programmatic caller, and the paragraph above already states the count in
    // prose. What changes is only how much of *NOT CHECKED* a single cause may
    // occupy.
    const NAME_EACH_UP_TO: usize = 3;
    if out.unevaluable_taint.len() <= NAME_EACH_UP_TO {
        out.not_checked.extend(out.unevaluable_taint.iter().cloned());
    } else {
        // Built from the findings, not by quoting one of the sentences above:
        // embedding a whole formatted line inside another repeated its prefix
        // and its explanation, which made the one entry that replaced forty
        // harder to read than any of them.
        let shown = NAME_EACH_UP_TO.min(untraced_briefly.len());
        out.not_checked.push(format!(
            "sda.taint-untraced: {} taint finding(s) landed on a declared effector with no \
             dataflow trace, so none of them could say whether a guard was crossed — refutation \
             needs the path, not the endpoint. The first {}: {}",
            untraced_briefly.len(),
            shown,
            untraced_briefly[..shown].join(", ")
        ));
    }
    if !taint.is_empty() && out.unevaluable_taint.len() == taint.len() {
        out.not_checked.push(format!(
            "sda.taint-inert: all {} supplied taint finding(s) lack a dataflow trace, so the \
             taint report could not participate in this proof at all. Whatever it says, \
             interposition here rests on the declaration alone",
            taint.len()
        ));
    }

    // Taint refutes. A flow the declaration does not admit fails the obligation
    // it contradicts, whatever the graph said.
    for b in taint_bypasses(map, taint) {
        let id = format!("flow::{}->{}/interposed", b.model, b.effector);
        if let Some(o) = out.obligations.iter_mut().find(|o| o.id == id) {
            o.status = ObligationStatus::Failed { counterexample: Some(b.describe()) };
        } else {
            out.obligations.push(
                ProofObligation::new(
                    &id,
                    format!(
                        "every path from `{}` to `{}` crosses a guard",
                        b.model, b.effector
                    ),
                    &b.effector,
                    Boundary::Symbolic,
                    ObligationStatus::Failed { counterexample: Some(b.describe()) },
                )
                .proved_by("sda.interposition"),
            );
        }
        out.bypasses.push(b);
    }

    if !out.obligations.is_empty() {
        out.assumptions.push(
            Assumption::new(
                FAITHFULNESS,
                "the declared dataflow graph matches the code — every edge the program can take \
                 is an edge in the declaration",
                Boundary::Symbolic,
                // Undischarged on purpose. Reachability over the declaration is
                // decidable and was decided; whether the declaration *is* the
                // program is a different question, and no clean taint run
                // answers it, because a heuristic tool's silence is not a proof
                // that no other edge exists.
                AssumptionSupport::Undischarged,
            )
            .underwrites_all(out.obligations.iter().map(|o| o.id.clone())),
        );
    }
    out
}

/// Taint flows that run from a model to an effector without crossing a guard.
///
/// A taint finding is read through its [`Evidence::Trace`]: the first frame is
/// where the data came from and the last is where it landed. A finding with no
/// trace names one location and cannot describe a flow, so it is skipped rather
/// than guessed at — the same refusal `RuntimeEventKind::from_cwe` makes.
fn taint_bypasses(map: &SystemMap, taint: &[Finding]) -> Vec<Bypass> {
    let mut out: Vec<Bypass> = Vec::new();
    for f in taint {
        // *Every* trace on the finding, not the first. Refutation is an
        // existential claim — one route that reaches the effector without
        // crossing a guard is a counterexample — so stopping at the first trace
        // makes the verdict depend on the order the producer emitted its flows.
        // A real `cpp/command-line-injection` result carries three code flows,
        // the first through the guard and the second around it; reading only the
        // first left the proof standing on a report that contained its own
        // refutation.
        let traces = f.evidence.iter().filter_map(|e| match e {
            Evidence::Trace { frames } if frames.len() >= 2 => Some(frames),
            _ => None,
        });
        for frames in traces {
            let mut ordered: Vec<_> = frames.iter().collect();
            ordered.sort_by_key(|fr| fr.step);

            let component_of = |fr: &sda_core::TraceFrame| {
                let p = fr.location.file.to_string_lossy().replace('\\', "/");
                map.component_for(&p)
            };
            // The component sequence the trace visits, with frames in no
            // declared component dropped and runs collapsed.
            let path: Vec<String> = ordered
                .iter()
                .filter_map(|fr| component_of(fr).map(|c| c.name.clone()))
                .fold(Vec::new(), |mut acc, n| {
                    if acc.last() != Some(&n) {
                        acc.push(n);
                    }
                    acc
                });
            let role_of = |name: &str| map.components.iter().find(|c| c.name == name);

            // The effector must be where the flow *ends*; that is the sink.
            let Some(sink) = path.last().and_then(|n| role_of(n)) else { continue };
            if sink.role != Role::Effector {
                continue;
            }

            // The model need not be where the flow *begins*. This used to require
            // it, and the requirement held only by accident: CodeQL's Python
            // source was `request` inside `policy/serve.py`, so the trace started
            // in the neural component. The C++ source is `argv`, which enters at
            // `main` — outside every declared component — and the same claim
            // arrived as a trace the check silently skipped.
            //
            // The claim is *"model output cannot reach an effector without
            // crossing a guard"*, so what matters is the segment from the last
            // visit to a neural component onward. Anything before that is how the
            // data reached the model, which is a different question.
            let Some(from) = path
                .iter()
                .rposition(|n| role_of(n).is_some_and(|c| c.boundary == Boundary::Neural))
            else {
                continue;
            };
            let path: Vec<String> = path[from..].to_vec();
            let src = match role_of(&path[0]) {
                Some(c) => c,
                None => continue,
            };
            let crosses_guard = path
                .iter()
                .any(|n| role_of(n).is_some_and(|c| c.role == Role::Guard));
            if crosses_guard {
                continue;
            }
            // Two code flows can reduce to the same component path — the C++
            // capture's first and third differ only in a step through a system
            // header. One counterexample reported twice is two counterexamples
            // in the report and in the count, and they are the same bypass.
            let bypass = Bypass {
                model: src.name.clone(),
                effector: sink.name.clone(),
                path,
                witness: Some(f.rule.to_string()),
            };
            if !out.iter().any(|b| {
                b.model == bypass.model && b.effector == bypass.effector && b.path == bypass.path
            }) {
                out.push(bypass);
            }
        }
    }
    out
}

/// Every simple path from `from` to `to`, and whether enumeration was cut short.
fn enumerate(flow: &FlowGraph, from: &str, to: &str) -> (Vec<Vec<String>>, bool) {
    let mut paths = Vec::new();
    let mut stack = vec![from.to_string()];
    let mut visited: BTreeSet<String> = [from.to_string()].into_iter().collect();
    let truncated = walk(flow, from, to, &mut stack, &mut visited, &mut paths);
    (paths, truncated)
}

fn walk(
    flow: &FlowGraph,
    at: &str,
    to: &str,
    stack: &mut Vec<String>,
    visited: &mut BTreeSet<String>,
    paths: &mut Vec<Vec<String>>,
) -> bool {
    if at == to {
        paths.push(stack.clone());
        return false;
    }
    for next in flow.successors(at).map(str::to_string).collect::<Vec<_>>() {
        if paths.len() >= MAX_PATHS {
            return true;
        }
        // Cycles are skipped rather than followed. A cycle adds no component a
        // simple path does not already contain, so it cannot turn a guarded
        // path into a bypass or the reverse.
        if !visited.insert(next.clone()) {
            continue;
        }
        stack.push(next.clone());
        let truncated = walk(flow, &next, to, stack, visited, paths);
        stack.pop();
        visited.remove(&next);
        if truncated {
            return true;
        }
    }
    false
}

/// The bypasses of an interposition result, as findings.
///
/// A refuted proof has to survive the report's machine formats, not only its
/// prose. `sda verify` prints [`summarize`] and a human reads it; a `scan` that
/// folded interposition in and reported the refutation *only* in a summary
/// string would emit JSON and SARIF in which a model reaching an effector
/// unguarded does not appear at all — the CI gate that consumes those would pass
/// the very system this check exists to stop.
///
/// The finding is located at the declaration, not in code: what failed is the
/// claim the project made about its own dataflow, and for a bypass derived from
/// the declared graph alone there is no source line that is wrong. A bypass with
/// a taint `witness` also carries its witnessing rule in the message, so the two
/// provenances are never conflated — one is a deduction over what was declared,
/// the other an observation that contradicted it.
pub fn findings_from(i: &Interposition, declaration: &str) -> Vec<Finding> {
    i.bypasses
        .iter()
        .map(|b| {
            // Observed beats declared: a taint tool walked the code and found the
            // path, which is not in doubt in the way a declaration is.
            let confidence = match &b.witness {
                Some(_) => sda_core::Confidence::Certain,
                None => sda_core::Confidence::High,
            };
            Finding::new(
                "sda.interposition",
                "SDA-INTERPOSE-01",
                format!("`{}` reaches the effector `{}` without crossing a guard", b.model, b.effector),
                sda_core::Severity::Critical,
                sda_core::Location::file_only(declaration),
            )
            .phase(sda_core::AnalysisPhase::Static)
            .confidence(confidence)
            .message(b.describe())
            .remediation(
                "Route the flow through a component declared with `role = \"guard\"`, or correct \
                 the declaration if the guard is already there and unlisted."
                    .to_string(),
            )
        })
        .collect()
}

/// The paragraph an interposition result contributes to a report.
pub fn summarize(i: &Interposition) -> String {
    if i.obligations.is_empty() {
        // Deliberately says nothing about models or paths. Three different
        // situations land here — no effector declared, no model declared, and a
        // declaration holding both that are genuinely unconnected — and only the
        // third is a fact about paths. Naming the specific reason is `NOT
        // CHECKED`'s job, and it holds one for each, so this points there rather
        // than guessing which one the reader is in.
        return "Interposition: not checked — no model/effector pair was available to prove \
                anything about. See NOT CHECKED for which part of the declaration is missing."
            .to_string();
    }
    let failed = i.obligations.iter().filter(|o| !o.status.is_discharged()).count();
    if failed > 0 {
        return format!(
            "Interposition: NOT established. {failed} of {} model/effector pair(s) have a path \
             that never crosses a guard:\n  {}",
            i.obligations.len(),
            i.bypasses.iter().map(Bypass::describe).collect::<Vec<_>>().join("\n  ")
        );
    }
    let mut s = format!(
        "Interposition: {} model/effector pair(s) proved guarded over the declared dataflow. \
         That reduces the safety case's premise from `the guard is interposed` to `the \
         declaration matches the code`; it does not remove it, and the smaller premise is listed \
         in NOT CHECKED as `{FAITHFULNESS}`.",
        i.obligations.len()
    );
    if !i.unevaluable_taint.is_empty() {
        s.push_str(&format!(
            "\n  {} taint finding(s) landed on an effector with no dataflow trace and could not \
             be read either way. A proof that a blind instrument did not contradict is not a \
             proof that was tested.",
            i.unevaluable_taint.len()
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::verification::Architecture;
    use sda_core::{AnalysisPhase, Location, NeuralProfile, Severity, TraceFrame};

    fn map() -> SystemMap {
        SystemMap::new()
            .with(
                Component::neural("policy", "models/policy").profiled(
                    NeuralProfile::new(Architecture::Transformer).with_parameters(7_000_000_000),
                ),
            )
            .with(Component::symbolic("guard::clamp", "src/guard").guard())
            .with(Component::symbolic("actuator::drive", "src/actuator").effector())
            .with(Component::symbolic("telemetry", "src/telemetry"))
    }

    fn guarded_flow() -> FlowGraph {
        FlowGraph::new().edge("policy", "guard::clamp").edge("guard::clamp", "actuator::drive")
    }

    #[test]
    fn a_guarded_declaration_discharges_the_obligation() {
        let i = verify(&map(), &guarded_flow(), &[]);
        assert_eq!(i.obligations.len(), 1);
        assert!(i.is_interposed());
        assert!(i.obligations[0].status.is_discharged());
    }

    #[test]
    fn the_proof_keeps_its_residual_premise_rather_than_claiming_interposition_outright() {
        let i = verify(&map(), &guarded_flow(), &[]);
        let a = &i.assumptions[0];
        assert_eq!(a.id, FAITHFULNESS);
        assert!(
            !a.support.is_sound(),
            "reachability over a declaration is decidable; whether the declaration is the \
             program is not, and calling it proved would be the laundering this refuses"
        );
        assert_eq!(a.supports, vec![i.obligations[0].id.clone()]);

        // And the ledger it folds into therefore still produces a conditional claim.
        let ledger = i.merge_into(VerificationLedger::new());
        let claim = ledger.conditional_claim("the actuator is never commanded out of range");
        assert!(claim.contains("PROVIDED"), "{claim}");
        assert!(claim.contains("declared dataflow graph matches the code"));
    }

    /// A declaration naming no model says the question was never asked.
    ///
    /// The mirror of `no_declared_effector_is_an_absent_question_not_a_clean_answer`,
    /// which existed; this one did not. With no neural component the pair loop
    /// never runs, `obligations` stays empty, and the report used to render that
    /// as "no model reaches a declared effector by any declared path" — a claim
    /// about models and paths, made of a declaration containing neither.
    ///
    /// The reassuring reading of that sentence and the empty one are the same
    /// words, which is the whole problem. A component that is a model and was
    /// declared symbolic — a judgement, not a typo, so the parser cannot catch
    /// it — lands here.
    #[test]
    fn no_declared_model_is_an_absent_question_not_a_clean_answer() {
        let m = SystemMap::new()
            .with(Component::symbolic("core", "src/core"))
            .with(Component::symbolic("actuator::drive", "src/actuator").effector());
        let flow = FlowGraph::new().edge("core", "actuator::drive");
        let i = verify(&m, &flow, &[]);

        assert!(i.obligations.is_empty(), "there is no model, so there is nothing to prove");
        assert!(
            i.not_checked.iter().any(|n| n.starts_with("sda.no-model:")),
            "the absent question must be named: {:?}",
            i.not_checked
        );
        assert!(
            !summarize(&i).contains("no model reaches"),
            "and the summary must not report a path result it never computed: {}",
            summarize(&i)
        );
    }

    /// And it does not also complain that no guard is declared.
    ///
    /// "Every path from a model to an effector is therefore a bypass" is vacuous
    /// in a system with no models. A *NOT CHECKED* section carrying entries that
    /// are true only because nothing exists is one people learn to skim, which
    /// costs the entries that matter.
    #[test]
    fn a_system_with_no_model_does_not_also_report_a_missing_guard() {
        let m = SystemMap::new()
            .with(Component::symbolic("core", "src/core"))
            .with(Component::symbolic("actuator::drive", "src/actuator").effector());
        let i = verify(&m, &FlowGraph::new().edge("core", "actuator::drive"), &[]);

        assert!(
            i.not_checked.iter().all(|n| !n.contains("sda.no-guard")),
            "vacuous in a system with no models: {:?}",
            i.not_checked
        );
    }

    /// A model and an effector that nothing connects is reported, not passed over.
    ///
    /// This was the silent one. `paths.is_empty()` simply `continue`d, so a
    /// declaration whose flow section is missing an edge produced no obligation,
    /// no notice, and a summary saying interposition was not checked — with
    /// nothing anywhere to say which part was missing.
    #[test]
    fn a_model_and_effector_with_no_path_between_them_is_reported() {
        let m = SystemMap::new()
            .with(Component::neural("policy", "models/policy"))
            .with(Component::symbolic("guard::clamp", "src/guard").guard())
            .with(Component::symbolic("actuator::drive", "src/actuator").effector());
        // Declared, guarded, and connected to nothing.
        let i = verify(&m, &FlowGraph::new().edge("policy", "guard::clamp"), &[]);

        assert!(i.obligations.is_empty());
        assert!(
            i.not_checked.iter().any(|n| n.starts_with("sda.flow-disconnected[policy")),
            "a missing flow edge and a genuine absence of reach look identical here, and only \
             one of them is safe: {:?}",
            i.not_checked
        );
    }

    /// Every way the proof can come back empty leaves a reason behind.
    ///
    /// `summarize` tells the reader that *NOT CHECKED* names which part of the
    /// declaration is missing. That is a promise, and this is what keeps it: all
    /// three ways `obligations` can come back empty are built here, and each is
    /// asserted to leave the specific entry that explains it.
    ///
    /// It pins the three that exist; it cannot force a fourth to declare itself,
    /// because nothing here is an exhaustive match. If a later `continue` skips a
    /// pair without a notice, the summary starts pointing at a section that does
    /// not hold the answer, and this test will not notice. Said plainly rather
    /// than left implied, because a test trusted past what it checks is worse
    /// than no test.
    #[test]
    fn an_empty_proof_always_says_which_part_of_the_declaration_was_missing() {
        let effector_only = SystemMap::new()
            .with(Component::symbolic("core", "src/core"))
            .with(Component::symbolic("actuator::drive", "src/actuator").effector());
        let model_only = SystemMap::new()
            .with(Component::neural("policy", "models/policy"))
            .with(Component::symbolic("core", "src/core"));
        let unconnected = SystemMap::new()
            .with(Component::neural("policy", "models/policy"))
            .with(Component::symbolic("actuator::drive", "src/actuator").effector());

        // Each case names the reason it must give, not merely that it gave one.
        // The first draft asserted any `sda.`-prefixed entry, and passed under
        // mutation because the vacuous `sda.no-guard` satisfied it — a test
        // checking that something was said rather than that the right thing was.
        let cases = [
            ("no model declared", effector_only, FlowGraph::new().edge("core", "actuator::drive"), "sda.no-model"),
            ("no effector declared", model_only, FlowGraph::new().edge("policy", "core"), "sda.no-effector"),
            ("declared but unconnected", unconnected, FlowGraph::new(), "sda.flow-disconnected"),
        ];

        for (what, m, flow, marker) in cases {
            let i = verify(&m, &flow, &[]);
            assert!(i.obligations.is_empty(), "{what}: expected nothing to prove");
            assert!(
                i.not_checked.iter().any(|n| n.starts_with(marker)),
                "{what}: the summary points at NOT CHECKED, so NOT CHECKED must hold the \
                 reason: {:?}",
                i.not_checked
            );
            assert!(
                summarize(&i).contains("See NOT CHECKED"),
                "{what}: and the summary must send the reader there"
            );
        }
    }

    #[test]
    fn summarize_says_what_the_proof_bought_and_what_it_did_not() {
        let s = summarize(&verify(&map(), &guarded_flow(), &[]));
        assert!(s.contains("proved guarded over the declared dataflow"));
        assert!(s.contains("it does not remove it"));
    }

    #[test]
    fn a_path_around_the_guard_fails_the_obligation_with_the_path_as_counterexample() {
        let flow = guarded_flow().edge("policy", "telemetry").edge("telemetry", "actuator::drive");
        let i = verify(&map(), &flow, &[]);
        assert!(!i.is_interposed());
        assert_eq!(i.bypasses.len(), 1);
        assert_eq!(i.bypasses[0].path, ["policy", "telemetry", "actuator::drive"]);
        assert!(matches!(i.obligations[0].status, ObligationStatus::Failed { .. }));
        assert!(summarize(&i).contains("NOT established"));
    }

    #[test]
    fn a_taint_flow_around_the_guard_refutes_a_declaration_that_looked_clean() {
        let finding = Finding::new(
            "ext.codeql",
            "rust/model-output-to-actuator",
            "model output reaches the actuator",
            Severity::High,
            Location::new("src/actuator/drive.rs", 88, 5),
        )
        .phase(AnalysisPhase::Static)
        .evidence(Evidence::Trace {
            frames: vec![
                TraceFrame {
                    location: Location::new("models/policy/head.onnx", 1, 1),
                    note: "model output".into(),
                    step: 0,
                },
                TraceFrame {
                    location: Location::new("src/telemetry/relay.rs", 12, 3),
                    note: "forwarded".into(),
                    step: 1,
                },
                TraceFrame {
                    location: Location::new("src/actuator/drive.rs", 88, 5),
                    note: "written to the actuator".into(),
                    step: 2,
                },
            ],
        });

        // The declaration alone says interposed. The code disagrees.
        let clean = verify(&map(), &guarded_flow(), &[]);
        assert!(clean.is_interposed());

        let i = verify(&map(), &guarded_flow(), std::slice::from_ref(&finding));
        assert!(!i.is_interposed(), "an observed bypass beats a declaration that omitted it");
        assert_eq!(i.obligations.len(), 1, "the same obligation, now failed");
        assert!(matches!(i.obligations[0].status, ObligationStatus::Failed { .. }));
        assert!(i.bypasses[0].describe().contains("observed by taint analysis"));
    }

    #[test]
    fn a_taint_flow_that_does_cross_the_guard_refutes_nothing() {
        let finding = Finding::new(
            "ext.codeql",
            "rust/model-output-to-actuator",
            "model output reaches the actuator",
            Severity::High,
            Location::new("src/actuator/drive.rs", 88, 5),
        )
        .evidence(Evidence::Trace {
            frames: vec![
                TraceFrame {
                    location: Location::new("models/policy/head.onnx", 1, 1),
                    note: "model output".into(),
                    step: 0,
                },
                TraceFrame {
                    location: Location::new("src/guard/clamp.rs", 40, 5),
                    note: "clamped".into(),
                    step: 1,
                },
                TraceFrame {
                    location: Location::new("src/actuator/drive.rs", 88, 5),
                    note: "written".into(),
                    step: 2,
                },
            ],
        });
        let i = verify(&map(), &guarded_flow(), std::slice::from_ref(&finding));
        assert!(i.is_interposed());
        assert!(i.bypasses.is_empty());
    }

    /// Untraced taint findings are named while that is useful and counted after.
    ///
    /// One *NOT CHECKED* entry per taint finding means a real CodeQL report sets
    /// the length of the section — the same unbounded shape as `sda.unmapped`,
    /// which reached sixty of seventy-seven lines on a small fixture before it
    /// was collapsed. The count is already stated in prose by the paragraph
    /// above this list, and `unevaluable_taint` still carries every line for a
    /// programmatic caller, so nothing is lost by bounding the projection.
    #[test]
    fn many_untraced_taint_findings_are_counted_rather_than_listed_one_by_one() {
        let taint: Vec<Finding> = (0..40)
            .map(|i| {
                Finding::new(
                    "ext.semgrep",
                    "rust/taint",
                    "tainted write",
                    Severity::High,
                    Location::new("src/actuator/drive.rs", 80 + i, 5),
                )
            })
            .collect();
        let i = verify(&map(), &guarded_flow(), &taint);

        let untraced: Vec<&String> =
            i.not_checked.iter().filter(|l| l.contains("sda.taint-untraced")).collect();
        assert_eq!(untraced.len(), 1, "forty entries bury the rest of the section: {untraced:?}");
        assert!(
            untraced[0].contains("40 taint finding(s)"),
            "and the number is the finding at this scale: {}",
            untraced[0]
        );
        assert_eq!(
            i.unevaluable_taint.len(),
            40,
            "the per-finding detail is kept on the struct; only the report projection is bounded"
        );
    }

    /// A handful are still named one by one, with rule and location.
    ///
    /// That is what makes the entry actionable — it says which finding and
    /// where — and a few lines bury nothing.
    #[test]
    fn a_few_untraced_taint_findings_are_still_named_individually() {
        let taint: Vec<Finding> = (0..2)
            .map(|i| {
                Finding::new(
                    "ext.semgrep",
                    "rust/taint",
                    "tainted write",
                    Severity::High,
                    Location::new("src/actuator/drive.rs", 80 + i, 5),
                )
            })
            .collect();
        let i = verify(&map(), &guarded_flow(), &taint);

        let untraced: Vec<&String> =
            i.not_checked.iter().filter(|l| l.contains("sda.taint-untraced")).collect();
        assert_eq!(untraced.len(), 2, "each is worth naming at this size: {untraced:?}");
        assert!(
            untraced.iter().all(|l| l.contains("drive.rs")),
            "with the location that makes it actionable: {untraced:?}"
        );
    }

    #[test]
    fn a_taint_finding_without_a_trace_is_skipped_rather_than_guessed_at() {
        let finding = Finding::new(
            "ext.semgrep",
            "rust/taint",
            "tainted write",
            Severity::High,
            Location::new("src/actuator/drive.rs", 88, 5),
        );
        let i = verify(&map(), &guarded_flow(), std::slice::from_ref(&finding));
        assert!(
            i.is_interposed(),
            "one location cannot describe a flow, and inventing one to fail an obligation on \
             would be worse than ignoring it"
        );
    }

    #[test]
    fn no_declared_effector_is_an_absent_question_not_a_clean_answer() {
        let m = SystemMap::new()
            .with(Component::neural("policy", "models/policy"))
            .with(Component::symbolic("guard::clamp", "src/guard").guard());
        let i = verify(&m, &guarded_flow(), &[]);
        assert!(i.obligations.is_empty());
        assert!(!i.is_interposed(), "nothing was proved, so this must not read as interposed");
        assert!(i.not_checked.iter().any(|l| l.contains("the absence of a question")));
    }

    #[test]
    fn no_declared_guard_is_reported_before_any_path_is_walked() {
        let m = SystemMap::new()
            .with(Component::neural("policy", "models/policy"))
            .with(Component::symbolic("actuator::drive", "src/actuator").effector());
        let i = verify(&m, &FlowGraph::new().edge("policy", "actuator::drive"), &[]);
        assert!(i.not_checked.iter().any(|l| l.contains("sda.no-guard")));
        assert!(!i.is_interposed());
    }

    #[test]
    fn an_edge_naming_an_undeclared_component_is_reported() {
        let flow = guarded_flow().edge("policy", "shadow::path");
        let i = verify(&map(), &flow, &[]);
        assert!(
            i.not_checked.iter().any(|l| l.contains("sda.flow-undeclared[shadow::path]")),
            "a typo here removes a path from the analysis silently: {:?}",
            i.not_checked
        );
    }

    #[test]
    fn a_cycle_in_the_declaration_does_not_hang_the_walk() {
        let flow = guarded_flow()
            .edge("guard::clamp", "telemetry")
            .edge("telemetry", "guard::clamp");
        let i = verify(&map(), &flow, &[]);
        assert!(i.is_interposed(), "every simple path still crosses the guard");
    }
}

/// A [`SystemMap`] and [`FlowGraph`] built from `.sda/architecture.toml`, plus
/// whatever could not be converted.
#[derive(Clone, Debug, Default)]
pub struct DeclaredSystem {
    pub map: SystemMap,
    pub flow: FlowGraph,
    /// Vocabulary the parser accepted and this layer could not map onto a type.
    ///
    /// `sda-rules` validates that a `boundary` is one of three words; it does
    /// not know [`Boundary`], and an `architecture` string is open by design
    /// because new kinds of network keep being invented. Anything unmapped lands
    /// here and reaches `NOT CHECKED`, because a component silently dropped at
    /// this seam removes paths from the interposition proof.
    pub problems: Vec<String>,
}

/// Build a system from a parsed declaration.
///
/// Entries the parser rejected are already gone; this reports only what survived
/// parsing and still could not be turned into a type. An unrecognised
/// architecture name becomes [`Architecture::Other`] rather than an error — the
/// tractability model already treats that as out of reach with a stated reason,
/// which is the right answer for a network nobody here has classified.
pub fn from_declaration(decl: &ArchitectureDeclaration) -> DeclaredSystem {
    let mut out = DeclaredSystem::default();

    for c in decl.components() {
        let boundary = match c.boundary.as_str() {
            "symbolic" => Boundary::Symbolic,
            "neural" => Boundary::Neural,
            "environment" => Boundary::Environment,
            other => {
                out.problems.push(format!(
                    "sda.architecture[{}]: boundary `{other}` is not one this engine knows, so \
                     the component was dropped and every path through it is gone from the \
                     interposition proof",
                    c.name
                ));
                continue;
            }
        };
        let mut component = Component::new(&c.name, &c.path, boundary);
        component.role = match c.role.as_str() {
            "guard" => Role::Guard,
            "effector" => Role::Effector,
            _ => Role::Ordinary,
        };
        if boundary == Boundary::Neural
            && let Some(name) = &c.architecture {
                let architecture = match name.as_str() {
                    "mlp" => Architecture::Mlp,
                    "cnn" => Architecture::Cnn,
                    "rnn" => Architecture::Rnn,
                    "transformer" => Architecture::Transformer,
                    "state-space" | "ssm" | "mamba" => Architecture::StateSpace,
                    "autoencoder" | "vae" => Architecture::Autoencoder,
                    "gan" => Architecture::Gan,
                    other => Architecture::Other { name: other.to_string() },
                };
                let mut profile = NeuralProfile::new(architecture);
                profile.parameters = c.parameters;
                profile.sequence_bound = c.sequence_bound;
                profile.input_region = c.input_region.clone();
                component.profile = Some(profile);
            }
        out.map.components.push(component);
    }

    for f in decl.flows() {
        out.flow.edges.push(Edge { from: f.from.clone(), to: f.to.clone() });
    }
    out
}

#[cfg(test)]
mod declaration_tests {
    use super::*;
    use sda_core::verification::Tractability;

    const DECL: &str = r#"
[[component]]
name = "policy"
path = "models/policy"
boundary = "neural"
architecture = "mamba"
parameters = 2000000000

[[component]]
name = "guard::clamp"
path = "src/guard"
boundary = "symbolic"
role = "guard"

[[component]]
name = "actuator::drive"
path = "src/actuator"
boundary = "symbolic"
role = "effector"

[[flow]]
from = "policy"
to = "guard::clamp"

[[flow]]
from = "guard::clamp"
to = "actuator::drive"
"#;

    #[test]
    fn a_declaration_becomes_a_system_the_interposition_proof_can_walk() {
        let decl = ArchitectureDeclaration::parse(DECL).unwrap();
        let sys = from_declaration(&decl);
        assert!(sys.problems.is_empty());
        assert_eq!(sys.map.components.len(), 3);
        assert_eq!(sys.flow.edges.len(), 2);

        let i = verify(&sys.map, &sys.flow, &[]);
        assert!(i.is_interposed(), "the declared shape guards the actuator");
        assert!(!i.assumptions.is_empty(), "and still carries its own premise");
    }

    #[test]
    fn architecture_aliases_map_onto_the_kind_they_name() {
        let decl = ArchitectureDeclaration::parse(DECL).unwrap();
        let sys = from_declaration(&decl);
        let policy = sys.map.component_for("models/policy/head.safetensors").unwrap();
        assert_eq!(
            policy.profile.as_ref().unwrap().architecture,
            Architecture::StateSpace,
            "`mamba` is a name for the kind, not a kind of its own"
        );
    }

    #[test]
    fn an_unclassified_architecture_survives_as_other_rather_than_dropping_the_component() {
        let text = "[[component]]\nname = \"m\"\npath = \"models/m\"\nboundary = \"neural\"\n\
                    architecture = \"diffusion-unet\"\n";
        let sys = from_declaration(&ArchitectureDeclaration::parse(text).unwrap());
        assert_eq!(sys.map.components.len(), 1);
        assert!(sys.problems.is_empty());
        let p = sys.map.components[0].profile.as_ref().unwrap();
        assert_eq!(p.architecture, Architecture::Other { name: "diffusion-unet".into() });
        assert!(
            matches!(p.tractability(), Tractability::OutOfReach { .. }),
            "unclassified is out of reach with a reason, which is the honest answer"
        );
    }

    #[test]
    fn the_declared_system_carries_the_model_scale_into_not_checked() {
        let decl = ArchitectureDeclaration::parse(DECL).unwrap();
        let sys = from_declaration(&decl);
        let a = crate::neurosymbolic::adjudicate(&[], &VerificationLedger::new(), &sys.map);
        assert!(
            a.not_checked.iter().any(|l| l.contains("sda.intractable[policy]")),
            "a 2B-parameter Mamba is beyond every prover, and the report says so: {:?}",
            a.not_checked
        );
    }
}
