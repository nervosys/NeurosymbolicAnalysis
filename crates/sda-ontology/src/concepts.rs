//! The concept hierarchy: what kinds of analysis exist, and how they relate.
//!
//! Tools come and go; the techniques do not. An agent that knows `abstract
//! interpretation is-a static analysis` and `it over-approximates` can reason
//! about a tool it has never seen, given only its classification.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConceptId(pub String);

impl ConceptId {
    pub fn new(s: &str) -> Self {
        ConceptId(s.to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ConceptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A node in the technique hierarchy.
#[derive(Clone, Debug, Serialize)]
pub struct Concept {
    pub id: ConceptId,
    pub label: String,
    pub parent: Option<ConceptId>,
    /// What this technique does and what it costs, in a form an agent can read.
    pub description: String,
}

fn c(id: &str, label: &str, parent: Option<&str>, description: &str) -> (ConceptId, Concept) {
    let cid = ConceptId::new(id);
    (
        cid.clone(),
        Concept {
            id: cid,
            label: label.to_string(),
            parent: parent.map(ConceptId::new),
            description: description.to_string(),
        },
    )
}

/// The built-in concept hierarchy.
pub fn concept_tree() -> BTreeMap<ConceptId, Concept> {
    [
        c(
            "analysis",
            "Program analysis",
            None,
            "Any technique for establishing properties of a program.",
        ),
        c(
            "static-analysis",
            "Static analysis",
            Some("analysis"),
            "Reasons about the program without executing it. Covers every path in principle, \
             which is why it over-reports: most tools must approximate, and approximation in the \
             safe direction produces alarms on paths that cannot happen.",
        ),
        c(
            "dynamic-analysis",
            "Dynamic analysis",
            Some("analysis"),
            "Observes the program while it runs. Every report is real, and every path not taken \
             is invisible. Its results are only as good as the inputs that drove it.",
        ),
        c(
            "statodynamic-analysis",
            "Statodynamic analysis",
            Some("analysis"),
            "Correlates static and dynamic evidence so each covers the other's weakness: static \
             findings are confirmed or refuted by execution, and code that never executed is \
             identified as untested rather than reported as clean.",
        ),
        // Static techniques
        c(
            "lexical-analysis",
            "Lexical and syntactic analysis",
            Some("static-analysis"),
            "Works from the token stream and shallow structure. Cheap, runs on code that does not \
             compile, and cannot reason about types.",
        ),
        c(
            "dataflow-analysis",
            "Data-flow analysis",
            Some("static-analysis"),
            "Propagates facts along the control-flow graph. The basis of taint tracking and \
             uninitialised-value detection.",
        ),
        c(
            "abstract-interpretation",
            "Abstract interpretation",
            Some("static-analysis"),
            "Executes the program over an abstract domain, over-approximating every path. Sound: \
             it will not miss a defect in its domain, and it will raise alarms that cannot happen.",
        ),
        c(
            "model-checking",
            "Model checking",
            Some("static-analysis"),
            "Exhaustively explores states up to a bound. Complete within that bound and silent \
             beyond it, so the bound is part of the result.",
        ),
        c(
            "symbolic-execution",
            "Symbolic execution",
            Some("static-analysis"),
            "Explores paths with symbolic inputs and a constraint solver, producing concrete \
             witnesses. Limited by path explosion long before whole-program scale.",
        ),
        c(
            "deductive-verification",
            "Deductive verification",
            Some("static-analysis"),
            "Discharges proof obligations written in the source — preconditions,              postconditions, invariants — usually with an SMT solver. Establishes the stated              property over every execution, and establishes nothing whatever about the properties              nobody stated: an unspecified component verifies vacuously, so a clean run is only              as meaningful as the specification behind it.",
        ),
        c(
            "type-checking",
            "Type and effect checking",
            Some("static-analysis"),
            "Rejects programs that violate a type discipline. Rust's borrow checker is the \
             industrially significant example.",
        ),
        // Dynamic techniques
        c(
            "runtime-instrumentation",
            "Runtime instrumentation",
            Some("dynamic-analysis"),
            "Rewrites the program to check its own operations — bounds, initialisation, \
             synchronisation. The sanitizer family, and the SDA probe shim.",
        ),
        c(
            "coverage-measurement",
            "Coverage measurement",
            Some("dynamic-analysis"),
            "Records which code executed. On its own it finds nothing; without it, no clean \
             dynamic result can be interpreted.",
        ),
        c(
            "fuzzing",
            "Fuzz testing",
            Some("dynamic-analysis"),
            "Generates inputs to drive execution into unexplored states, usually guided by \
             coverage feedback.",
        ),
        c(
            "concolic-testing",
            "Concolic testing",
            Some("dynamic-analysis"),
            "Runs concretely while collecting symbolic constraints, then solves them to reach new \
             paths. A bridge between fuzzing and symbolic execution.",
        ),
        c(
            "profiling",
            "Profiling",
            Some("dynamic-analysis"),
            "Measures time and space behaviour. On a real-time target, a timing regression is a \
             correctness defect.",
        ),
        // AI-specific
        c(
            "ai-analysis",
            "AI model analysis",
            Some("analysis"),
            "Establishing properties of a machine-learning model rather than of code.",
        ),
        c(
            "model-artifact-analysis",
            "Model artifact analysis",
            Some("ai-analysis"),
            "Inspects the serialized model as a file: container format, headers, metadata, and \
             load-time behaviour. Establishes what loading the file does, never what the weights do.",
        ),
        c(
            "neural-network-verification",
            "Neural network property verification",
            Some("ai-analysis"),
            "Proves sound bounds on a network's outputs over a stated region of its input space —              local robustness, output reachability. The only deductive claim available about              learned weights, and a local one: it holds over the region given and says nothing              outside it. Practical for small perception and control networks; there is no              transformer-scale equivalent.",
        ),
        c(
            "model-behavior-analysis",
            "Model behavioural analysis",
            Some("ai-analysis"),
            "Runs the model against chosen inputs and judges its outputs. The only route to \
             backdoor, censorship, and jailbreak evidence — and it can demonstrate a behaviour, \
             never its absence.",
        ),
        // Neurosymbolic
        c(
            "neurosymbolic-analysis",
            "Neurosymbolic system analysis",
            Some("analysis"),
            "Analyses a system whose symbolic and learned parts admit different kinds of              evidence. The symbolic shell is proved; the model is only sampled; and the two are              joined by assume-guarantee across a stated boundary rather than by averaging their              results into one confidence. What it produces is a conditional claim — the property              holds *provided* the boundary assumptions hold — with those assumptions enumerated              and their support named.",
        ),
    ]
    .into_iter()
    .collect()
}

/// The technique concept a tool of this kind implements.
pub fn technique_for(kind: sda_core::AnalyzerKind) -> ConceptId {
    match kind {
        sda_core::AnalyzerKind::Static => ConceptId::new("static-analysis"),
        sda_core::AnalyzerKind::Dynamic => ConceptId::new("dynamic-analysis"),
        sda_core::AnalyzerKind::Hybrid => ConceptId::new("statodynamic-analysis"),
    }
}

/// Every ancestor of a concept, nearest first.
pub fn ancestors(tree: &BTreeMap<ConceptId, Concept>, id: &ConceptId) -> Vec<ConceptId> {
    let mut out = Vec::new();
    let mut cur = tree.get(id).and_then(|c| c.parent.clone());
    while let Some(p) = cur {
        out.push(p.clone());
        cur = tree.get(&p).and_then(|c| c.parent.clone());
    }
    out
}

/// Whether `ancestor` subsumes `id`.
pub fn subsumes(tree: &BTreeMap<ConceptId, Concept>, ancestor: &ConceptId, id: &ConceptId) -> bool {
    ancestors(tree, id).contains(ancestor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tree_is_rooted_and_fully_connected() {
        let t = concept_tree();
        assert!(t.contains_key(&ConceptId::new("analysis")));
        for (id, c) in &t {
            match &c.parent {
                None => assert_eq!(id.as_str(), "analysis", "only the root may have no parent"),
                Some(p) => assert!(t.contains_key(p), "{id} has a dangling parent {p}"),
            }
        }
    }

    #[test]
    fn subsumption_walks_the_hierarchy() {
        let t = concept_tree();
        let root = ConceptId::new("analysis");
        let ai = ConceptId::new("abstract-interpretation");
        assert!(subsumes(&t, &ConceptId::new("static-analysis"), &ai));
        assert!(subsumes(&t, &root, &ai));
        assert!(!subsumes(&t, &ConceptId::new("dynamic-analysis"), &ai));
    }

    #[test]
    fn ancestors_are_ordered_nearest_first() {
        let t = concept_tree();
        let a = ancestors(&t, &ConceptId::new("fuzzing"));
        assert_eq!(a[0], ConceptId::new("dynamic-analysis"));
        assert_eq!(a[1], ConceptId::new("analysis"));
    }

    #[test]
    fn analyzer_kinds_map_onto_technique_concepts() {
        let t = concept_tree();
        for kind in [
            sda_core::AnalyzerKind::Static,
            sda_core::AnalyzerKind::Dynamic,
            sda_core::AnalyzerKind::Hybrid,
        ] {
            assert!(t.contains_key(&technique_for(kind)), "{kind:?} maps to an unknown concept");
        }
    }

    #[test]
    fn every_concept_explains_its_cost_or_its_limits() {
        for c in concept_tree().values() {
            assert!(c.description.len() > 40, "{} is under-described", c.id);
        }
    }

    #[test]
    fn ai_analysis_is_a_sibling_of_code_analysis_not_a_subtype_of_it() {
        let t = concept_tree();
        let ai = ConceptId::new("model-behavior-analysis");
        assert!(subsumes(&t, &ConceptId::new("ai-analysis"), &ai));
        assert!(!subsumes(&t, &ConceptId::new("dynamic-analysis"), &ai));
    }
}
