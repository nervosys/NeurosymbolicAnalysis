//! The statodynamic analysis ontology.
//!
//! An agent cannot plan a run over a landscape it does not know. This crate is
//! that knowledge, in a form a machine can query: a concept hierarchy over
//! analysis techniques, a catalogue of tools classified against it, and the
//! relations between them.
//!
//! Two things distinguish it from a list of links.
//!
//! **It records limits.** Every tool carries a [`Tool::limits`] sentence and a
//! [`Soundness`] classification. An agent choosing between CBMC and Cppcheck
//! needs to know that one is complete up to a bound and the other is a
//! heuristic, because that determines what a clean result is worth.
//!
//! **It records cost.** Build requirements and licensing are part of the
//! decision. A planner that suggests Coverity to someone without a licence has
//! not helped.

#![forbid(unsafe_code)]

use sda_core::{AnalyzerKind, Capability, Language, ProviderOrigin};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub mod concepts;

pub use concepts::{Concept, ConceptId, concept_tree};

/// What a clean result from a tool is worth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Soundness {
    /// No false negatives within its stated scope: a clean result means clean,
    /// as far as the scope goes.
    Complete,
    /// No false positives: every report is real, but silence proves nothing.
    Sound,
    /// Neither guarantee. Most tools, honestly labelled.
    Heuristic,
    /// May both miss and over-report.
    Unsound,
}

impl Soundness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Soundness::Complete => "complete",
            Soundness::Sound => "sound",
            Soundness::Heuristic => "heuristic",
            Soundness::Unsound => "unsound",
        }
    }
    /// What a clean result from this tool establishes, in words.
    pub fn clean_result_means(&self) -> &'static str {
        match self {
            Soundness::Complete => {
                "no defect of the kinds it checks exists within its stated scope"
            }
            Soundness::Sound => "nothing was found, which is not evidence that nothing is there",
            Soundness::Heuristic => "nothing was found; this is weak evidence at best",
            Soundness::Unsound => "nothing was found; draw no conclusion from that",
        }
    }
    fn parse(s: &str) -> Soundness {
        match s {
            "complete" => Soundness::Complete,
            "sound" => Soundness::Sound,
            "unsound" => Soundness::Unsound,
            _ => Soundness::Heuristic,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cost {
    Free,
    FreeTier,
    Commercial,
}

impl Cost {
    pub fn as_str(&self) -> &'static str {
        match self {
            Cost::Free => "free",
            Cost::FreeTier => "free-tier",
            Cost::Commercial => "commercial",
        }
    }
    fn parse(s: &str) -> Cost {
        match s {
            "commercial" => Cost::Commercial,
            "free-tier" => Cost::FreeTier,
            _ => Cost::Free,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Maturity {
    Experimental,
    Stable,
    Mature,
}

impl Maturity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Maturity::Experimental => "experimental",
            Maturity::Stable => "stable",
            Maturity::Mature => "mature",
        }
    }
    fn parse(s: &str) -> Maturity {
        match s {
            "mature" => Maturity::Mature,
            "experimental" => Maturity::Experimental,
            _ => Maturity::Stable,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawTool {
    id: String,
    name: String,
    origin: String,
    kind: String,
    languages: Vec<String>,
    capabilities: Vec<String>,
    #[serde(default)]
    exe: Option<String>,
    #[serde(default)]
    url: Option<String>,
    cost: String,
    maturity: String,
    #[serde(default)]
    requires_build: bool,
    soundness: String,
    limits: String,
    #[serde(default)]
    detects: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawCatalog {
    tool: Vec<RawTool>,
}

/// One tool in the ontology.
#[derive(Clone, Debug, Serialize)]
pub struct Tool {
    pub id: String,
    pub name: String,
    pub origin: ProviderOrigin,
    pub kind: AnalyzerKind,
    pub languages: Vec<Language>,
    pub capabilities: Vec<Capability>,
    pub executable: Option<String>,
    pub url: Option<String>,
    pub cost: Cost,
    pub maturity: Maturity,
    pub requires_build: bool,
    pub soundness: Soundness,
    /// One sentence on what this tool cannot establish.
    pub limits: String,
    /// Classification schemes this tool reports against.
    pub detects: Vec<String>,
}

impl Tool {
    pub fn is_native(&self) -> bool {
        self.origin == ProviderOrigin::Native
    }
    pub fn handles(&self, lang: &Language) -> bool {
        self.languages.contains(lang)
    }
    pub fn provides(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// The paragraph an agent reads to decide whether to run this tool.
    pub fn brief(&self) -> String {
        let langs: Vec<&str> = self.languages.iter().map(|l| l.as_str()).collect();
        let caps: Vec<&str> = self.capabilities.iter().map(|c| c.as_str()).collect();
        let mut s = format!(
            "{} ({}) — {} {} analysis for {}. Capabilities: {}. Soundness: {} ({}). Cost: {}. \
             Maturity: {}.",
            self.name,
            self.id,
            if self.is_native() { "native" } else { "external" },
            self.kind.as_str(),
            langs.join(", "),
            caps.join(", "),
            self.soundness.as_str(),
            self.soundness.clean_result_means(),
            self.cost.as_str(),
            self.maturity.as_str(),
        );
        if self.requires_build {
            s.push_str(" Requires a built target.");
        }
        s.push_str(&format!(" Limits: {}", self.limits));
        if let Some(e) = &self.executable {
            s.push_str(&format!(" Executable: `{e}`."));
        }
        s
    }
}

/// A relation between two things in the ontology.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Relation {
    pub subject: String,
    pub predicate: Predicate,
    pub object: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Predicate {
    /// The tool implements a technique concept.
    Implements,
    /// The tool can find weaknesses in a classification scheme.
    Detects,
    /// The tool handles a language.
    Analyzes,
    /// The tool provides a capability.
    Provides,
    /// Two tools are usefully run together — their blind spots differ.
    Complements,
    /// A concept is a kind of another concept.
    IsA,
}

impl Predicate {
    pub fn as_str(&self) -> &'static str {
        match self {
            Predicate::Implements => "implements",
            Predicate::Detects => "detects",
            Predicate::Analyzes => "analyzes",
            Predicate::Provides => "provides",
            Predicate::Complements => "complements",
            Predicate::IsA => "is-a",
        }
    }
}

const TOOLS: &str = include_str!("../data/tools.toml");

/// The loaded ontology.
#[derive(Clone, Debug)]
pub struct Ontology {
    tools: BTreeMap<String, Tool>,
    concepts: BTreeMap<ConceptId, Concept>,
}

impl Default for Ontology {
    fn default() -> Self {
        Self::load()
    }
}

impl Ontology {
    /// # Panics
    /// Only if the built-in catalogue is malformed, which a test prevents.
    pub fn load() -> Ontology {
        let raw: RawCatalog = toml::from_str(TOOLS)
            .unwrap_or_else(|e| panic!("built-in tool ontology is malformed: {e}"));

        let tools = raw
            .tool
            .into_iter()
            .map(|t| {
                let tool = Tool {
                    id: t.id.clone(),
                    name: t.name,
                    origin: if t.origin == "native" {
                        ProviderOrigin::Native
                    } else {
                        ProviderOrigin::External
                    },
                    kind: match t.kind.as_str() {
                        "dynamic" => AnalyzerKind::Dynamic,
                        "hybrid" => AnalyzerKind::Hybrid,
                        _ => AnalyzerKind::Static,
                    },
                    languages: t.languages.iter().map(|l| parse_language(l)).collect(),
                    capabilities: t.capabilities.iter().filter_map(|c| Capability::parse(c)).collect(),
                    executable: t.exe,
                    url: t.url,
                    cost: Cost::parse(&t.cost),
                    maturity: Maturity::parse(&t.maturity),
                    requires_build: t.requires_build,
                    soundness: Soundness::parse(&t.soundness),
                    limits: t.limits,
                    detects: t.detects,
                };
                (t.id, tool)
            })
            .collect();

        Ontology { tools, concepts: concept_tree() }
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
    pub fn get(&self, id: &str) -> Option<&Tool> {
        self.tools.get(id)
    }
    pub fn tools(&self) -> Vec<&Tool> {
        self.tools.values().collect()
    }
    pub fn concept(&self, id: &ConceptId) -> Option<&Concept> {
        self.concepts.get(id)
    }
    pub fn concepts(&self) -> Vec<&Concept> {
        self.concepts.values().collect()
    }

    /// Native tools, which run by default.
    pub fn native(&self) -> Vec<&Tool> {
        self.tools.values().filter(|t| t.is_native()).collect()
    }

    /// Ids of every native tool.
    ///
    /// These ship with the toolkit, so they are always available — which is what
    /// callers building the "what do I have?" set for [`Ontology::gaps`] need.
    /// Building that set from the provider registry alone under-reports: not
    /// every native capability is a registered `Analyzer` (the fuzzer and the
    /// correlation engine are invoked directly), and omitting them makes gap
    /// analysis recommend an external tool for something already in the box.
    pub fn native_ids(&self) -> BTreeSet<String> {
        self.tools.values().filter(|t| t.is_native()).map(|t| t.id.clone()).collect()
    }

    /// Free-text search over ids, names, limits, and capabilities.
    pub fn search(&self, query: &str) -> Vec<&Tool> {
        let q = query.to_ascii_lowercase();
        let mut hits: Vec<(&Tool, u32)> = self
            .tools
            .values()
            .filter_map(|t| {
                let mut score = 0u32;
                if t.id.to_ascii_lowercase().contains(&q) {
                    score += 10;
                }
                if t.name.to_ascii_lowercase().contains(&q) {
                    score += 8;
                }
                if t.capabilities.iter().any(|c| c.as_str().contains(&q)) {
                    score += 6;
                }
                if t.detects.iter().any(|d| d.to_ascii_lowercase().contains(&q)) {
                    score += 4;
                }
                if t.limits.to_ascii_lowercase().contains(&q) {
                    score += 1;
                }
                (score > 0).then_some((t, score))
            })
            .collect();
        // Native first at equal relevance, so the default answer surfaces.
        hits.sort_by(|a, b| {
            b.1.cmp(&a.1).then(b.0.is_native().cmp(&a.0.is_native())).then(a.0.id.cmp(&b.0.id))
        });
        hits.into_iter().map(|(t, _)| t).collect()
    }

    /// Tools that can find something in `capability` for `language`.
    ///
    /// This is the ontology's primary query, and the one the planner calls.
    pub fn recommend(&self, capability: Capability, language: &Language) -> Vec<&Tool> {
        let mut v: Vec<&Tool> = self
            .tools
            .values()
            .filter(|t| t.provides(capability) && t.handles(language))
            .collect();
        // Rank: native first, then stronger soundness, then maturity, then cost.
        v.sort_by(|a, b| {
            b.is_native()
                .cmp(&a.is_native())
                .then(a.soundness.cmp(&b.soundness))
                .then(b.maturity.cmp(&a.maturity))
                .then(a.cost.cmp(&b.cost))
                .then(a.id.cmp(&b.id))
        });
        v
    }

    /// Tools reporting against a classification scheme, e.g. `MISRA-C-2023`.
    pub fn detecting(&self, scheme: &str) -> Vec<&Tool> {
        self.tools.values().filter(|t| t.detects.iter().any(|d| d == scheme)).collect()
    }

    /// Capabilities that no available tool covers for a language — the honest
    /// answer to "what am I not checking?".
    ///
    /// A capability that *no* catalogued tool provides for the language is not
    /// reported. `model-artifact-scan` is not a gap in your C analysis; it does
    /// not apply to C at all, and listing it — with an empty list of things to
    /// install — turns a useful report into noise that trains people to skim it.
    pub fn gaps(&self, language: &Language, available: &BTreeSet<String>) -> Vec<Capability> {
        Capability::all()
            .iter()
            .copied()
            .filter(|cap| {
                let applicable: Vec<&Tool> = self
                    .tools
                    .values()
                    .filter(|t| t.handles(language) && t.provides(*cap))
                    .collect();
                // Inapplicable to this language, or already covered.
                !applicable.is_empty() && !applicable.iter().any(|t| available.contains(&t.id))
            })
            .collect()
    }

    /// Every relation the ontology asserts, as triples. This is what an agent
    /// walks when it needs to reason rather than look something up.
    pub fn relations(&self) -> Vec<Relation> {
        let mut out = Vec::new();
        for t in self.tools.values() {
            for l in &t.languages {
                out.push(Relation {
                    subject: t.id.clone(),
                    predicate: Predicate::Analyzes,
                    object: l.to_string(),
                });
            }
            for c in &t.capabilities {
                out.push(Relation {
                    subject: t.id.clone(),
                    predicate: Predicate::Provides,
                    object: c.as_str().to_string(),
                });
            }
            for d in &t.detects {
                out.push(Relation {
                    subject: t.id.clone(),
                    predicate: Predicate::Detects,
                    object: d.clone(),
                });
            }
            out.push(Relation {
                subject: t.id.clone(),
                predicate: Predicate::Implements,
                object: concepts::technique_for(t.kind).0.clone(),
            });
        }
        for c in self.concepts.values() {
            if let Some(parent) = &c.parent {
                out.push(Relation {
                    subject: c.id.0.clone(),
                    predicate: Predicate::IsA,
                    object: parent.0.clone(),
                });
            }
        }
        // Tools whose blind spots differ are worth running together.
        let tools: Vec<&Tool> = self.tools.values().collect();
        for (i, a) in tools.iter().enumerate() {
            for b in tools.iter().skip(i + 1) {
                if !languages_overlap(a, b) {
                    continue;
                }
                if a.kind != b.kind
                    && a.kind != AnalyzerKind::Hybrid
                    && b.kind != AnalyzerKind::Hybrid
                {
                    out.push(Relation {
                        subject: a.id.clone(),
                        predicate: Predicate::Complements,
                        object: b.id.clone(),
                    });
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// A description an agent can read, covering the tool and its neighbourhood.
    pub fn describe(&self, id: &str) -> Option<String> {
        let t = self.get(id)?;
        let mut s = t.brief();
        if let Some(u) = &t.url {
            s.push_str(&format!("\nHomepage: {u}"));
        }
        let alternatives: Vec<String> = t
            .capabilities
            .first()
            .map(|c| {
                self.recommend(*c, t.languages.first().unwrap_or(&Language::C))
                    .into_iter()
                    .filter(|o| o.id != t.id)
                    .take(4)
                    .map(|o| o.id.clone())
                    .collect()
            })
            .unwrap_or_default();
        if !alternatives.is_empty() {
            s.push_str(&format!(
                "\nAlternatives for the same capability: {}",
                alternatives.join(", ")
            ));
        }
        Some(s)
    }
}

fn languages_overlap(a: &Tool, b: &Tool) -> bool {
    a.languages.iter().any(|l| b.languages.contains(l))
}

fn parse_language(s: &str) -> Language {
    match s {
        "c" => Language::C,
        "cpp" => Language::Cpp,
        "rust" => Language::Rust,
        "python" => Language::Python,
        "model-artifact" => Language::ModelArtifact,
        "assembly" => Language::Assembly,
        other => Language::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ontology_loads_with_native_and_external_tools() {
        let o = Ontology::load();
        assert!(o.len() > 30, "got {}", o.len());
        assert!(o.native().len() >= 6);
        assert!(o.tools().iter().any(|t| !t.is_native()));
    }

    #[test]
    fn every_native_tool_id_matches_a_real_provider_id() {
        let o = Ontology::load();
        // These are the ids the engines actually register under; a mismatch
        // would make the ontology describe tools that cannot be selected.
        for id in ["sda.static.c", "sda.static.cpp", "sda.static.rust", "sda.dynamic", "sda.ai.artifact"] {
            assert!(o.get(id).is_some(), "{id} missing from the ontology");
            assert!(o.get(id).unwrap().is_native());
        }
    }

    #[test]
    fn recommendations_put_native_tools_first() {
        let o = Ontology::load();
        let r = o.recommend(Capability::StyleCompliance, &Language::C);
        assert!(!r.is_empty());
        assert!(r[0].is_native(), "got {}", r[0].id);
        assert!(r.iter().any(|t| t.id == "ext.cppcheck"), "externals must still be offered");
    }

    #[test]
    fn stronger_soundness_ranks_above_weaker_among_externals() {
        let o = Ontology::load();
        let r = o.recommend(Capability::FormalVerification, &Language::C);
        let cbmc = r.iter().position(|t| t.id == "ext.cbmc").unwrap();
        let frama = r.iter().position(|t| t.id == "ext.frama-c").unwrap();
        assert!(cbmc < frama, "complete should rank above sound");
    }

    #[test]
    fn every_tool_states_what_it_cannot_do() {
        let o = Ontology::load();
        for t in o.tools() {
            assert!(t.limits.len() > 20, "{} has no meaningful stated limits", t.id);
        }
    }

    #[test]
    fn soundness_is_translated_into_what_a_clean_result_means() {
        assert!(Soundness::Complete.clean_result_means().contains("no defect"));
        assert!(Soundness::Sound.clean_result_means().contains("not evidence"));
        assert!(Soundness::Heuristic.clean_result_means().contains("weak evidence"));
    }

    #[test]
    fn search_surfaces_the_native_answer_early() {
        let o = Ontology::load();
        let r = o.search("memory-safety");
        assert!(!r.is_empty());
        assert!(r.iter().take(3).any(|t| t.is_native()));
    }

    #[test]
    fn schemes_resolve_to_the_tools_that_report_them() {
        let o = Ontology::load();
        let misra = o.detecting("MISRA-C-2023");
        assert!(misra.iter().any(|t| t.id == "sda.static.c"));
        assert!(misra.iter().any(|t| t.id == "ext.cppcheck"));
        assert!(misra.len() >= 4);
    }

    #[test]
    fn gaps_report_what_a_given_tool_set_does_not_cover() {
        let o = Ontology::load();
        let available: BTreeSet<String> = ["sda.static.c".to_string()].into_iter().collect();
        let gaps = o.gaps(&Language::C, &available);
        assert!(gaps.contains(&Capability::Fuzzing));
        assert!(gaps.contains(&Capability::MemorySafety));
        assert!(!gaps.contains(&Capability::StyleCompliance));
    }

    #[test]
    fn the_native_tool_set_leaves_no_gap_a_native_tool_covers() {
        // The bug this guards: callers used to build the available-set from the
        // provider registry, which omits native tools that are not registered
        // `Analyzer`s — the fuzzer among them. Gap analysis then recommended
        // AFL++ for fuzzing that the toolkit already ships.
        let o = Ontology::load();
        let native = o.native_ids();
        assert!(native.contains("sda.fuzz"), "the fuzzer must be in the ontology");

        for lang in [Language::C, Language::Cpp, Language::Rust] {
            for cap in o.gaps(&lang, &native) {
                assert!(
                    o.recommend(cap, &lang).iter().all(|t| !t.is_native()),
                    "{cap:?} is reported as a gap for {lang} despite a native tool providing it"
                );
            }
        }
    }

    #[test]
    fn a_capability_inapplicable_to_the_language_is_not_a_gap() {
        // Reporting `model-artifact-scan` as a gap in C analysis — with nothing
        // to install, because no tool provides it for C — is noise, and noise in
        // a "what am I missing?" report is worse than silence.
        let o = Ontology::load();
        for cap in o.gaps(&Language::C, &BTreeSet::new()) {
            assert!(
                !o.recommend(cap, &Language::C).is_empty(),
                "{cap:?} reported as a C gap but nothing provides it for C"
            );
        }
        assert!(!o.gaps(&Language::C, &BTreeSet::new()).contains(&Capability::ModelArtifactScan));
        // ...and it *is* a gap for the language it applies to.
        assert!(
            o.gaps(&Language::ModelArtifact, &BTreeSet::new())
                .contains(&Capability::ModelArtifactScan)
        );
    }

    #[test]
    fn fuzzing_is_no_longer_a_gap_for_a_default_installation() {
        let o = Ontology::load();
        let gaps = o.gaps(&Language::C, &o.native_ids());
        assert!(!gaps.contains(&Capability::Fuzzing));
    }

    #[test]
    fn adding_the_dynamic_engine_closes_the_memory_safety_gap() {
        let o = Ontology::load();
        let available: BTreeSet<String> =
            ["sda.static.c".to_string(), "sda.dynamic".to_string()].into_iter().collect();
        assert!(!o.gaps(&Language::C, &available).contains(&Capability::MemorySafety));
    }

    #[test]
    fn relations_form_a_walkable_graph() {
        let o = Ontology::load();
        let r = o.relations();
        assert!(r.len() > 100);
        for p in [Predicate::Analyzes, Predicate::Detects, Predicate::IsA, Predicate::Complements] {
            assert!(r.iter().any(|t| t.predicate == p), "no {p:?} relations");
        }
    }

    #[test]
    fn describe_gives_an_agent_the_tool_and_its_alternatives() {
        let o = Ontology::load();
        let d = o.describe("ext.valgrind").unwrap();
        assert!(d.contains("Valgrind"));
        assert!(d.contains("Limits:"));
        assert!(d.contains("Alternatives"));
        assert!(o.describe("nope").is_none());
    }

    #[test]
    fn model_artifact_tools_are_reachable_by_capability() {
        let o = Ontology::load();
        let r = o.recommend(Capability::ModelArtifactScan, &Language::ModelArtifact);
        assert!(r[0].is_native());
        assert!(r.iter().any(|t| t.id == "ext.modelscan"));
    }

    #[test]
    fn commercial_tools_are_offered_but_rank_below_free_equivalents() {
        let o = Ontology::load();
        let r = o.recommend(Capability::MemorySafety, &Language::C);
        assert!(r.iter().any(|t| t.cost == Cost::Commercial), "commercial tools must be listed");
        let first_commercial = r.iter().position(|t| t.cost == Cost::Commercial).unwrap();
        assert!(first_commercial > 0, "a free or native option should lead");
    }
}
