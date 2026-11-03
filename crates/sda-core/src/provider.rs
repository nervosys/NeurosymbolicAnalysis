//! The provider abstraction: one trait for our native engines and for every
//! external industry tool.
//!
//! Policy, encoded in [`Registry::select`]: **native providers win by default.**
//! External adapters are accepted, described, and runnable, but only participate
//! when the caller opts in — either globally (`prefer_external`) or per-provider
//! (`enable`). This keeps runs hermetic and reproducible out of the box while
//! letting a team layer in the exact commercial or open-source checker their
//! process already mandates.

use crate::finding::Finding;
use crate::ids::ProviderId;
use crate::target::{Language, Target};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Where a provider's implementation lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderOrigin {
    /// Implemented in this workspace, in Rust, with no external process.
    Native,
    /// Wraps a third-party executable that must be installed separately.
    External,
}

impl ProviderOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderOrigin::Native => "native",
            ProviderOrigin::External => "external",
        }
    }
}

/// Which half of statodynamic analysis a provider performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalyzerKind {
    /// Reads source or binaries without executing them.
    Static,
    /// Executes the target and observes it.
    Dynamic,
    /// Does both, internally correlated.
    Hybrid,
}

impl AnalyzerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnalyzerKind::Static => "static",
            AnalyzerKind::Dynamic => "dynamic",
            AnalyzerKind::Hybrid => "hybrid",
        }
    }
}

/// A discrete analytical ability, used by the ontology and the agent planner to
/// answer "what do I run to find X?".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Enforces a coding standard (MISRA, CERT, house style).
    StyleCompliance,
    /// Finds memory-safety defects.
    MemorySafety,
    /// Finds concurrency defects.
    ConcurrencySafety,
    /// Finds undefined behaviour.
    UndefinedBehavior,
    /// Tracks untrusted data to sensitive sinks.
    TaintAnalysis,
    /// Proves or refutes properties (model checking, abstract interpretation).
    FormalVerification,
    /// Discharges proof obligations written in the source: pre/postconditions,
    /// invariants, refinement.
    ///
    /// Distinct from [`Capability::FormalVerification`], and the distinction is
    /// operational rather than academic. A model checker searches for a
    /// counterexample and can be pointed at unannotated code; a deductive prover
    /// discharges what you wrote down and is silent — vacuously successful —
    /// about everything you did not. Which one you have determines whether a
    /// clean result means anything at all.
    DeductiveProof,
    /// Establishes sound bounds on a neural network's output over a stated
    /// input region.
    ///
    /// The only deductive claim available about learned weights, and it is a
    /// local one: it holds over the region given and says nothing outside it.
    /// It does not scale to transformer-sized models.
    NeuralPropertyVerification,
    /// Measures which code executed.
    CoverageMeasurement,
    /// Generates inputs to explore behaviour.
    Fuzzing,
    /// Measures time/space behaviour.
    PerformanceProfiling,
    /// Inventories and audits third-party components.
    DependencyAudit,
    /// Analyzes serialized AI model files.
    ModelArtifactScan,
    /// Probes a running AI model's behaviour.
    ModelBehaviorProbe,
    /// Computes structural metrics (complexity, coupling).
    MetricsCollection,
    /// Reconstructs control/data flow for other passes to consume.
    ProgramFactExtraction,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::StyleCompliance => "style-compliance",
            Capability::MemorySafety => "memory-safety",
            Capability::ConcurrencySafety => "concurrency-safety",
            Capability::UndefinedBehavior => "undefined-behavior",
            Capability::TaintAnalysis => "taint-analysis",
            Capability::FormalVerification => "formal-verification",
            Capability::DeductiveProof => "deductive-proof",
            Capability::NeuralPropertyVerification => "neural-property-verification",
            Capability::CoverageMeasurement => "coverage-measurement",
            Capability::Fuzzing => "fuzzing",
            Capability::PerformanceProfiling => "performance-profiling",
            Capability::DependencyAudit => "dependency-audit",
            Capability::ModelArtifactScan => "model-artifact-scan",
            Capability::ModelBehaviorProbe => "model-behavior-probe",
            Capability::MetricsCollection => "metrics-collection",
            Capability::ProgramFactExtraction => "program-fact-extraction",
        }
    }

    pub fn all() -> &'static [Capability] {
        use Capability::*;
        &[
            StyleCompliance,
            MemorySafety,
            ConcurrencySafety,
            UndefinedBehavior,
            TaintAnalysis,
            FormalVerification,
            DeductiveProof,
            NeuralPropertyVerification,
            CoverageMeasurement,
            Fuzzing,
            PerformanceProfiling,
            DependencyAudit,
            ModelArtifactScan,
            ModelBehaviorProbe,
            MetricsCollection,
            ProgramFactExtraction,
        ]
    }

    pub fn parse(s: &str) -> Option<Capability> {
        Capability::all().iter().copied().find(|c| c.as_str() == s)
    }
}

#[cfg(test)]
mod capability_tests {
    use super::Capability;

    /// Every capability is in `all()`, and survives a round trip through its name.
    ///
    /// `parse` scans `all()`, so a variant missing from that hand-written list is
    /// silently unparseable however correct `as_str` is — a provider declaring it
    /// over the MCP surface would come back `None` and the capability would read
    /// as one this toolkit does not have. The enum and the list are maintained by
    /// hand and nothing compared them, which is the shape that had two CWE maps
    /// disagreeing about one class.
    ///
    /// The `match` below is the forcing function. A new capability does not
    /// compile until it is named there, and naming it there is the prompt to put
    /// it in `all()` as well. The length check catches the other direction.
    #[test]
    fn every_capability_is_listed_in_all_and_parses_back() {
        use Capability::*;

        let every = [
            StyleCompliance,
            MemorySafety,
            ConcurrencySafety,
            UndefinedBehavior,
            TaintAnalysis,
            FormalVerification,
            DeductiveProof,
            NeuralPropertyVerification,
            CoverageMeasurement,
            Fuzzing,
            PerformanceProfiling,
            DependencyAudit,
            ModelArtifactScan,
            ModelBehaviorProbe,
            MetricsCollection,
            ProgramFactExtraction,
        ];

        for c in every {
            // Exhaustive: adding a variant breaks this arm and nothing else.
            match c {
                StyleCompliance
                | MemorySafety
                | ConcurrencySafety
                | UndefinedBehavior
                | TaintAnalysis
                | FormalVerification
                | DeductiveProof
                | NeuralPropertyVerification
                | CoverageMeasurement
                | Fuzzing
                | PerformanceProfiling
                | DependencyAudit
                | ModelArtifactScan
                | ModelBehaviorProbe
                | MetricsCollection
                | ProgramFactExtraction => {}
            }

            assert!(
                Capability::all().contains(&c),
                "{c:?} is missing from `all()`, so `parse` can never produce it"
            );
            assert_eq!(
                Capability::parse(c.as_str()),
                Some(c),
                "{c:?} does not survive `as_str` then `parse`"
            );
        }

        assert_eq!(
            Capability::all().len(),
            every.len(),
            "`all()` and the enum have drifted apart in the other direction"
        );
    }
}

/// Self-description every provider must supply. This is what the ontology
/// indexes and what an agent reads to decide whether to run it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub id: ProviderId,
    pub name: String,
    pub origin: ProviderOrigin,
    pub kind: AnalyzerKind,
    pub languages: Vec<Language>,
    pub capabilities: Vec<Capability>,
    /// Prose an agent can read to decide relevance.
    pub description: String,
    /// For external providers: the executable that must be on `PATH`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// Homepage or documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Whether the target must be built before this provider can run.
    #[serde(default)]
    pub requires_build: bool,
}

impl ProviderInfo {
    pub fn native(
        id: impl Into<ProviderId>,
        name: impl Into<String>,
        kind: AnalyzerKind,
        languages: Vec<Language>,
        capabilities: Vec<Capability>,
        description: impl Into<String>,
    ) -> Self {
        ProviderInfo {
            id: id.into(),
            name: name.into(),
            origin: ProviderOrigin::Native,
            kind,
            languages,
            capabilities,
            description: description.into(),
            executable: None,
            url: None,
            requires_build: false,
        }
    }

    pub fn requires_build(mut self, yes: bool) -> Self {
        self.requires_build = yes;
        self
    }

    pub fn handles(&self, lang: &Language) -> bool {
        self.languages.contains(lang)
    }

    pub fn provides(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }
}

/// Knobs shared by every provider run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunOptions {
    /// Wall-clock budget for the whole provider, in seconds. `None` means no limit.
    ///
    /// **Not enforced.** No provider reads this, and the engine reports a set
    /// budget in *NOT CHECKED* rather than letting it pass as honoured. It is
    /// kept because external adapters do enforce their own timeout and this is
    /// where a global one belongs when there is cancellation to build it on;
    /// until then a caller must not be allowed to believe it works.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// Provider-specific settings, keyed by provider id.
    ///
    /// **Read by nothing.** No provider consults these, and the example in
    /// [`RunOptions::get`] names a setting that exists only in that sentence. The
    /// engine reports supplied settings in *NOT CHECKED*, because a knob that is
    /// silently ignored is worse than a knob that is absent.
    #[serde(default)]
    pub settings: BTreeMap<String, serde_json::Value>,
    /// Rules to skip regardless of what the provider would emit.
    #[serde(default)]
    pub disabled_rules: Vec<String>,
}

impl RunOptions {
    /// Look up a provider-scoped setting, e.g. `("sda.dynamic", "max_runs")`.
    pub fn get(&self, provider: &str, key: &str) -> Option<&serde_json::Value> {
        self.settings.get(&format!("{provider}.{key}"))
    }
    pub fn set(&mut self, provider: &str, key: &str, v: serde_json::Value) {
        self.settings.insert(format!("{provider}.{key}"), v);
    }
}

/// The single interface every analyzer implements, native or external.
pub trait Analyzer: Send + Sync {
    fn info(&self) -> ProviderInfo;

    /// Whether this provider can run right now. External adapters check that
    /// their executable resolves; native providers are always available.
    fn available(&self) -> Availability {
        Availability::Available
    }

    /// Run against `target`, returning findings.
    fn analyze(&self, target: &Target, opts: &RunOptions) -> crate::Result<Vec<Finding>>;

    /// What the last [`analyze`](Analyzer::analyze) could **not** check, taken
    /// rather than read: the caller drains it once and it is gone.
    ///
    /// A provider that fails is already reported, and a provider that runs is
    /// assumed to have checked what it claims. Neither covers the common middle:
    /// a tool that ran, produced findings, and told you *in its own output* that
    /// it worked with less than it wanted. Cppcheck does this constantly — "the
    /// include <map> was not found", "only 12 of 17 configurations were checked"
    /// — and until this existed those arrived as `information`-severity findings
    /// among the real ones, where filtering a large report to `medium` and above
    /// throws them away and what remains reads as a completed analysis. That is
    /// the failure this whole codebase is organised against, arriving through
    /// the one door nobody had put a guard on.
    ///
    /// Default: nothing, so a provider that has no such story says nothing.
    fn take_notices(&self) -> Vec<crate::Exclusion> {
        Vec::new()
    }
}

/// Marker trait for providers that never execute the target.
pub trait StaticAnalyzer: Analyzer {}

/// Marker trait for providers that do execute the target.
pub trait DynamicAnalyzer: Analyzer {}

/// Result of a provider's readiness check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Availability {
    Available,
    /// Present but with a caveat worth surfacing (e.g. old version).
    Degraded { reason: String },
    Unavailable { reason: String },
}

impl Availability {
    pub fn is_usable(&self) -> bool {
        !matches!(self, Availability::Unavailable { .. })
    }
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Availability::Unavailable { reason: reason.into() }
    }
}

/// Selection policy for a run.
#[derive(Clone, Debug)]
pub struct SelectionPolicy {
    /// When true, external adapters participate alongside native providers.
    pub prefer_external: bool,
    /// Explicitly enabled provider ids. External providers named here run even
    /// when `prefer_external` is false.
    pub enabled: Vec<ProviderId>,
    /// Explicitly disabled provider ids; always wins over everything else.
    pub disabled: Vec<ProviderId>,
    /// Restrict to providers handling at least one of these languages.
    pub languages: Vec<Language>,
    /// Restrict to providers offering at least one of these capabilities.
    pub capabilities: Vec<Capability>,
    /// Restrict to this analyzer kind.
    pub kind: Option<AnalyzerKind>,
}

impl Default for SelectionPolicy {
    /// Native-only, all languages, all capabilities — the hermetic default.
    fn default() -> Self {
        SelectionPolicy {
            prefer_external: false,
            enabled: Vec::new(),
            disabled: Vec::new(),
            languages: Vec::new(),
            capabilities: Vec::new(),
            kind: None,
        }
    }
}

impl SelectionPolicy {
    pub fn with_external(mut self) -> Self {
        self.prefer_external = true;
        self
    }
    pub fn enable(mut self, id: impl Into<ProviderId>) -> Self {
        self.enabled.push(id.into());
        self
    }
    pub fn disable(mut self, id: impl Into<ProviderId>) -> Self {
        self.disabled.push(id.into());
        self
    }
    pub fn for_languages(mut self, langs: Vec<Language>) -> Self {
        self.languages = langs;
        self
    }
    pub fn for_capabilities(mut self, caps: Vec<Capability>) -> Self {
        self.capabilities = caps;
        self
    }
    pub fn only(mut self, kind: AnalyzerKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Decide whether `info` participates in this run, and why not if it doesn't.
    pub fn admits(&self, info: &ProviderInfo) -> Result<(), String> {
        if self.disabled.contains(&info.id) {
            return Err("explicitly disabled".into());
        }
        let explicitly_enabled = self.enabled.contains(&info.id);
        if info.origin == ProviderOrigin::External && !self.prefer_external && !explicitly_enabled {
            return Err("external provider not enabled (native-first policy)".into());
        }
        if let Some(k) = self.kind {
            // A hybrid provider satisfies a request for either half.
            if info.kind != k && info.kind != AnalyzerKind::Hybrid {
                return Err(format!("kind {} does not match requested {}", info.kind.as_str(), k.as_str()));
            }
        }
        if !self.languages.is_empty() && !self.languages.iter().any(|l| info.handles(l)) {
            return Err("no language overlap with target".into());
        }
        if !self.capabilities.is_empty() && !self.capabilities.iter().any(|c| info.provides(*c)) {
            return Err("no requested capability".into());
        }
        Ok(())
    }
}

/// Why a provider was left out of a run. Surfaced to the user and to agents so
/// a short run never silently looks like a clean one.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Exclusion {
    pub provider: ProviderId,
    pub reason: String,
}

/// The set of providers known to this process.
#[derive(Default)]
pub struct Registry {
    providers: Vec<std::sync::Arc<dyn Analyzer>>,
}

impl Registry {
    pub fn new() -> Self {
        Registry { providers: Vec::new() }
    }

    pub fn register(&mut self, p: std::sync::Arc<dyn Analyzer>) -> &mut Self {
        self.providers.push(p);
        self
    }

    pub fn len(&self) -> usize {
        self.providers.len()
    }
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    pub fn all(&self) -> &[std::sync::Arc<dyn Analyzer>] {
        &self.providers
    }

    pub fn get(&self, id: &str) -> Option<&std::sync::Arc<dyn Analyzer>> {
        self.providers.iter().find(|p| p.info().id.as_str() == id)
    }

    /// Every provider's self-description, sorted native-first then by id, so
    /// listings read as "here is what you get by default, here is what you can add".
    pub fn describe(&self) -> Vec<ProviderInfo> {
        let mut v: Vec<ProviderInfo> = self.providers.iter().map(|p| p.info()).collect();
        v.sort_by(|a, b| a.origin.cmp(&b.origin).then(a.id.cmp(&b.id)));
        v
    }

    /// Apply `policy` and availability checks, returning the providers that will
    /// run and a reason for every one that will not.
    pub fn select(
        &self,
        policy: &SelectionPolicy,
    ) -> (Vec<std::sync::Arc<dyn Analyzer>>, Vec<Exclusion>) {
        let mut chosen = Vec::new();
        let mut excluded = Vec::new();
        for p in &self.providers {
            let info = p.info();
            if let Err(reason) = policy.admits(&info) {
                excluded.push(Exclusion { provider: info.id, reason });
                continue;
            }
            match p.available() {
                Availability::Unavailable { reason } => {
                    excluded.push(Exclusion { provider: info.id, reason });
                }
                _ => chosen.push(p.clone()),
            }
        }
        // Native first so their findings anchor correlation before external
        // adapters pile on.
        chosen.sort_by(|a, b| {
            let (x, y) = (a.info(), b.info());
            x.origin.cmp(&y.origin).then(x.id.cmp(&y.id))
        });
        (chosen, excluded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub(ProviderInfo, Availability);
    impl Analyzer for Stub {
        fn info(&self) -> ProviderInfo {
            self.0.clone()
        }
        fn available(&self) -> Availability {
            self.1.clone()
        }
        fn analyze(&self, _t: &Target, _o: &RunOptions) -> crate::Result<Vec<Finding>> {
            Ok(vec![])
        }
    }

    fn info(id: &str, origin: ProviderOrigin, kind: AnalyzerKind) -> ProviderInfo {
        ProviderInfo {
            id: id.into(),
            name: id.into(),
            origin,
            kind,
            languages: vec![Language::C],
            capabilities: vec![Capability::StyleCompliance],
            description: String::new(),
            executable: None,
            url: None,
            requires_build: false,
        }
    }

    fn registry() -> Registry {
        let mut r = Registry::new();
        r.register(std::sync::Arc::new(Stub(
            info("ext.cppcheck", ProviderOrigin::External, AnalyzerKind::Static),
            Availability::Available,
        )));
        r.register(std::sync::Arc::new(Stub(
            info("sda.static.c", ProviderOrigin::Native, AnalyzerKind::Static),
            Availability::Available,
        )));
        r
    }

    #[test]
    fn default_policy_is_native_only() {
        let (chosen, excluded) = registry().select(&SelectionPolicy::default());
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].info().id.as_str(), "sda.static.c");
        assert_eq!(excluded.len(), 1);
        assert!(excluded[0].reason.contains("native-first"));
    }

    #[test]
    fn external_participates_when_opted_in() {
        let (chosen, _) = registry().select(&SelectionPolicy::default().with_external());
        assert_eq!(chosen.len(), 2);
        // Native still sorts first.
        assert_eq!(chosen[0].info().origin, ProviderOrigin::Native);
    }

    #[test]
    fn a_single_external_can_be_enabled_without_opening_the_floodgates() {
        let mut r = registry();
        r.register(std::sync::Arc::new(Stub(
            info("ext.coverity", ProviderOrigin::External, AnalyzerKind::Static),
            Availability::Available,
        )));
        let (chosen, _) = r.select(&SelectionPolicy::default().enable("ext.cppcheck"));
        let ids: Vec<String> = chosen.iter().map(|p| p.info().id.to_string()).collect();
        assert!(ids.contains(&"ext.cppcheck".to_string()));
        assert!(!ids.contains(&"ext.coverity".to_string()));
    }

    #[test]
    fn disable_beats_enable() {
        let policy = SelectionPolicy::default().with_external().disable("ext.cppcheck");
        let (chosen, excluded) = registry().select(&policy);
        assert_eq!(chosen.len(), 1);
        assert_eq!(excluded[0].reason, "explicitly disabled");
    }

    #[test]
    fn unavailable_providers_are_excluded_with_a_reason() {
        let mut r = Registry::new();
        r.register(std::sync::Arc::new(Stub(
            info("ext.gone", ProviderOrigin::External, AnalyzerKind::Static),
            Availability::unavailable("`cppcheck` not found on PATH"),
        )));
        let (chosen, excluded) = r.select(&SelectionPolicy::default().with_external());
        assert!(chosen.is_empty());
        assert!(excluded[0].reason.contains("not found"));
    }

    #[test]
    fn hybrid_providers_satisfy_either_kind_request() {
        let h = info("sda.hybrid", ProviderOrigin::Native, AnalyzerKind::Hybrid);
        assert!(SelectionPolicy::default().only(AnalyzerKind::Static).admits(&h).is_ok());
        assert!(SelectionPolicy::default().only(AnalyzerKind::Dynamic).admits(&h).is_ok());
    }

    #[test]
    fn language_and_capability_filters_apply() {
        let i = info("sda.static.c", ProviderOrigin::Native, AnalyzerKind::Static);
        assert!(SelectionPolicy::default().for_languages(vec![Language::Rust]).admits(&i).is_err());
        assert!(SelectionPolicy::default().for_languages(vec![Language::C]).admits(&i).is_ok());
        assert!(
            SelectionPolicy::default()
                .for_capabilities(vec![Capability::Fuzzing])
                .admits(&i)
                .is_err()
        );
    }
}
