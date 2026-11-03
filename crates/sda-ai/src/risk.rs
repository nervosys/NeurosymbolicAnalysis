//! The LLM vulnerability taxonomy and its mapping onto the NIST AI RMF.

use sda_core::{Severity, Taxonomy, TaxonomyRef};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Which analysis phase can detect a risk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// Findable by inspecting the artifact or the calling code.
    Static,
    /// Requires running the model and observing its behaviour.
    Dynamic,
    /// Both contribute, and neither is sufficient alone.
    Both,
    /// Needs an organisational record, not a tool.
    Manual,
}

impl Phase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::Static => "static",
            Phase::Dynamic => "dynamic",
            Phase::Both => "both",
            Phase::Manual => "manual",
        }
    }
    pub fn scannable(&self) -> bool {
        matches!(self, Phase::Static | Phase::Both)
    }
    pub fn probeable(&self) -> bool {
        matches!(self, Phase::Dynamic | Phase::Both)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct RawRisk {
    id: String,
    title: String,
    detail: String,
    phase: String,
    severity: String,
    #[serde(default)]
    owasp: Option<String>,
    #[serde(default)]
    atlas: Option<String>,
    #[serde(default)]
    rmf: Vec<String>,
    #[serde(default)]
    cwe: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawRisks {
    risk: Vec<RawRisk>,
}

/// One risk in the taxonomy.
#[derive(Clone, Debug, Serialize)]
pub struct Risk {
    pub id: String,
    pub title: String,
    /// Why it matters, written for an embedded-systems audience.
    pub detail: String,
    pub phase: Phase,
    pub severity: Severity,
    pub owasp: Option<String>,
    pub atlas: Option<String>,
    /// NIST AI RMF subcategories this risk engages.
    pub rmf: Vec<String>,
    pub cwe: Option<u32>,
}

impl Risk {
    /// Cross-references to attach to a finding for this risk.
    pub fn taxonomy_refs(&self) -> Vec<TaxonomyRef> {
        let mut v = Vec::new();
        if let Some(o) = &self.owasp {
            v.push(TaxonomyRef::new(Taxonomy::OwaspLlm, o.clone()));
        }
        if let Some(a) = &self.atlas {
            v.push(TaxonomyRef::new(Taxonomy::Atlas, a.clone()));
        }
        for r in &self.rmf {
            v.push(TaxonomyRef::new(Taxonomy::NistAiRmf, r.clone()));
        }
        if let Some(c) = self.cwe {
            v.push(TaxonomyRef::cwe(c));
        }
        v
    }

    /// Rule identifier used on findings, e.g. `AI-SLEEPER-AGENT`.
    pub fn rule_id(&self) -> String {
        format!("AI-{}", self.id)
    }
}

fn severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn phase(s: &str) -> Phase {
    match s {
        "static" => Phase::Static,
        "dynamic" => Phase::Dynamic,
        "manual" => Phase::Manual,
        _ => Phase::Both,
    }
}

const RISKS: &str = include_str!("../data/llm-risks.toml");
const RMF: &str = include_str!("../data/nist-ai-rmf.toml");

/// The loaded taxonomy.
#[derive(Clone, Debug)]
pub struct Taxonomy2 {
    risks: BTreeMap<String, Risk>,
}

impl Default for Taxonomy2 {
    fn default() -> Self {
        Self::load()
    }
}

impl Taxonomy2 {
    /// # Panics
    /// Only if the built-in taxonomy is malformed, which a test prevents.
    pub fn load() -> Self {
        let raw: RawRisks =
            toml::from_str(RISKS).unwrap_or_else(|e| panic!("built-in LLM risk taxonomy is malformed: {e}"));
        let risks = raw
            .risk
            .into_iter()
            .map(|r| {
                (
                    r.id.clone(),
                    Risk {
                        id: r.id,
                        title: r.title,
                        detail: r.detail.trim().to_string(),
                        phase: phase(&r.phase),
                        severity: severity(&r.severity),
                        owasp: r.owasp,
                        atlas: r.atlas,
                        rmf: r.rmf,
                        cwe: r.cwe,
                    },
                )
            })
            .collect();
        Taxonomy2 { risks }
    }

    pub fn get(&self, id: &str) -> Option<&Risk> {
        self.risks.get(id)
    }
    pub fn all(&self) -> Vec<&Risk> {
        self.risks.values().collect()
    }
    pub fn len(&self) -> usize {
        self.risks.len()
    }
    pub fn is_empty(&self) -> bool {
        self.risks.is_empty()
    }
    pub fn by_phase(&self, p: Phase) -> Vec<&Risk> {
        self.risks.values().filter(|r| r.phase == p || r.phase == Phase::Both).collect()
    }
    /// Risks engaging a given NIST AI RMF subcategory.
    pub fn for_rmf(&self, subcategory: &str) -> Vec<&Risk> {
        self.risks.values().filter(|r| r.rmf.iter().any(|s| s == subcategory)).collect()
    }
}

// --- NIST AI RMF -----------------------------------------------------------

/// Whether mechanical evidence for a subcategory is possible at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceKind {
    /// A scan or probe produces real evidence.
    Tool,
    /// A scan contributes but cannot discharge the subcategory.
    Partial,
    /// Needs an organisational record; no tool can discharge it.
    Process,
}

impl EvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceKind::Tool => "tool",
            EvidenceKind::Partial => "partial",
            EvidenceKind::Process => "process",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct RawSub {
    id: String,
    title: String,
    evidence: String,
}

#[derive(Clone, Debug, Deserialize)]
struct RawRmf {
    framework: String,
    subcategory: Vec<RawSub>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Subcategory {
    pub id: String,
    pub title: String,
    pub evidence: EvidenceKind,
    /// The function the subcategory belongs to: GOVERN, MAP, MEASURE, MANAGE.
    pub function: String,
}

/// The AI RMF index.
#[derive(Clone, Debug)]
pub struct Rmf {
    pub framework: String,
    subcategories: BTreeMap<String, Subcategory>,
}

impl Default for Rmf {
    fn default() -> Self {
        Self::load()
    }
}

impl Rmf {
    pub fn load() -> Self {
        let raw: RawRmf =
            toml::from_str(RMF).unwrap_or_else(|e| panic!("built-in AI RMF index is malformed: {e}"));
        let subcategories = raw
            .subcategory
            .into_iter()
            .map(|s| {
                let function = s.id.split_whitespace().next().unwrap_or("").to_string();
                let evidence = match s.evidence.as_str() {
                    "tool" => EvidenceKind::Tool,
                    "partial" => EvidenceKind::Partial,
                    _ => EvidenceKind::Process,
                };
                (s.id.clone(), Subcategory { id: s.id, title: s.title, evidence, function })
            })
            .collect();
        Rmf { framework: raw.framework, subcategories }
    }

    pub fn get(&self, id: &str) -> Option<&Subcategory> {
        self.subcategories.get(id)
    }
    pub fn all(&self) -> Vec<&Subcategory> {
        self.subcategories.values().collect()
    }
    pub fn function(&self, f: &str) -> Vec<&Subcategory> {
        self.subcategories.values().filter(|s| s.function == f).collect()
    }
    pub fn functions(&self) -> Vec<String> {
        let mut v: Vec<String> = self.subcategories.values().map(|s| s.function.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// A statement of what a scan can and cannot contribute to an AI RMF
    /// assessment. Printed with every AI report.
    pub fn caveat(&self) -> String {
        let total = self.subcategories.len();
        let tool = self.subcategories.values().filter(|s| s.evidence == EvidenceKind::Tool).count();
        let process =
            self.subcategories.values().filter(|s| s.evidence == EvidenceKind::Process).count();
        format!(
            "{}: of the {total} subcategories this toolkit indexes, {tool} can be supported by \
             mechanical evidence from a scan or probe campaign, and {process} require an \
             organisational record that no tool can produce. A clean scan is evidence for the \
             first group and says nothing at all about the second.",
            self.framework
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_taxonomy_loads_and_covers_the_named_risks() {
        let t = Taxonomy2::load();
        assert!(t.len() >= 15, "got {}", t.len());
        for id in ["SLEEPER-AGENT", "MODEL-POISONING", "CENSORSHIP-BIAS", "UNSAFE-DESERIALIZATION"] {
            assert!(t.get(id).is_some(), "{id} missing from the taxonomy");
        }
    }

    #[test]
    fn sleeper_agents_are_critical_and_need_both_phases() {
        let t = Taxonomy2::load();
        let r = t.get("SLEEPER-AGENT").unwrap();
        assert_eq!(r.severity, Severity::Critical);
        assert_eq!(r.phase, Phase::Both);
        assert!(r.phase.scannable() && r.phase.probeable());
        assert!(r.detail.contains("prove absence"), "the write-up must state the limits of detection");
    }

    #[test]
    fn risks_carry_owasp_atlas_and_rmf_cross_references() {
        let t = Taxonomy2::load();
        let refs = t.get("UNSAFE-DESERIALIZATION").unwrap().taxonomy_refs();
        assert!(refs.iter().any(|r| r.scheme == sda_core::Taxonomy::OwaspLlm));
        assert!(refs.iter().any(|r| r.scheme == sda_core::Taxonomy::Atlas));
        assert!(refs.iter().any(|r| r.scheme == sda_core::Taxonomy::NistAiRmf));
        assert!(refs.iter().any(|r| r.id == "CWE-502"));
    }

    #[test]
    fn phase_filters_route_risks_to_the_right_engine() {
        let t = Taxonomy2::load();
        assert!(t.by_phase(Phase::Static).iter().any(|r| r.id == "UNSAFE-DESERIALIZATION"));
        assert!(t.by_phase(Phase::Dynamic).iter().any(|r| r.id == "JAILBREAK"));
        // A `Both` risk appears under either filter, which is the point.
        assert!(t.by_phase(Phase::Static).iter().any(|r| r.id == "SLEEPER-AGENT"));
        assert!(t.by_phase(Phase::Dynamic).iter().any(|r| r.id == "SLEEPER-AGENT"));
    }

    #[test]
    fn the_rmf_index_loads_with_all_four_functions() {
        let r = Rmf::load();
        let f = r.functions();
        for want in ["GOVERN", "MAP", "MEASURE", "MANAGE"] {
            assert!(f.contains(&want.to_string()), "missing function {want}");
        }
    }

    #[test]
    fn process_subcategories_are_never_claimed_as_tool_evidence() {
        let r = Rmf::load();
        assert_eq!(r.get("GOVERN 1.1").unwrap().evidence, EvidenceKind::Process);
        assert_eq!(r.get("MEASURE 2.7").unwrap().evidence, EvidenceKind::Tool);
        let caveat = r.caveat();
        assert!(caveat.contains("says nothing at all"));
    }

    #[test]
    fn risks_can_be_looked_up_by_rmf_subcategory() {
        let t = Taxonomy2::load();
        let engaged = t.for_rmf("MEASURE 2.7");
        assert!(engaged.len() >= 3, "MEASURE 2.7 is the security subcategory; expected several");
    }

    #[test]
    fn every_rmf_reference_in_the_taxonomy_exists_in_the_index() {
        let t = Taxonomy2::load();
        let r = Rmf::load();
        for risk in t.all() {
            for sub in &risk.rmf {
                assert!(
                    r.get(sub).is_some(),
                    "risk `{}` references AI RMF subcategory `{sub}`, which the index does not define",
                    risk.id
                );
            }
        }
    }
}

