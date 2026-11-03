//! Coding-standard catalogues: MISRA C:2023, MISRA C++:2023, and the NERVOSYS
//! Rust 2024 safety profile.
//!
//! Two design commitments run through this crate.
//!
//! **Honesty about coverage.** Every guideline records how — or whether — this
//! toolkit can actually check it ([`Coverage`]). A run that reports zero
//! violations of a `Semantics` rule has not verified anything; `sda rules audit`
//! and the report's exclusion list say so out loud. A compliance tool that
//! silently conflates "checked and clean" with "not checked" is worse than none.
//!
//! **Honesty about provenance.** MISRA guideline text is copyright MISRA and is
//! not reproduced, and the built-in MISRA catalogues carry numbers and
//! classification only. Where a rule *number* cannot be stated with confidence — the whole
//! of MISRA C++:2023, whose numbering was rebuilt against the C++ clause
//! structure — [`Rule::confirmed`] is false and reports cite the clause instead
//! of inventing a citation. Use [`Catalog::import`] to merge a licensed list.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod architecture;
pub mod baseline;
pub mod deviation;
pub mod project;
pub mod scope;
pub mod triage;

pub use architecture::{ArchitectureDeclaration, ComponentDecl, FlowDecl};
pub use baseline::Baseline;
pub use deviation::{Deviation, DeviationRegister, DeviationScope};
pub use project::{CONFIG_DIR, ProjectConfig};
pub use scope::{ScopeRegister, ScopeRule};
pub use triage::{TriageRecord, TriageState, TriageStore};

/// A coding standard the toolkit knows about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Standard {
    MisraC2023,
    MisraCpp2023,
    Rust2024,
}

impl Standard {
    pub fn as_str(&self) -> &'static str {
        match self {
            Standard::MisraC2023 => "misra-c-2023",
            Standard::MisraCpp2023 => "misra-cpp-2023",
            Standard::Rust2024 => "rust-2024",
        }
    }
    pub fn title(&self) -> &'static str {
        match self {
            Standard::MisraC2023 => "MISRA C:2023",
            Standard::MisraCpp2023 => "MISRA C++:2023",
            Standard::Rust2024 => "NERVOSYS Rust 2024 safety profile",
        }
    }
    /// Prefix used to build rule identifiers, e.g. `MISRA-C-2023-15.5`.
    pub fn id_prefix(&self) -> &'static str {
        match self {
            Standard::MisraC2023 => "MISRA-C-2023",
            Standard::MisraCpp2023 => "MISRA-CPP-2023",
            Standard::Rust2024 => "RUST-2024",
        }
    }
    pub fn language(&self) -> sda_core::Language {
        match self {
            Standard::MisraC2023 => sda_core::Language::C,
            Standard::MisraCpp2023 => sda_core::Language::Cpp,
            Standard::Rust2024 => sda_core::Language::Rust,
        }
    }
    pub fn taxonomy(&self) -> sda_core::Taxonomy {
        match self {
            Standard::MisraC2023 => sda_core::Taxonomy::MisraC2023,
            Standard::MisraCpp2023 => sda_core::Taxonomy::MisraCpp2023,
            Standard::Rust2024 => sda_core::Taxonomy::Rust2024,
        }
    }
    pub fn all() -> &'static [Standard] {
        &[Standard::MisraC2023, Standard::MisraCpp2023, Standard::Rust2024]
    }
    pub fn parse(s: &str) -> Option<Standard> {
        let n = s.to_ascii_lowercase().replace([' ', '_', ':', '+'], "-");
        Standard::all()
            .iter()
            .copied()
            .find(|st| st.as_str() == n || st.as_str().replace('-', "") == n.replace('-', ""))
    }
    /// Standards applicable to a language.
    pub fn for_language(lang: &sda_core::Language) -> Vec<Standard> {
        Standard::all().iter().copied().filter(|s| s.language() == *lang).collect()
    }
}

impl std::fmt::Display for Standard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.title())
    }
}

/// MISRA's compliance categories, which determine what a deviation costs you.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Obligation {
    /// May never be deviated. A violation is a compliance failure, full stop.
    Mandatory,
    /// May be deviated only with a formal, recorded deviation.
    Required,
    /// May be disapplied with a recorded rationale.
    Advisory,
}

impl Obligation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Obligation::Mandatory => "mandatory",
            Obligation::Required => "required",
            Obligation::Advisory => "advisory",
        }
    }
    /// Whether a deviation record can legitimately silence this guideline.
    pub fn deviable(&self) -> bool {
        !matches!(self, Obligation::Mandatory)
    }
    /// Default severity for a violation of this category.
    pub fn severity(&self) -> sda_core::Severity {
        match self {
            Obligation::Mandatory => sda_core::Severity::High,
            Obligation::Required => sda_core::Severity::Medium,
            Obligation::Advisory => sda_core::Severity::Low,
        }
    }
    fn parse(s: &str) -> Obligation {
        match s {
            "mandatory" => Obligation::Mandatory,
            "advisory" => Obligation::Advisory,
            _ => Obligation::Required,
        }
    }
}

/// Whether conformance can be settled by algorithm at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decidability {
    Decidable,
    /// No analyzer can settle this in general; a clean result is not a proof.
    Undecidable,
}

/// Whether the guideline is judged per translation unit or across the program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Single,
    System,
}

/// How this toolkit checks a guideline. The heart of the crate's honesty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Coverage {
    /// Checked in full by a native engine.
    Native,
    /// Checked natively with known gaps; findings carry reduced confidence and
    /// a clean result does not establish conformance.
    Partial,
    /// Needs type or flow information; routed to a real compiler via `sda-build`.
    Semantics,
    /// Best established by observing execution.
    Dynamic,
    /// Delegated to an external adapter, when the operator enables one.
    External,
    /// A process obligation. No tool can discharge it; it needs a human record.
    Manual,
}

impl Coverage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Coverage::Native => "native",
            Coverage::Partial => "partial",
            Coverage::Semantics => "semantics",
            Coverage::Dynamic => "dynamic",
            Coverage::External => "external",
            Coverage::Manual => "manual",
        }
    }
    /// True when a default, hermetic run actually exercises this guideline.
    pub fn checked_by_default(&self) -> bool {
        matches!(self, Coverage::Native | Coverage::Partial)
    }
    /// True when a clean result constitutes evidence of conformance.
    pub fn clean_means_conformant(&self) -> bool {
        matches!(self, Coverage::Native)
    }
    fn parse(s: &str) -> Coverage {
        match s {
            "native" => Coverage::Native,
            "partial" => Coverage::Partial,
            "semantics" => Coverage::Semantics,
            "dynamic" => Coverage::Dynamic,
            "manual" => Coverage::Manual,
            _ => Coverage::External,
        }
    }
}

/// One guideline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    /// Fully-qualified identifier, e.g. `MISRA-C-2023-15.5`.
    pub id: String,
    pub standard: Standard,
    /// Guideline number as the standard writes it, e.g. `15.5` or `D4.12`.
    pub number: String,
    /// The standard and number for a MISRA guideline unless a list was imported, whose
    /// text is licensed. A short headline for the Rust rules.
    pub title: String,
    pub obligation: Obligation,
    pub decidability: Decidability,
    pub scope: Scope,
    pub coverage: Coverage,
    /// Clause of the parent document, for standards organised by clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clause: Option<String>,
    /// Whether the guideline *number* is confirmed against the published
    /// document. Unconfirmed rules are reported by clause, never by number.
    pub confirmed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<u32>,
    /// True when this entry came from an operator-supplied authoritative list
    /// rather than the built-in catalogue.
    #[serde(default)]
    pub imported: bool,
}

impl Rule {
    /// True when this is a directive rather than a rule (MISRA C numbers
    /// directives `D1.1`, `D4.12`, and so on).
    pub fn is_directive(&self) -> bool {
        self.number.starts_with('D')
    }

    /// How this guideline should be cited in a compliance report.
    ///
    /// An unconfirmed number is never presented as a citation: the clause is
    /// given instead, so a reviewer can find the governing guideline without
    /// the report asserting a number it cannot stand behind.
    pub fn citation(&self) -> String {
        if self.confirmed {
            format!("{} {}", self.standard.title(), self.number)
        } else if let Some(c) = &self.clause {
            format!("{} clause {} (rule number unconfirmed)", self.standard.title(), c)
        } else {
            format!("{} (rule number unconfirmed)", self.standard.title())
        }
    }

    /// Cross-references to attach to a finding for this guideline.
    pub fn taxonomy_refs(&self) -> Vec<sda_core::TaxonomyRef> {
        let mut v = Vec::new();
        if self.confirmed {
            v.push(sda_core::TaxonomyRef::new(self.standard.taxonomy(), self.number.clone()));
        } else if let Some(c) = &self.clause {
            v.push(
                sda_core::TaxonomyRef::new(self.standard.taxonomy(), format!("clause {c}"))
                    .with_note("rule number not confirmed against the published document"),
            );
        }
        if let Some(cwe) = self.cwe {
            v.push(sda_core::TaxonomyRef::cwe(cwe));
        }
        v
    }

    pub fn severity(&self) -> sda_core::Severity {
        self.obligation.severity()
    }

    /// Confidence ceiling implied by how this guideline is checked. A partially
    /// implemented check may not claim high confidence.
    pub fn confidence_ceiling(&self) -> sda_core::Confidence {
        match self.coverage {
            Coverage::Native => sda_core::Confidence::High,
            Coverage::Dynamic => sda_core::Confidence::Certain,
            Coverage::Partial => sda_core::Confidence::Medium,
            _ => sda_core::Confidence::Low,
        }
    }
}

// --- catalogue -------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawCatalog {
    #[serde(default)]
    completeness: Option<String>,
    #[serde(default)]
    rule: Vec<RawRule>,
    #[serde(default)]
    clause: Vec<RawClause>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    n: String,
    // Absent from the MISRA catalogues, whose text is licensed: a list imported
    // by someone who holds the document supplies it.
    #[serde(default)]
    t: String,
    o: String,
    d: String,
    s: String,
    c: String,
    #[serde(default)]
    clause: Option<String>,
    #[serde(default = "default_true")]
    confirmed: bool,
    #[serde(default)]
    cwe: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RawClause {
    n: String,
    t: String,
}

fn default_true() -> bool {
    true
}

/// A loaded standard: its rules, its clause index, and how complete it is.
#[derive(Clone, Debug)]
pub struct Catalog {
    pub standard: Standard,
    rules: BTreeMap<String, Rule>,
    clauses: BTreeMap<String, String>,
    complete: bool,
}

const MISRA_C: &str = include_str!("../data/misra-c-2023.toml");
const MISRA_CPP: &str = include_str!("../data/misra-cpp-2023.toml");
const RUST_2024: &str = include_str!("../data/rust-2024.toml");

impl Catalog {
    /// Load a built-in catalogue.
    ///
    /// # Panics
    /// Only if a built-in catalogue file is malformed, which the test suite
    /// prevents from ever shipping.
    pub fn load(standard: Standard) -> Catalog {
        let text = match standard {
            Standard::MisraC2023 => MISRA_C,
            Standard::MisraCpp2023 => MISRA_CPP,
            Standard::Rust2024 => RUST_2024,
        };
        Catalog::parse(standard, text)
            .unwrap_or_else(|e| panic!("built-in catalogue for {standard} is malformed: {e}"))
    }

    pub fn parse(standard: Standard, text: &str) -> Result<Catalog, String> {
        let raw: RawCatalog = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut rules = BTreeMap::new();
        for r in raw.rule {
            let rule = Rule {
                id: format!("{}-{}", standard.id_prefix(), r.n),
                standard,
                number: r.n.clone(),
                title: if r.t.is_empty() {
                    format!("{} {}", standard.title(), r.n)
                } else {
                    r.t
                },
                obligation: Obligation::parse(&r.o),
                decidability: if r.d == "decidable" {
                    Decidability::Decidable
                } else {
                    Decidability::Undecidable
                },
                scope: if r.s == "system" { Scope::System } else { Scope::Single },
                coverage: Coverage::parse(&r.c),
                clause: r.clause,
                confirmed: r.confirmed,
                cwe: r.cwe,
                imported: false,
            };
            rules.insert(r.n, rule);
        }
        let clauses = raw.clause.into_iter().map(|c| (c.n, c.t)).collect();
        Ok(Catalog {
            standard,
            rules,
            clauses,
            complete: raw.completeness.as_deref() != Some("partial"),
        })
    }

    /// Merge an operator-supplied authoritative list over the built-in one.
    ///
    /// Imported entries are marked `confirmed`, which is the whole point — it
    /// upgrades clause-level citations to real ones — and bring their titles.
    ///
    /// They do not get to say what this engine checks: `coverage` of a known
    /// number stays the built-in value, because a document cannot know it. Nor
    /// do they restate a number the built-in catalogue has already confirmed:
    /// its obligation and decidability stay. A scanned project supplies this
    /// file from `.sda/`, and before this an imported entry could make a
    /// Mandatory rule's findings Low and lift their confidence to that of a
    /// fully native check. Found by a security audit.
    pub fn import(&mut self, text: &str) -> Result<usize, String> {
        let other = Catalog::parse(self.standard, text)?;
        let n = other.rules.len();
        for (number, mut rule) in other.rules {
            if let Some(known) = self.rules.get(&number) {
                rule.coverage = known.coverage;
                rule.cwe = rule.cwe.or(known.cwe);
                if known.confirmed {
                    rule.obligation = known.obligation;
                    rule.decidability = known.decidability;
                }
            }
            rule.imported = true;
            rule.confirmed = true;
            self.rules.insert(number, rule);
        }
        if n > 0 && self.rules.values().all(|r| r.confirmed) {
            self.complete = true;
        }
        Ok(n)
    }

    /// How many operator-imported rules declare `system` scope.
    ///
    /// [`Rule::scope`] is parsed from the `s` key and no check reads it, so a
    /// project's declaration that a guideline is judged across the program does
    /// not change any result. The caller reports it; see
    /// `ProjectConfig::discover`.
    pub fn imported_system_scope(&self) -> usize {
        self.rules.values().filter(|r| r.imported && r.scope == Scope::System).count()
    }

    pub fn get(&self, number: &str) -> Option<&Rule> {
        self.rules.get(number)
    }

    /// Look up by fully-qualified id, e.g. `MISRA-C-2023-15.5`.
    pub fn get_by_id(&self, id: &str) -> Option<&Rule> {
        self.rules.values().find(|r| r.id == id)
    }

    /// All rules, ordered by guideline number (directives first, then numeric).
    pub fn rules(&self) -> Vec<&Rule> {
        let mut v: Vec<&Rule> = self.rules.values().collect();
        v.sort_by_key(|r| sort_key(&r.number));
        v
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether the catalogue claims to be a complete transcription.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn clause_title(&self, n: &str) -> Option<&str> {
        self.clauses.get(n).map(|s| s.as_str())
    }

    pub fn find(&self, query: &str) -> Vec<&Rule> {
        let q = query.to_ascii_lowercase();
        let mut v: Vec<&Rule> = self
            .rules
            .values()
            .filter(|r| {
                r.number.to_ascii_lowercase().contains(&q)
                    || r.title.to_ascii_lowercase().contains(&q)
                    || r.id.to_ascii_lowercase().contains(&q)
            })
            .collect();
        v.sort_by_key(|r| sort_key(&r.number));
        v
    }

    pub fn by_coverage(&self, c: Coverage) -> Vec<&Rule> {
        let mut v: Vec<&Rule> = self.rules.values().filter(|r| r.coverage == c).collect();
        v.sort_by_key(|r| sort_key(&r.number));
        v
    }

    pub fn by_obligation(&self, o: Obligation) -> Vec<&Rule> {
        let mut v: Vec<&Rule> = self.rules.values().filter(|r| r.obligation == o).collect();
        v.sort_by_key(|r| sort_key(&r.number));
        v
    }

    /// A coverage audit: what this toolkit does and does not check, by category.
    pub fn audit(&self) -> Audit {
        let mut by_coverage: BTreeMap<String, usize> = BTreeMap::new();
        let mut by_obligation: BTreeMap<String, usize> = BTreeMap::new();
        for r in self.rules.values() {
            *by_coverage.entry(r.coverage.as_str().to_string()).or_default() += 1;
            *by_obligation.entry(r.obligation.as_str().to_string()).or_default() += 1;
        }
        Audit {
            standard: self.standard,
            total: self.rules.len(),
            catalog_complete: self.complete,
            unconfirmed_numbers: self.rules.values().filter(|r| !r.confirmed).count(),
            checked_by_default: self
                .rules
                .values()
                .filter(|r| r.coverage.checked_by_default())
                .count(),
            conformance_provable: self
                .rules
                .values()
                .filter(|r| r.coverage.clean_means_conformant())
                .count(),
            undecidable: self
                .rules
                .values()
                .filter(|r| r.decidability == Decidability::Undecidable)
                .count(),
            by_coverage,
            by_obligation,
        }
    }
}

/// Sort key that orders `D1.1` before `1.1` and `2.10` after `2.9`.
fn sort_key(number: &str) -> (u8, Vec<u32>, String) {
    let (group, rest) = match number.strip_prefix('D') {
        Some(r) => (0u8, r),
        None => (1u8, number),
    };
    let parts: Vec<u32> = rest.split('.').filter_map(|p| p.parse().ok()).collect();
    // Non-numeric schemes (the Rust profile's `UNSAFE.1`) fall back to text.
    (group, parts, rest.to_string())
}

/// The result of a coverage audit, rendered by `sda rules audit`.
#[derive(Clone, Debug, Serialize)]
pub struct Audit {
    pub standard: Standard,
    pub total: usize,
    /// Whether the catalogue is a complete transcription of the standard.
    pub catalog_complete: bool,
    /// Guidelines whose *number* is not confirmed against the document.
    pub unconfirmed_numbers: usize,
    /// Guidelines a default hermetic run actually exercises.
    pub checked_by_default: usize,
    /// Guidelines where a clean result is genuine evidence of conformance.
    pub conformance_provable: usize,
    /// Guidelines no analyzer can settle in general.
    pub undecidable: usize,
    pub by_coverage: BTreeMap<String, usize>,
    pub by_obligation: BTreeMap<String, usize>,
}

impl Audit {
    /// A one-paragraph statement of what a clean run does and does not mean.
    /// Printed at the top of every compliance report, by design.
    pub fn caveat(&self) -> String {
        let pct = (self.conformance_provable * 100).checked_div(self.total).unwrap_or(0);
        let mut s = format!(
            "{}: {} guidelines catalogued. {} are exercised by a default run; \
             a clean result is evidence of conformance for {} of them ({pct}%). \
             {} are undecidable in general.",
            self.standard.title(),
            self.total,
            self.checked_by_default,
            self.conformance_provable,
            self.undecidable,
        );
        if !self.catalog_complete {
            s.push_str(
                " This catalogue is PARTIAL: guidelines absent from it were not checked at all.",
            );
        }
        if self.unconfirmed_numbers > 0 {
            s.push_str(&format!(
                " {} guideline numbers are unconfirmed and are cited by clause only.",
                self.unconfirmed_numbers
            ));
        }
        s
    }
}

/// All built-in catalogues.
pub fn all_catalogs() -> Vec<Catalog> {
    Standard::all().iter().map(|s| Catalog::load(*s)).collect()
}

/// Resolve a rule by fully-qualified id across every built-in catalogue.
pub fn lookup(id: &str) -> Option<Rule> {
    all_catalogs().into_iter().find_map(|c| c.get_by_id(id).cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_catalog_parses() {
        for s in Standard::all() {
            let c = Catalog::load(*s);
            assert!(!c.is_empty(), "{s} catalogue is empty");
        }
    }

    #[test]
    fn misra_c_catalog_spans_directives_and_all_rule_chapters() {
        let c = Catalog::load(Standard::MisraC2023);
        assert!(c.len() > 170, "expected a substantial catalogue, got {}", c.len());
        assert!(c.get("D4.12").is_some(), "directives must be present");
        assert!(c.get("1.1").is_some());
        assert!(c.get("22.20").is_some(), "concurrency rules must be present");
        assert!(c.is_complete());
    }

    #[test]
    fn rules_sort_numerically_not_lexically() {
        let c = Catalog::load(Standard::MisraC2023);
        let rules = c.rules();
        let numbers: Vec<&str> = rules.iter().map(|r| r.number.as_str()).collect();
        let i2 = numbers.iter().position(|n| *n == "2.8").unwrap();
        let i21 = numbers.iter().position(|n| *n == "21.10").unwrap();
        assert!(i2 < i21, "2.8 must sort before 21.10, not after it lexically");
        let i21_2 = numbers.iter().position(|n| *n == "21.2").unwrap();
        assert!(i21_2 < i21, "21.2 must sort before 21.10");
        assert!(numbers[0].starts_with('D'), "directives sort first");
    }

    #[test]
    fn obligation_drives_severity_and_deviability() {
        assert!(!Obligation::Mandatory.deviable());
        assert!(Obligation::Required.deviable());
        assert_eq!(Obligation::Mandatory.severity(), sda_core::Severity::High);
        assert_eq!(Obligation::Advisory.severity(), sda_core::Severity::Low);
    }

    #[test]
    fn confirmed_rules_cite_a_number_and_unconfirmed_ones_cite_a_clause() {
        let c = Catalog::load(Standard::MisraC2023);
        assert_eq!(c.get("15.5").unwrap().citation(), "MISRA C:2023 15.5");

        let cpp = Catalog::load(Standard::MisraCpp2023);
        let unconfirmed = cpp.rules().into_iter().find(|r| !r.confirmed).unwrap();
        let cite = unconfirmed.citation();
        assert!(cite.contains("clause"), "got {cite}");
        assert!(cite.contains("unconfirmed"));
    }

    #[test]
    fn unconfirmed_rules_never_emit_a_numbered_taxonomy_reference() {
        let cpp = Catalog::load(Standard::MisraCpp2023);
        let r = cpp.rules().into_iter().find(|r| !r.confirmed).unwrap();
        let refs = r.taxonomy_refs();
        let misra = refs.iter().find(|t| t.scheme == sda_core::Taxonomy::MisraCpp2023).unwrap();
        assert!(misra.id.starts_with("clause "), "got {}", misra.id);
        assert!(misra.note.is_some());
    }

    #[test]
    fn cwe_cross_references_are_attached_when_present() {
        let c = Catalog::load(Standard::MisraC2023);
        let refs = c.get("21.17").unwrap().taxonomy_refs();
        assert!(refs.iter().any(|t| t.id == "CWE-787"));
    }

    #[test]
    fn cpp_catalog_declares_itself_partial() {
        let cpp = Catalog::load(Standard::MisraCpp2023);
        assert!(!cpp.is_complete());
        assert!(cpp.audit().caveat().contains("PARTIAL"));
        assert!(cpp.clause_title("9").is_some(), "clause index must be populated");
    }

    #[test]
    fn rust_profile_is_complete_by_construction() {
        let r = Catalog::load(Standard::Rust2024);
        assert!(r.is_complete());
        assert_eq!(r.audit().unconfirmed_numbers, 0);
        assert!(r.get("UNSAFE.1").is_some());
        assert!(r.get("MODEL.3").is_some(), "embedded-AI rules must be present");
    }

    #[test]
    fn audit_separates_checked_from_conformance_provable() {
        let a = Catalog::load(Standard::MisraC2023).audit();
        assert!(a.checked_by_default > 0);
        assert!(
            a.conformance_provable <= a.checked_by_default,
            "a clean result cannot prove more than was checked"
        );
        assert!(a.undecidable > 0, "MISRA has undecidable guidelines and we must say so");
        assert!(a.caveat().contains("undecidable"));
    }

    /// An undecidable guideline can never be `native`, in any catalogue.
    ///
    /// `Decidability::Undecidable` is documented as "no analyzer can settle this
    /// in general; a clean result is not a proof", and `Coverage::Native` is
    /// documented as the class where a clean result *is* evidence of
    /// conformance. A guideline marked both says both things, and `sda rules
    /// audit` then counts it towards `conformance_provable`.
    ///
    /// MISRA C D4.4 was marked both: it is about code left commented out, and
    /// is decided by a heuristic that tells code from prose about code. It was
    /// found by hand while chasing 12.1, which was the same defect arrived at
    /// from the other direction: an open-ended guideline whose check samples it.
    /// This makes the class of mistake impossible rather than fixed once.
    #[test]
    fn nothing_undecidable_claims_a_clean_result_proves_conformance() {
        for standard in Standard::all() {
            let catalog = Catalog::load(*standard);
            for rule in catalog.rules() {
                assert!(
                    !(rule.decidability == Decidability::Undecidable
                        && rule.coverage.clean_means_conformant()),
                    "{standard} {}: marked `{}` — undecidable, yet a clean result is offered as                      evidence of conformance. `partial` is the honest class",
                    rule.number,
                    rule.coverage.as_str()
                );
            }
        }
    }

    #[test]
    fn coverage_semantics_are_distinct() {
        assert!(Coverage::Native.clean_means_conformant());
        assert!(!Coverage::Partial.clean_means_conformant());
        assert!(Coverage::Partial.checked_by_default());
        assert!(!Coverage::Semantics.checked_by_default());
        assert!(!Coverage::Manual.checked_by_default());
    }

    #[test]
    fn importing_an_authoritative_list_upgrades_citations() {
        let mut cpp = Catalog::load(Standard::MisraCpp2023);
        let before = cpp.audit().unconfirmed_numbers;
        assert!(before > 0);

        let imported = cpp
            .import(
                "standard = \"MISRA C++:2023\"\n\
                 [[rule]]\nn = \"8.2.2\"\nt = \"Official text placeholder\"\n\
                 o = \"required\"\nd = \"decidable\"\ns = \"single\"\nc = \"native\"\n",
            )
            .unwrap();
        assert_eq!(imported, 1);
        let r = cpp.get("8.2.2").unwrap();
        assert!(r.confirmed && r.imported);
        assert_eq!(r.citation(), "MISRA C++:2023 8.2.2");
        assert_eq!(cpp.audit().unconfirmed_numbers, before - 1);
    }

    /// A scanned project's `.sda/misra-c-2023.toml` is imported. It may bring a
    /// title, and nothing else about a number already confirmed: not a lower
    /// obligation, and never a coverage this engine does not have.
    #[test]
    fn an_imported_list_cannot_restate_what_is_already_known() {
        let mut c = Catalog::load(Standard::MisraC2023);
        let before = c.get("9.1").unwrap().clone();
        assert_eq!(before.obligation, Obligation::Mandatory);
        c.import(
            "[[rule]]\nn = \"9.1\"\nt = \"A title\"\no = \"advisory\"\nd = \"decidable\"\n\
             s = \"single\"\nc = \"native\"\n",
        )
        .unwrap();
        let after = c.get("9.1").unwrap();
        assert_eq!(after.title, "A title");
        assert_eq!(after.obligation, Obligation::Mandatory);
        assert_eq!(after.decidability, before.decidability);
        assert_eq!(after.coverage, before.coverage);
        assert_eq!(after.cwe, before.cwe);
    }

    #[test]
    fn directives_are_distinguishable_from_rules() {
        let c = Catalog::load(Standard::MisraC2023);
        assert!(c.get("D4.12").unwrap().is_directive());
        assert!(!c.get("15.5").unwrap().is_directive());
    }

    #[test]
    fn search_matches_number_title_and_id() {
        let c = Catalog::load(Standard::MisraC2023);
        assert!(!c.find("15.5").is_empty());
        assert!(!c.find("MISRA-C-2023-15.5").is_empty());
    }

    #[test]
    fn standards_resolve_from_loose_user_input() {
        assert_eq!(Standard::parse("misra-c-2023"), Some(Standard::MisraC2023));
        assert_eq!(Standard::parse("MISRA C 2023"), Some(Standard::MisraC2023));
        assert_eq!(Standard::parse("rust-2024"), Some(Standard::Rust2024));
        assert_eq!(Standard::parse("nonsense"), None);
    }

    #[test]
    fn standards_map_to_their_language() {
        assert_eq!(Standard::for_language(&sda_core::Language::C), vec![Standard::MisraC2023]);
        assert_eq!(Standard::for_language(&sda_core::Language::Rust), vec![Standard::Rust2024]);
    }

    #[test]
    fn global_lookup_finds_rules_across_catalogs() {
        assert!(lookup("MISRA-C-2023-15.5").is_some());
        assert!(lookup("RUST-2024-UNSAFE.1").is_some());
        assert!(lookup("NOT-A-RULE").is_none());
    }

    #[test]
    fn confidence_is_capped_by_how_well_we_check() {
        let c = Catalog::load(Standard::MisraC2023);
        assert_eq!(c.get("15.5").unwrap().confidence_ceiling(), sda_core::Confidence::High);
        assert_eq!(c.get("14.2").unwrap().confidence_ceiling(), sda_core::Confidence::Medium);
    }
}


#[cfg(test)]
mod standard_list_tests {
    use super::Standard;

    /// Every standard is in `all()`, and survives a round trip through its name.
    ///
    /// `all()` is not a convenience here. `ProjectConfig::discover` iterates it to
    /// find a project's catalogue overrides — `.sda/misra-c-2023.toml` and its
    /// siblings — so a standard missing from the list means a project ships its
    /// own transcription of that standard and the file is never looked for. The
    /// built-in catalogue stays silently in place and the conformance argument
    /// rests on rule text nobody supplied, which is a defect this document
    /// already records once.
    ///
    /// The `match` is the forcing function: a fourth standard does not compile
    /// until it is named here, and naming it here is the prompt to add it to
    /// `all()` too.
    #[test]
    fn every_standard_is_listed_in_all_and_parses_back() {
        use Standard::*;

        let every = [MisraC2023, MisraCpp2023, Rust2024];

        for st in every {
            match st {
                MisraC2023 | MisraCpp2023 | Rust2024 => {}
            }

            assert!(
                Standard::all().contains(&st),
                "{st:?} is missing from `all()`, so a project's `.sda/{}.toml` would never \
                 be looked for and its catalogue override would be ignored in silence",
                st.as_str()
            );
            assert_eq!(
                Standard::parse(st.as_str()),
                Some(st),
                "{st:?} does not survive `as_str` then `parse`"
            );
        }

        assert_eq!(
            Standard::all().len(),
            every.len(),
            "`all()` and the enum have drifted apart in the other direction"
        );
    }
}
