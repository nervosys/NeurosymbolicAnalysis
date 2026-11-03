//! Cross-references into external classification schemes.
//!
//! A finding is far more useful when it can be pivoted through the schemes an
//! organization already tracks: MISRA for automotive/embedded compliance, CWE for
//! weakness triage, OWASP-LLM and MITRE ATLAS for AI risk, and NIST AI RMF for
//! governance evidence. Every finding carries zero or more [`TaxonomyRef`]s.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Taxonomy {
    /// MISRA C:2023 rule or directive.
    MisraC2023,
    /// MISRA C++:2023 rule.
    MisraCpp2023,
    /// The toolkit's Rust 2024 safety profile.
    Rust2024,
    /// CERT C / C++ secure coding rule.
    Cert,
    /// Common Weakness Enumeration, e.g. `CWE-787`.
    Cwe,
    /// A specific published vulnerability, e.g. `CVE-2024-1234`.
    Cve,
    /// OWASP Top 10 for LLM Applications, e.g. `LLM01`.
    OwaspLlm,
    /// MITRE ATLAS adversarial-ML technique, e.g. `AML.T0018`.
    Atlas,
    /// NIST AI Risk Management Framework subcategory, e.g. `MEASURE 2.7`.
    NistAiRmf,
    /// NIST Secure Software Development Framework practice.
    NistSsdf,
    /// AUTOSAR C++14 guideline (legacy, superseded by MISRA C++:2023).
    Autosar,
}

impl Taxonomy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Taxonomy::MisraC2023 => "MISRA-C-2023",
            Taxonomy::MisraCpp2023 => "MISRA-CPP-2023",
            Taxonomy::Rust2024 => "RUST-2024",
            Taxonomy::Cert => "CERT",
            Taxonomy::Cwe => "CWE",
            Taxonomy::Cve => "CVE",
            Taxonomy::OwaspLlm => "OWASP-LLM",
            Taxonomy::Atlas => "ATLAS",
            Taxonomy::NistAiRmf => "NIST-AI-RMF",
            Taxonomy::NistSsdf => "NIST-SSDF",
            Taxonomy::Autosar => "AUTOSAR",
        }
    }

    /// Canonical documentation URL for an identifier in this scheme, when one
    /// can be constructed without a licensed copy of the standard.
    pub fn url_for(&self, id: &str) -> Option<String> {
        match self {
            Taxonomy::Cwe => {
                let n = id.trim_start_matches("CWE-").trim_start_matches("cwe-");
                Some(format!("https://cwe.mitre.org/data/definitions/{n}.html"))
            }
            Taxonomy::Cve => Some(format!("https://nvd.nist.gov/vuln/detail/{id}")),
            Taxonomy::Atlas => Some(format!("https://atlas.mitre.org/techniques/{id}")),
            Taxonomy::NistAiRmf => {
                Some("https://www.nist.gov/itl/ai-risk-management-framework".to_string())
            }
            Taxonomy::OwaspLlm => {
                Some("https://owasp.org/www-project-top-10-for-large-language-model-applications/"
                    .to_string())
            }
            // MISRA and CERT identifiers are only meaningful against the
            // licensed documents; we deliberately do not invent deep links.
            _ => None,
        }
    }

    pub fn all() -> &'static [Taxonomy] {
        &[
            Taxonomy::MisraC2023,
            Taxonomy::MisraCpp2023,
            Taxonomy::Rust2024,
            Taxonomy::Cert,
            Taxonomy::Cwe,
            Taxonomy::Cve,
            Taxonomy::OwaspLlm,
            Taxonomy::Atlas,
            Taxonomy::NistAiRmf,
            Taxonomy::NistSsdf,
            Taxonomy::Autosar,
        ]
    }
}

impl fmt::Display for Taxonomy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single cross-reference, e.g. `CWE-476` or `MISRA-C-2023 Rule 15.5`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TaxonomyRef {
    pub scheme: Taxonomy,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl TaxonomyRef {
    pub fn new(scheme: Taxonomy, id: impl Into<String>) -> Self {
        TaxonomyRef { scheme, id: id.into(), note: None }
    }
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
    pub fn cwe(n: u32) -> Self {
        TaxonomyRef::new(Taxonomy::Cwe, format!("CWE-{n}"))
    }
    pub fn url(&self) -> Option<String> {
        self.scheme.url_for(&self.id)
    }
    /// Fully-qualified form used in reports and fingerprints.
    pub fn qualified(&self) -> String {
        format!("{}:{}", self.scheme.as_str(), self.id)
    }
}

impl fmt::Display for TaxonomyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.qualified())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwe_links_resolve_with_or_without_prefix() {
        assert_eq!(
            Taxonomy::Cwe.url_for("CWE-787").unwrap(),
            "https://cwe.mitre.org/data/definitions/787.html"
        );
        assert_eq!(
            Taxonomy::Cwe.url_for("787").unwrap(),
            "https://cwe.mitre.org/data/definitions/787.html"
        );
    }

    #[test]
    fn licensed_standards_have_no_invented_links() {
        assert!(Taxonomy::MisraC2023.url_for("15.5").is_none());
        assert!(Taxonomy::Cert.url_for("EXP34-C").is_none());
    }

    #[test]
    fn qualified_form_is_round_trippable_by_eye() {
        assert_eq!(TaxonomyRef::cwe(476).qualified(), "CWE:CWE-476");
    }
}
