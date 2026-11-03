//! AI model security analysis.
//!
//! Local models are increasingly compiled into firmware on devices that are
//! physically reachable, rarely updated, and safety-relevant. That combination
//! changes what a model file is: not an asset the build system copies, but an
//! **untrusted input with a deserializer attached**, and often an executable one.
//!
//! This crate extends statodynamic analysis to cover it:
//!
//! * [`formats`] and [`pickle`] parse model containers natively, treating every
//!   header field as attacker-controlled — the static half.
//! * [`probe`] specifies and evaluates behavioural probe campaigns against a
//!   running model — the dynamic half.
//! * [`risk`] holds the LLM vulnerability taxonomy and its mapping onto the
//!   OWASP LLM Top 10, MITRE ATLAS, and the NIST AI Risk Management Framework.
//!
//! The two halves connect the same way they do for code: the artifact scan finds
//! tokenizer entries that look like triggers, and those seed the probe campaign
//! that tries to make the model act on them.

#![forbid(unsafe_code)]

pub mod formats;
pub mod pickle;
pub mod probe;
pub mod risk;
pub mod scan;

pub use formats::{Format, GgufHeader, SafetensorsHeader};
pub use pickle::{PickleScan, Risk as PickleRisk};
pub use probe::{Probe, ProbeReport, ProbeResponse, ProbeRunner, default_suite, suite_for_triggers};
pub use risk::{EvidenceKind, Phase, Rmf, Risk, Taxonomy2 as RiskTaxonomy};
pub use scan::{ArtifactReport, ModelScanner};

/// A registry containing the native AI providers.
///
/// The probe runner is registered even though it usually cannot run: an
/// unavailable provider appears in the report's exclusion list with its reason,
/// which is how a run that never tested for backdoors admits it. Leaving it out
/// would make the same run look complete.
pub fn ai_registry() -> sda_core::Registry {
    let mut r = sda_core::Registry::new();
    r.register(std::sync::Arc::new(ModelScanner::new()));
    r.register(std::sync::Arc::new(ProbeRunner::new()));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ai_registry_holds_both_halves_of_ai_analysis() {
        let r = ai_registry();
        assert_eq!(r.len(), 2);
        assert!(r.describe().iter().all(|p| p.origin == sda_core::ProviderOrigin::Native));
        assert!(r.get("sda.ai.artifact").is_some(), "the static half");
        assert!(r.get("sda.ai.probe").is_some(), "the dynamic half");
    }

    #[test]
    fn a_default_ai_run_reports_that_behaviour_was_not_tested() {
        // The artifact scanner runs; the probe runner cannot, and its exclusion
        // is what stops a container-only scan reading as a clean bill of health.
        let (chosen, excluded) = ai_registry().select(&sda_core::SelectionPolicy::default());
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].info().id.as_str(), "sda.ai.artifact");
        let probe = excluded.iter().find(|e| e.provider.as_str() == "sda.ai.probe").unwrap();
        assert!(probe.reason.contains("were NOT tested"));
    }

    #[test]
    fn every_risk_in_the_taxonomy_is_reachable_from_a_scan_or_a_probe_or_marked_manual() {
        let t = RiskTaxonomy::load();
        for r in t.all() {
            assert!(
                r.phase.scannable() || r.phase.probeable() || r.phase == Phase::Manual,
                "risk `{}` has no route to detection and no manual marking",
                r.id
            );
        }
    }
}
