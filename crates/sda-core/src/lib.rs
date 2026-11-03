//! Core domain model for the NERVOSYS statodynamic analysis toolkit.
//!
//! "Statodynamic" analysis is the deliberate fusion of *static* evidence (what the
//! source says) with *dynamic* evidence (what the built artifact does). Neither is
//! authoritative alone: static analysis over-reports on paths that never execute,
//! dynamic analysis under-reports on paths never taken. This crate models both as
//! first-class [`Evidence`] attached to a [`Finding`], plus the [`Correlation`] that
//! adjudicates between them.
//!
//! Everything downstream — the native engines, the external-tool adapters, the
//! ontology, the agent protocol, and the GUI — speaks the types defined here.

#![forbid(unsafe_code)]

pub mod evidence;
pub mod finding;
pub mod ids;
pub mod provider;
pub mod report;
pub mod safe_write;
pub mod sarif;
pub mod target;
pub mod taxonomy;
pub mod verification;

pub use evidence::{Evidence, RuntimeEvent, RuntimeEventKind, TraceFrame};
pub use finding::{AnalysisPhase, Confidence, Finding, Location, Severity};
pub use ids::{FindingId, ProviderId, RuleId};
pub use provider::{
    Analyzer, AnalyzerKind, Availability, Capability, DynamicAnalyzer, Exclusion, ProviderInfo,
    ProviderOrigin, Registry, RunOptions, SelectionPolicy, StaticAnalyzer,
};
pub use report::{Correlation, CorrelationVerdict, Report, Summary, VcsProvenance, now_rfc3339};
pub use target::{Language, Target, TargetFile, find_compile_commands};
pub use taxonomy::{Taxonomy, TaxonomyRef};
pub use verification::{
    Architecture, Assumption, AssumptionSupport, Boundary, Modality, NeuralProfile,
    ObligationStatus, ProofObligation, SearchStrategy, Tractability, VerificationLedger,
};

/// Errors surfaced by analysis providers and report handling.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("provider `{provider}` is unavailable: {reason}")]
    ProviderUnavailable { provider: String, reason: String },
    #[error("provider `{provider}` failed: {reason}")]
    ProviderFailed { provider: String, reason: String },
    #[error("unsupported language `{0}` for this provider")]
    UnsupportedLanguage(String),
    #[error("malformed {format} data: {reason}")]
    Malformed { format: String, reason: String },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn io(path: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io { path: path.into(), source }
    }
    pub fn malformed(format: impl Into<String>, reason: impl Into<String>) -> Self {
        Error::Malformed { format: format.into(), reason: reason.into() }
    }
    pub fn other(reason: impl Into<String>) -> Self {
        Error::Other(reason.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The schema version stamped into every emitted [`Report`].
pub const SCHEMA_VERSION: &str = "sda-report/1";
