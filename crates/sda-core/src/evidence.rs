//! What backs a finding up.
//!
//! Evidence is the seam where static and dynamic analysis meet. A static checker
//! attaches a [`Evidence::Source`] snippet; a dynamic run attaches
//! [`Evidence::Runtime`] events and [`Evidence::Trace`] frames; the correlation
//! engine reads both to decide whether a suspected defect is real.

use crate::finding::Location;
use crate::verification::{Modality, ObligationStatus, ProofObligation};
use serde::{Deserialize, Serialize};

/// One frame of an execution or data-flow trace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceFrame {
    pub location: Location,
    /// What happens here, e.g. "buffer allocated with size n" or "n read from packet".
    pub note: String,
    /// Ordinal within the trace, ascending from the source of the problem.
    pub step: u32,
}

/// The class of runtime observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeEventKind {
    /// Process terminated on a signal or unhandled exception.
    Crash,
    /// A sanitizer (ASan/UBSan/TSan/MSan, or our native shim) reported an error.
    SanitizerReport,
    /// Memory reachable at exit / not freed.
    Leak,
    /// Read or write outside an allocation's bounds.
    MemoryError,
    /// Concurrent unsynchronized access.
    DataRace,
    /// Behaviour the standard leaves undefined, detected at runtime.
    UndefinedBehavior,
    /// Exceeded a wall-clock, memory, or stack budget.
    ResourceExhaustion,
    /// The line/branch was executed. Absence of this is itself evidence.
    Coverage,
    /// A value observed at a probe point.
    ValueObservation,
    /// An AI model produced output matching a probe's trigger criteria.
    ModelBehavior,
    /// A syscall or library call of interest was made.
    Syscall,
}

impl RuntimeEventKind {
    /// The class of runtime observation a stated weakness implies.
    ///
    /// An external dynamic tool reports a defect and names its CWE; it does not
    /// speak this enum. Correlation, though, decides relatedness from the
    /// witness's *event kind*, so a Memcheck invalid-write carrying `CWE-787`
    /// and nothing else could not be recognised as a memory error, and could
    /// confirm nothing. This is the translation.
    ///
    /// It is deliberately a `Option`: a CWE this map does not know produces
    /// `None`, not a guess. The caller then attaches a
    /// [`RuntimeEventKind::SanitizerReport`] — the honest label for "a dynamic
    /// checking tool said so" — rather than inventing a specific weakness class
    /// the tool never claimed. Confirmation is the strongest claim this toolkit
    /// makes and it must not rest on a fabricated classification.
    pub fn from_cwe(cwe: u32) -> Option<RuntimeEventKind> {
        use RuntimeEventKind::*;
        Some(match cwe {
            // Out-of-bounds access, buffer handling, array indexing, and the
            // free-list errors Memcheck reports as invalid accesses.
            119 | 120 | 125 | 129 | 415 | 416 | 466 | 469 | 761 | 762 | 787 | 805 => MemoryError,
            // Undefined behaviour: overflow, bad shifts, null deref, uninitialised.
            190 | 191 | 457 | 476 | 682 | 758 | 843 => UndefinedBehavior,
            362 | 366 | 367 | 667 | 833 => DataRace,
            401 | 772 | 775 => Leak,
            400 | 674 | 770 | 789 => ResourceExhaustion,
            248 => Crash,
            // Embedded malicious code, unsafe deserialisation, injection. The
            // forward map in `correlate::related_weaknesses` has claimed these
            // for `ModelBehavior` since it was written and this one never
            // learned them, so an external scanner's CWE-502 finding — which is
            // exactly what modelscan reports about a pickled model — became a
            // `SanitizerReport` event by fallback. `SanitizerReport` does not
            // relate back to 502, so a static CWE-502 finding and a runtime
            // witness of the same CWE did not correlate: the precise failure
            // `every_weakness_class_confirms_its_own_cwe` was written to catch,
            // in the one class it could not see, because it iterates the CWEs
            // this function already knows.
            74 | 502 | 506 => ModelBehavior,
            _ => return None,
        })
    }
}

/// A single thing observed while the target ran.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub kind: RuntimeEventKind,
    /// Where in the source, when the runtime could attribute it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    pub detail: String,
    /// Identifier of the run that produced this, for reproduction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Path to the input that triggered it, if reproducible from a corpus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    /// How many times this was observed across the run.
    #[serde(default = "one_u64")]
    pub count: u64,
}

fn one_u64() -> u64 {
    1
}

impl RuntimeEvent {
    pub fn new(kind: RuntimeEventKind, detail: impl Into<String>) -> Self {
        RuntimeEvent { kind, location: None, detail: detail.into(), run_id: None, input: None, count: 1 }
    }
    pub fn at(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }
    pub fn from_run(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }
    pub fn with_input(mut self, input: impl Into<String>) -> Self {
        self.input = Some(input.into());
        self
    }
    /// True for events that prove a defect rather than merely suggesting one.
    pub fn is_defect(&self) -> bool {
        !matches!(self.kind, RuntimeEventKind::Coverage | RuntimeEventKind::ValueObservation | RuntimeEventKind::Syscall)
    }
}

/// Anything that substantiates a finding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Evidence {
    /// Verbatim source lines around the finding.
    Source {
        location: Location,
        /// Line number of `text`'s first line.
        first_line: u32,
        text: String,
    },
    /// An ordered path through the program.
    Trace { frames: Vec<TraceFrame> },
    /// Something observed while the target executed.
    Runtime { event: RuntimeEvent },
    /// A measured quantity, e.g. cyclomatic complexity or branch coverage.
    Metric { name: String, value: f64, unit: Option<String> },
    /// A property of a serialized model file.
    ModelArtifact {
        /// Path to the model file.
        path: String,
        format: String,
        /// Byte offset the observation applies to, when meaningful.
        offset: Option<u64>,
        detail: String,
    },
    /// A prompt/response pair from an AI behavioral probe.
    ModelProbe {
        probe_id: String,
        prompt: String,
        response: String,
        /// Why this response is considered a hit.
        verdict: String,
    },
    /// A ruling by a theorem prover on one proof obligation.
    ///
    /// The `assumptions` field is the load-bearing one. A proof detached from
    /// what it was granted is not checkable by a reader, and at a neurosymbolic
    /// boundary what it was granted is precisely the part nobody proved — so
    /// evidence that carried only the verdict would be evidence for the wrong
    /// claim.
    Proof {
        obligation: ProofObligation,
        /// Ids of the assumptions the ruling depends on. Resolve them against
        /// the run's [`crate::verification::VerificationLedger`].
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        assumptions: Vec<String>,
    },
    /// Free-form note from a provider that does not fit the shapes above.
    Note { text: String },
}

impl Evidence {
    pub fn source(location: Location, first_line: u32, text: impl Into<String>) -> Self {
        Evidence::Source { location, first_line, text: text.into() }
    }
    pub fn note(text: impl Into<String>) -> Self {
        Evidence::Note { text: text.into() }
    }
    pub fn metric(name: impl Into<String>, value: f64) -> Self {
        Evidence::Metric { name: name.into(), value, unit: None }
    }

    /// True if this evidence came from observing execution.
    pub fn is_runtime(&self) -> bool {
        matches!(self, Evidence::Runtime { .. } | Evidence::ModelProbe { .. })
    }

    /// A prover's ruling on one obligation.
    pub fn proof(obligation: ProofObligation) -> Self {
        Evidence::Proof { obligation, assumptions: Vec::new() }
    }

    /// True if this evidence, on its own, demonstrates a real defect.
    ///
    /// Named for what it is: a *witness*, which is an existential claim. It was
    /// once called `is_proof`, and that name became actively misleading once
    /// [`Evidence::Proof`] arrived carrying universal claims — the two mean
    /// opposite things about how far a single observation generalises.
    pub fn is_defect_witness(&self) -> bool {
        match self {
            Evidence::Runtime { event } => event.is_defect(),
            Evidence::Proof { obligation, .. } => {
                matches!(obligation.status, ObligationStatus::Failed { .. })
            }
            _ => false,
        }
    }

    /// How this evidence was established, when the question applies.
    ///
    /// `Source` and `Note` have no modality: quoting a line establishes nothing
    /// by itself, and saying so is better than picking a default.
    pub fn modality(&self) -> Option<Modality> {
        match self {
            Evidence::Proof { .. } => Some(Modality::Deductive),
            Evidence::Runtime { .. }
            | Evidence::ModelProbe { .. }
            | Evidence::Metric { .. }
            | Evidence::Trace { .. } => Some(Modality::Inductive),
            Evidence::ModelArtifact { .. } | Evidence::Source { .. } | Evidence::Note { .. } => {
                None
            }
        }
    }

    /// True only for a *discharged* obligation: a claim that holds on every
    /// execution, subject to the assumptions recorded alongside it.
    pub fn is_discharged_proof(&self) -> bool {
        matches!(self, Evidence::Proof { obligation, .. } if obligation.status.is_discharged())
    }

    /// Short label for list views.
    pub fn label(&self) -> String {
        match self {
            Evidence::Source { location, .. } => format!("source @ {}", location.display()),
            Evidence::Trace { frames } => format!("trace ({} frames)", frames.len()),
            Evidence::Runtime { event } => format!("runtime: {:?}", event.kind),
            Evidence::Metric { name, value, .. } => format!("{name} = {value}"),
            Evidence::ModelArtifact { format, .. } => format!("model artifact ({format})"),
            Evidence::ModelProbe { probe_id, .. } => format!("probe: {probe_id}"),
            Evidence::Proof { obligation, .. } => {
                format!("proof: {} {}", obligation.id, obligation.status.as_str())
            }
            Evidence::Note { .. } => "note".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_events_are_not_defects() {
        assert!(!RuntimeEvent::new(RuntimeEventKind::Coverage, "line hit").is_defect());
        assert!(RuntimeEvent::new(RuntimeEventKind::MemoryError, "heap overflow").is_defect());
    }

    #[test]
    fn only_defect_runtime_evidence_counts_as_proof() {
        let crash = Evidence::Runtime { event: RuntimeEvent::new(RuntimeEventKind::Crash, "SIGSEGV") };
        let cov = Evidence::Runtime { event: RuntimeEvent::new(RuntimeEventKind::Coverage, "hit") };
        assert!(crash.is_defect_witness());
        assert!(!cov.is_defect_witness());
        assert!(!Evidence::note("hi").is_defect_witness());
        // Coverage is still runtime-sourced even though it proves nothing by itself.
        assert!(cov.is_runtime());
    }

    #[test]
    fn evidence_round_trips_through_json() {
        let e = Evidence::source(Location::new("a.c", 3, 1), 2, "int x;");
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"kind\":\"source\""));
        let back: Evidence = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Evidence::Source { first_line: 2, .. }));
    }
}
