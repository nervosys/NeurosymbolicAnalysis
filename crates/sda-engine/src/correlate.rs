//! The correlation engine.
//!
//! Static analysis says *this could happen*. Dynamic analysis says *this did
//! happen*, and — just as valuable — *this line never ran at all*. Correlating
//! them turns two piles of findings into a ranked set of claims with stated
//! evidence:
//!
//! | static says | runtime says | verdict | what it means |
//! |---|---|---|---|
//! | suspect | defect at the same place | `Confirmed` | fix this first |
//! | suspect | executed often, no defect | `Refuted` | probably a false positive |
//! | suspect | never executed | `Unreached` | the static claim stands, *and* you have a coverage hole |
//! | silent | defect | `Unpredicted` | a gap in the static rule set |
//!
//! The `Unreached` row is the one most tools get wrong. Treating "no runtime
//! defect" as evidence of correctness, without checking whether the code ever
//! ran, silently converts a coverage gap into a clean bill of health.

use crate::dynamic::Observation;
use sda_core::{
    AnalysisPhase, Confidence, Correlation, CorrelationVerdict, Evidence, Finding, Location,
    RuntimeEventKind, Severity,
};

/// Tuning for how much runtime evidence it takes to overturn a static claim.
#[derive(Clone, Debug)]
pub struct CorrelationPolicy {
    /// Executions of a line, with no defect observed there, before a static
    /// finding is considered refuted. One pass through proves very little.
    pub refutation_threshold: u64,
    /// Lines either side of a static finding within which a runtime defect is
    /// taken to be the same defect. Compilers and sanitizers disagree about
    /// exactly which line an operation belongs to.
    pub line_tolerance: u32,
    /// Whether an unpredicted runtime defect should be reported as its own
    /// finding. Off only when triaging a known-noisy corpus.
    pub report_unpredicted: bool,
}

impl Default for CorrelationPolicy {
    fn default() -> Self {
        CorrelationPolicy {
            // Deliberately conservative. Demoting a real defect because one
            // happy-path run did not trigger it is the worst failure this
            // engine can have.
            refutation_threshold: 25,
            line_tolerance: 2,
            report_unpredicted: true,
        }
    }
}

/// The outcome of fusing static findings with runtime observation.
#[derive(Clone, Debug, Default)]
pub struct CorrelationResult {
    /// Static findings with severity and confidence adjusted by the evidence.
    pub findings: Vec<Finding>,
    pub correlations: Vec<Correlation>,
}

impl CorrelationResult {
    pub fn count(&self, v: CorrelationVerdict) -> usize {
        self.correlations.iter().filter(|c| c.verdict == v).count()
    }
}

/// Fuse static findings and runtime observation.
///
/// `obs` is `Option` on purpose, and the distinction is the one this whole
/// codebase is about. `Some(Observation::default())` means *execution was
/// measured and nothing was recorded* — a coverage hole, and a finding on such a
/// line is `Unreached`. `None` means *execution was never measured*: an external
/// dynamic tool such as Valgrind ran the program and reported its faults, but
/// reports no execution counts at all. Those two look identical in the data and
/// mean opposite things, so calling the second one a coverage hole would invent
/// a claim about the code out of a fact about the instrument.
///
/// Confirmation works either way — a witness is a witness. Refutation and
/// `Unreached` require measurement, and are simply unavailable under `None`.
pub fn correlate(
    static_findings: &[Finding],
    dynamic_findings: &[Finding],
    obs: Option<&Observation>,
    policy: &CorrelationPolicy,
) -> CorrelationResult {
    let mut result = CorrelationResult::default();
    let mut matched_dynamic: Vec<usize> = Vec::new();

    for sf in static_findings {
        // A suppressed finding has an approved deviation; correlating it would
        // only re-raise something the process already settled.
        if sf.is_suppressed() {
            result.findings.push(sf.clone());
            continue;
        }

        // Normalised because this string is quoted verbatim in the rationales
        // below, while the confirmed rationale reports its location through
        // `Location::display`, which is always `/`. Leaving this native made one
        // report describe the same file as `src\leaky.c` in one sentence and
        // `src/leaky.c` in the next. Coverage and proximity matching normalise
        // both sides themselves, so this only affects what is written down.
        let path = sf.location.file.to_string_lossy().replace('\\', "/");
        let line = sf.location.line;

        // 1. Did a runtime defect land on this code?
        let witness = dynamic_findings.iter().enumerate().find(|(_, df)| {
            near(&df.location, &sf.location, &path, policy.line_tolerance)
        });

        // Proximity is necessary but not sufficient: the defect must also be of
        // a class this finding could produce.
        let witness = witness.filter(|(_, df)| same_defect_class(sf, df) == Some(true));

        if let Some((idx, df)) = witness {
            matched_dynamic.push(idx);
            // Say which rule matched. "within N lines" was printed for every
            // confirmation and is simply untrue of one matched by span. The
            // rationale is the evidence a reader is given for the strongest claim
            // this engine makes, so it has to describe what actually happened.
            let how = match sf.location.end_line {
                Some(end) if df.location.line >= sf.location.line && df.location.line <= end => {
                    format!(
                        "inside the region this finding is about (lines {}-{})",
                        sf.location.line, end
                    )
                }
                _ => format!("within {} line(s) of this static finding", policy.line_tolerance),
            };
            let mut c = Correlation::new(
                CorrelationVerdict::Confirmed,
                format!(
                    "the runtime defect `{}` occurred at {}, {how}, and is of a weakness class \
                     this guideline is about — the predicted fault actually happens",
                    df.title,
                    df.location.display(),
                ),
            )
            .about(sf.id.clone())
            .witnessed_by(df.id.clone());
            for e in df.evidence.iter().filter(|e| e.is_runtime()) {
                c = c.evidence(e.clone());
            }
            // The proof travels with the finding, not only with the correlation
            // record: whoever opens this finding should see the runtime event
            // that confirms it without having to cross-reference anything.
            let mut confirmed = adjust(sf, CorrelationVerdict::Confirmed, &c.rationale);
            for e in df.evidence.iter().filter(|e| e.is_runtime()) {
                confirmed.evidence.push(e.clone());
            }
            result.findings.push(confirmed);
            result.correlations.push(c);
            continue;
        }

        // 2. Did the code run at all? Only askable when something measured it.
        let Some(obs) = obs else {
            let rationale = format!(
                "no coverage was measured in this run — the runtime evidence came from a tool that \
                 reports defects rather than execution counts — so nothing is known about whether \
                 {path}:{line} ran. The static finding is neither refuted nor shown unreached; it \
                 stands exactly as it did"
            );
            let c = Correlation::new(CorrelationVerdict::Inconclusive, rationale.clone())
                .about(sf.id.clone());
            result.findings.push(adjust(sf, CorrelationVerdict::Inconclusive, &rationale));
            result.correlations.push(c);
            continue;
        };
        let hits = obs.covered(&path, line);
        let file_ran = obs.file_executed(&path);

        // A file that never ran and a line that never ran are the same verdict:
        // the claim is untested. They were separate arms with identical bodies,
        // which reads as though the distinction mattered here — it matters to the
        // *rationale*, which is chosen below by verdict, not by which of these
        // was true.
        let verdict = if !file_ran || hits == 0 {
            CorrelationVerdict::Unreached
        } else if hits >= policy.refutation_threshold {
            CorrelationVerdict::Refuted
        } else {
            CorrelationVerdict::Inconclusive
        };

        let rationale = match verdict {
            // These say "no coverage record", not "did not execute", because
            // the engine cannot tell those apart and must not claim to. With
            // line-granular instrumentation — the SDA probe shim, where a line
            // is recorded only where someone wrote `SDA_COV()` — an
            // uninstrumented line and an unexecuted one are indistinguishable.
            // Asserting the stronger claim produced a demonstrable falsehood:
            // a run reported "no line of sda_probe.h was executed" about the
            // very `fopen` that had just written the probe stream being read.
            CorrelationVerdict::Unreached if !file_ran => format!(
                "no line of {path} produced a coverage record, so this static finding is neither \
                 confirmed nor refuted. Either nothing in this file ran, or it carries no \
                 instrumentation — both are coverage gaps, and both are worth acting on"
            ),
            CorrelationVerdict::Unreached => format!(
                "{path}:{line} produced no coverage record, though other lines in the file did. \
                 Either it did not execute or it is not instrumented; the static finding stands \
                 unchallenged either way, and this line is untested"
            ),
            CorrelationVerdict::Refuted => format!(
                "{path}:{line} executed {hits} times with no defect observed there, which meets the \
                 refutation threshold of {}. Treat as a likely false positive, not as proof of \
                 correctness — the executions may all have taken the same path",
                policy.refutation_threshold
            ),
            _ => format!(
                "{path}:{line} executed {hits} times, below the refutation threshold of {}. Not \
                 enough evidence either way",
                policy.refutation_threshold
            ),
        };

        let mut c = Correlation::new(verdict, rationale.clone()).about(sf.id.clone());
        // Only where something actually counted. `covered` returns zero both for
        // a line a coverage tool measured at zero — real evidence — and for a
        // line nothing looked at, and an `executions = 0` metric asserts the
        // first. The rationale above has always drawn that distinction; the
        // structured evidence did not, and the structured half is the one a
        // machine reads. A shim-instrumented program is mostly the second case,
        // which is how the first real Cortex-M run produced fourteen findings
        // carrying a count nobody had taken.
        c = if obs.measured(&path, line) {
            c.evidence(Evidence::metric("executions", hits as f64))
        } else {
            c.evidence(Evidence::note(format!(
                "no coverage record exists for {path}:{line}, so its execution count is unknown rather than zero"
            )))
        };
        result.findings.push(adjust(sf, verdict, &rationale));
        result.correlations.push(c);
    }

    // 3. Runtime defects that no static rule predicted. These are the gaps in
    // the rule set, and they are the most informative output of a whole run.
    if policy.report_unpredicted {
        for (i, df) in dynamic_findings.iter().enumerate() {
            if matched_dynamic.contains(&i) {
                continue;
            }
            let mut f = df.clone();
            f.confidence = Confidence::Certain;
            let rationale = format!(
                "`{}` was observed at {} but no static rule predicted it. That is a gap in the rule \
                 set, not in the code: either no catalogued guideline covers this defect class, or \
                 the guideline that does is not checked by a default run",
                df.title,
                df.location.display()
            );
            let c = Correlation::new(CorrelationVerdict::Unpredicted, rationale)
                .witnessed_by(df.id.clone());
            result.findings.push(f);
            result.correlations.push(c);
        }
    }

    result
}

/// CWEs a given runtime observation could plausibly be an instance of.
///
/// Used to decide whether a static finding and a runtime defect are about the
/// *same kind of thing*. Proximity alone is not enough: a bounds fault two lines
/// away does not confirm an advisory about using width-explicit typedefs, and
/// saying it does devalues the strongest claim this tool makes.
fn related_weaknesses(kind: RuntimeEventKind) -> &'static [u32] {
    use RuntimeEventKind::*;
    match kind {
        // Out-of-bounds read/write, buffer handling, array indexing, and the
        // free-list errors a memory checker reports as invalid accesses.
        // 415/416/761/762 were missing while `RuntimeEventKind::from_cwe` mapped
        // them *to* `MemoryError`, so a use-after-free witnessed by Memcheck
        // could not confirm a use-after-free the static side had predicted —
        // the same CWE on both sides, and no confirmation. See
        // `every_weakness_class_confirms_its_own_cwe`.
        MemoryError => &[119, 120, 125, 129, 415, 416, 466, 469, 761, 762, 787, 805],
        // Undefined behaviour: overflow, bad shifts, null deref, uninitialised.
        UndefinedBehavior => &[758, 190, 191, 682, 476, 457, 843],
        DataRace => &[362, 366, 367, 667, 833],
        Leak => &[401, 772, 775],
        ResourceExhaustion => &[400, 674, 789, 770],
        // A crash can be almost anything, so it confirms the classes that
        // typically produce one rather than everything.
        Crash => &[248, 476, 787, 125, 674, 758],
        SanitizerReport => &[787, 125, 758, 362, 401],
        ModelBehavior => &[506, 502, 74],
        Coverage | ValueObservation | Syscall => &[],
    }
}

/// Whether a runtime defect could plausibly be the static finding coming true.
///
/// Returns `None` when relatedness cannot be established at all — the finding
/// carries no weakness classification — which is different from establishing
/// that they are unrelated, and is reported differently.
fn same_defect_class(finding: &Finding, witness: &Finding) -> Option<bool> {
    let kinds: Vec<RuntimeEventKind> = witness
        .evidence
        .iter()
        .filter_map(|e| match e {
            Evidence::Runtime { event } => Some(event.kind),
            _ => None,
        })
        .collect();
    if kinds.is_empty() {
        return None;
    }

    let static_cwes: Vec<u32> = finding
        .taxonomy
        .iter()
        .filter(|t| t.scheme == sda_core::Taxonomy::Cwe)
        .filter_map(|t| t.id.trim_start_matches("CWE-").parse().ok())
        .collect();
    if static_cwes.is_empty() {
        return None;
    }

    Some(
        kinds
            .iter()
            .any(|k| related_weaknesses(*k).iter().any(|c| static_cwes.contains(c))),
    )
}

/// Whether a runtime location refers to the same code as a static finding.
///
/// Two separate questions, kept separate on purpose.
///
/// `tolerance` is a *measurement* allowance: compilers and sanitizers disagree
/// about which line an operation belongs to, so a line or two either side of a
/// point is noise, not scope. Widening it to cover a construct would loosen
/// matching for every rule and every tool at once.
///
/// A stated `end_line` is a *claim*: the static finding said it is about a
/// region, so a runtime defect inside that region is inside the thing the
/// finding is about. An `unsafe` block forced the distinction — the finding sits
/// on the keyword while the compiler has stopped checking for the whole body,
/// and Miri faults wherever the defect actually is, which was three lines past
/// the noise allowance. Only findings that state an extent are affected, and a
/// finding states one only where something measured it.
fn near(loc: &Location, static_loc: &Location, path: &str, tolerance: u32) -> bool {
    let a = loc.file.to_string_lossy().replace('\\', "/");
    let b = path.replace('\\', "/");
    if !(a.ends_with(&b) || b.ends_with(&a)) {
        return false;
    }
    if let Some(end) = static_loc.end_line
        && loc.line >= static_loc.line && loc.line <= end {
            return true;
        }
    loc.line.abs_diff(static_loc.line) <= tolerance
}

/// Apply a verdict's effect to a finding, recording why in its evidence.
fn adjust(f: &Finding, verdict: CorrelationVerdict, rationale: &str) -> Finding {
    let mut out = f.clone();
    out.severity = verdict.adjust_severity(f.severity);
    out.confidence = verdict.adjust_confidence(f.confidence);
    if verdict != CorrelationVerdict::Inconclusive {
        out.phase = AnalysisPhase::Statodynamic;
    }
    out.evidence.push(Evidence::note(format!("[{}] {rationale}", verdict.as_str())));
    out
}

/// Lines that a static provider flagged but no run ever reached, grouped by
/// file. Reported separately because a coverage hole is a test-suite defect,
/// not a code defect, and belongs on a different work queue.
///
/// **Correlations are matched to findings by id, not by position.** They are
/// pushed in lockstep everywhere but one branch: a suppressed finding is passed
/// through without a correlation, because an approved deviation is not
/// re-litigated. Zipping the two vectors was therefore correct only until the
/// first suppression, after which every gap was attributed to the wrong file and
/// line — and, on a project with an approved deviation early in the list, to a
/// line whose departure had already been accepted.
///
/// Takes the two slices rather than a `CorrelationResult` so that a finished
/// `Report` can be asked the same question. It could not be, which is part of
/// why nothing ever asked it.
pub fn coverage_gaps(
    findings: &[Finding],
    correlations: &[Correlation],
) -> Vec<(String, Vec<u32>)> {
    let mut by_file: std::collections::BTreeMap<String, Vec<u32>> = Default::default();
    for c in correlations.iter().filter(|c| c.verdict == CorrelationVerdict::Unreached) {
        let Some(id) = c.static_finding.as_ref() else { continue };
        let Some(f) = findings.iter().find(|f| &f.id == id) else { continue };
        by_file
            .entry(f.location.file.to_string_lossy().to_string())
            .or_default()
            .push(f.location.line);
    }
    by_file
        .into_iter()
        .map(|(f, mut lines)| {
            lines.sort_unstable();
            lines.dedup();
            (f, lines)
        })
        .collect()
}

/// A one-paragraph summary of what the correlation established, for the top of
/// a report. Written to be read by someone deciding what to do next.
pub fn summarize(result: &CorrelationResult) -> String {
    let confirmed = result.count(CorrelationVerdict::Confirmed);
    let refuted = result.count(CorrelationVerdict::Refuted);
    let unreached = result.count(CorrelationVerdict::Unreached);
    let unpredicted = result.count(CorrelationVerdict::Unpredicted);
    let inconclusive = result.count(CorrelationVerdict::Inconclusive);

    let mut s = format!(
        "{confirmed} static finding(s) were confirmed by runtime evidence and should be fixed \
         first. {refuted} were refuted by repeated execution without fault. {unreached} sit on \
         code no run reached — those claims are untested, not clean."
    );
    if unpredicted > 0 {
        s.push_str(&format!(
            " {unpredicted} runtime defect(s) had no static prediction at all, which points at a \
             gap in the rule set rather than in the code."
        ));
    }
    if inconclusive > 0 {
        s.push_str(&format!(" {inconclusive} had too little execution to judge."));
    }
    s
}

/// Build a synthetic finding for a file with no coverage at all, so that an
/// unexercised module cannot pass quietly.
pub fn unexercised_file_finding(path: &str) -> Finding {
    Finding::new(
        "sda.correlate",
        "SDA-COV-UNEXERCISED",
        "no run executed any line of this file",
        Severity::Medium,
        Location::file_only(path),
    )
    .message(format!(
        "Every static finding in {path} is unverifiable and every runtime guarantee about it is \
         vacuous, because no run reached it. Add a test or a fuzz entry point before reading its \
         clean dynamic result as good news."
    ))
    .confidence(Confidence::Certain)
    .phase(AnalysisPhase::Statodynamic)
    .evidence(Evidence::Runtime {
        event: sda_core::RuntimeEvent::new(
            RuntimeEventKind::Coverage,
            "file has zero executed lines",
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::parse_probe_stream;
    use sda_core::Location;

    /// Mirrors what the analyzer actually emits for MISRA C 18.1, including the
    /// CWE the catalogue attaches — correlation now uses that to decide whether
    /// a runtime defect is the same *kind* of thing.
    fn static_finding(file: &str, line: u32) -> Finding {
        Finding::new(
            "sda.static.c",
            "MISRA-C-2023-18.1",
            "pointer arithmetic may leave the array",
            Severity::Medium,
            Location::new(file, line, 3),
        )
        .confidence(Confidence::Medium)
        .taxonomy(sda_core::TaxonomyRef::cwe(787))
    }

    fn dynamic_finding(file: &str, line: u32) -> Finding {
        Finding::new(
            "sda.dynamic",
            "SDA-DYN-MEMORY",
            "memory access outside an allocation, observed at runtime",
            Severity::Critical,
            Location::new(file, line, 1),
        )
        .phase(AnalysisPhase::Dynamic)
        .confidence(Confidence::Certain)
        .evidence(Evidence::Runtime {
            event: sda_core::RuntimeEvent::new(RuntimeEventKind::MemoryError, "oob write"),
        })
    }

    fn covered(file: &str, line: u32, n: u64) -> Observation {
        parse_probe_stream(
            &format!("{{\"t\":\"cov\",\"f\":\"{file}\",\"l\":{line},\"n\":{n}}}\n"),
            "r1",
        )
    }

    /// One report must describe one file one way. The rationale strings quoted
    /// the static finding's path verbatim while the confirmed rationale reported
    /// its location through `Location::display`, so a Windows run produced
    /// `src\leaky.c` in one sentence and `src/leaky.c` in the next.
    #[test]
    fn rationales_name_a_file_the_same_way_everywhere() {
        let native = Location::new(
            std::path::Path::new("src").join("drivers").join("buf.c"),
            88,
            3,
        );
        let mut sf = static_finding("ignored", 88);
        sf.location = native;

        let r = correlate(&[sf], &[], Some(&Observation::default()), &CorrelationPolicy::default());
        let rationale = &r.correlations[0].rationale;
        assert!(
            rationale.contains("src/drivers/buf.c"),
            "rationale must use URI separators: {rationale}"
        );
        assert!(!rationale.contains('\\'), "no native separators: {rationale}");
    }

    /// Correlation is the toolkit's central claim, and it works through the CWE
    /// a finding carries. The cppcheck adapter used to discard the `cwe`
    /// attribute from the XML it parsed, so every external finding arrived
    /// without one — and a finding without a CWE can never be confirmed, no
    /// matter how good the runtime evidence is. This is that path, end to end.
    #[test]
    fn an_external_finding_carrying_a_cwe_can_be_confirmed_too() {
        let cppcheck = Finding::new(
            "ext.cppcheck",
            "nullPointer",
            "Null pointer dereference: p",
            Severity::High,
            Location::new("src/main.c", 5, 12),
        )
        .confidence(Confidence::Medium)
        .taxonomy(sda_core::TaxonomyRef::cwe(476));

        let crash = Finding::new(
            "sda.dynamic",
            "SDA-DYN-CRASH",
            "process died dereferencing a null pointer",
            Severity::Critical,
            Location::new("src/main.c", 5, 1),
        )
        .phase(AnalysisPhase::Dynamic)
        .confidence(Confidence::Certain)
        .evidence(Evidence::Runtime {
            event: sda_core::RuntimeEvent::new(RuntimeEventKind::Crash, "SIGSEGV at 0x0"),
        });

        let r = correlate(
            &[cppcheck],
            &[crash],
            Some(&covered("src/main.c", 5, 1)),
            &CorrelationPolicy::default(),
        );
        assert_eq!(
            r.count(CorrelationVerdict::Confirmed),
            1,
            "CWE-476 is a null-dereference weakness and the witness is a crash"
        );
    }

    /// The two weakness tables must agree, or a tool's own stated CWE cannot
    /// confirm a static finding carrying that identical CWE.
    ///
    /// `RuntimeEventKind::from_cwe` turns the CWE an external dynamic tool
    /// states into an event kind; `related_weaknesses` turns an event kind back
    /// into the CWEs it could be an instance of. They were written years apart
    /// and disagreed: `from_cwe(416)` said `MemoryError`, and `MemoryError`'s
    /// list had no 416, so Memcheck witnessing a use-after-free could not
    /// confirm a predicted use-after-free. Exhaustive rather than a written-down
    /// list, so the two cannot drift apart again.
    #[test]
    fn every_weakness_class_confirms_its_own_cwe() {
        for cwe in 1u32..2000 {
            let Some(kind) = RuntimeEventKind::from_cwe(cwe) else { continue };
            assert!(
                related_weaknesses(kind).contains(&cwe),
                "CWE-{cwe} maps to {kind:?}, but {kind:?} does not relate back to CWE-{cwe}: a \
                 witness and a static finding carrying the same CWE would not correlate"
            );
        }
    }

    /// And every CWE a class claims as a confirmer is one the reverse map knows.
    ///
    /// `every_weakness_class_confirms_its_own_cwe` above walks CWE 1..2000 and
    /// skips any that `from_cwe` returns `None` for, so it can only check classes
    /// the reverse map already knows about. A CWE claimed by
    /// `related_weaknesses` and unknown to `from_cwe` is invisible to it — and
    /// that was not hypothetical: `ModelBehavior` claimed 506, 502 and 74, and
    /// `from_cwe` mapped none of them.
    ///
    /// The cost was the one the test above names in its own failure message. An
    /// external scanner's CWE-502 finding fell back to `SanitizerReport`, whose
    /// CWE list does not contain 502, so a static CWE-502 finding was never
    /// confirmed by a runtime witness carrying the same CWE.
    ///
    /// The two tests are the two directions, and neither is the other.
    #[test]
    fn every_cwe_a_class_claims_is_one_the_reverse_map_knows() {
        use RuntimeEventKind::*;

        // Exhaustive on purpose: a new kind has to be listed here before this
        // compiles, which is the only way a new mapping gets asked the question.
        let kinds = [
            MemoryError,
            Crash,
            DataRace,
            UndefinedBehavior,
            Leak,
            ResourceExhaustion,
            SanitizerReport,
            ModelBehavior,
            Coverage,
            ValueObservation,
            Syscall,
        ];

        for kind in kinds {
            for cwe in related_weaknesses(kind) {
                assert!(
                    RuntimeEventKind::from_cwe(*cwe).is_some(),
                    "{kind:?} claims CWE-{cwe} as a confirmer and `from_cwe` does not map it. \
                     An external tool reporting CWE-{cwe} falls back to `SanitizerReport`, and \
                     a static finding carrying CWE-{cwe} is then never confirmed by a witness \
                     of the same weakness"
                );
            }
        }
    }

    /// An external dynamic tool reports defects and no execution counts. Nothing
    /// measured coverage, so nothing may be said about it — but the witness is
    /// still a witness, and confirmation is exactly what it is for.
    #[test]
    fn an_unmeasured_run_confirms_but_never_refutes_or_calls_a_line_unreached() {
        let r = correlate(
            &[static_finding("src/buf.c", 88), static_finding("src/quiet.c", 4)],
            &[dynamic_finding("src/buf.c", 88)],
            None,
            &CorrelationPolicy::default(),
        );
        assert_eq!(r.count(CorrelationVerdict::Confirmed), 1, "a witness is a witness");
        assert_eq!(r.count(CorrelationVerdict::Refuted), 0, "nothing counted executions");
        assert_eq!(
            r.count(CorrelationVerdict::Unreached),
            0,
            "`unreached` is a claim about the code; here it would be a claim about the instrument"
        );
        assert_eq!(r.count(CorrelationVerdict::Inconclusive), 1);

        let uncorroborated = r
            .correlations
            .iter()
            .find(|c| c.verdict == CorrelationVerdict::Inconclusive)
            .unwrap();
        assert!(
            uncorroborated.rationale.contains("no coverage was measured"),
            "it must name what was missing: {}",
            uncorroborated.rationale
        );
        assert!(
            !uncorroborated.rationale.contains("coverage record"),
            "and must not borrow the wording of a measured run with a coverage hole: {}",
            uncorroborated.rationale
        );
        // The finding itself is untouched: an unmeasurable line is not a weaker
        // claim, and `coverage_gaps` must not invent a hole nothing looked for.
        assert_eq!(r.findings[1].severity, Severity::Medium);
        assert!(coverage_gaps(&r.findings, &r.correlations).is_empty());
    }

    /// The same empty input, meaning the opposite thing. `Some(default)` is a
    /// run that measured execution and recorded none — a coverage hole worth
    /// acting on. `None` is a run that never measured. Collapsing them would
    /// manufacture a coverage claim out of a fact about the instrument.
    #[test]
    fn measured_and_empty_is_not_the_same_as_never_measured() {
        let measured = correlate(
            &[static_finding("src/buf.c", 88)],
            &[],
            Some(&Observation::default()),
            &CorrelationPolicy::default(),
        );
        let unmeasured =
            correlate(&[static_finding("src/buf.c", 88)], &[], None, &CorrelationPolicy::default());

        assert_eq!(measured.count(CorrelationVerdict::Unreached), 1);
        assert_eq!(unmeasured.count(CorrelationVerdict::Unreached), 0);
        assert_eq!(coverage_gaps(&measured.findings, &measured.correlations).len(), 1);
        assert!(coverage_gaps(&unmeasured.findings, &unmeasured.correlations).is_empty());
    }

    #[test]
    fn a_runtime_defect_confirms_and_escalates_the_static_finding() {
        let r = correlate(
            &[static_finding("src/buf.c", 88)],
            &[dynamic_finding("src/buf.c", 88)],
            Some(&covered("src/buf.c", 88, 1)),
            &CorrelationPolicy::default(),
        );
        assert_eq!(r.count(CorrelationVerdict::Confirmed), 1);
        assert_eq!(r.findings[0].severity, Severity::High, "Medium escalates to High");
        assert_eq!(r.findings[0].confidence, Confidence::Certain);
        assert_eq!(r.findings[0].phase, AnalysisPhase::Statodynamic);
        assert!(
            r.findings[0].has_runtime_evidence(),
            "the confirming runtime event must be attached to the finding itself"
        );
    }

    #[test]
    fn a_nearby_defect_of_an_unrelated_class_does_not_confirm() {
        // A bounds fault does not confirm an advisory about typedef width, even
        // on the adjacent line. Proximity is not relatedness, and "confirmed" is
        // the strongest claim this tool makes.
        let advisory = Finding::new(
            "sda.static.c",
            "MISRA-C-2023-D4.6",
            "basic numerical type used",
            Severity::Low,
            Location::new("src/buf.c", 88, 1),
        );
        let r = correlate(
            &[advisory],
            &[dynamic_finding("src/buf.c", 88)],
            Some(&covered("src/buf.c", 88, 1)),
            &CorrelationPolicy::default(),
        );
        assert_eq!(r.count(CorrelationVerdict::Confirmed), 0);
        assert_eq!(r.findings[0].severity, Severity::Low, "severity must not be escalated");
    }

    #[test]
    fn relatedness_is_decided_by_weakness_class() {
        use sda_core::{RuntimeEvent, RuntimeEventKind};
        let with_cwe = |n: u32| {
            Finding::new("p", "R", "t", Severity::Medium, Location::new("a.c", 1, 1))
                .taxonomy(sda_core::TaxonomyRef::cwe(n))
        };
        let witness = |kind: RuntimeEventKind| {
            Finding::new("d", "D", "t", Severity::High, Location::new("a.c", 1, 1))
                .evidence(Evidence::Runtime { event: RuntimeEvent::new(kind, "x") })
        };

        // An out-of-bounds write confirms a bounds guideline...
        assert_eq!(
            same_defect_class(&with_cwe(787), &witness(RuntimeEventKind::MemoryError)),
            Some(true)
        );
        // ...but not a concurrency one.
        assert_eq!(
            same_defect_class(&with_cwe(362), &witness(RuntimeEventKind::MemoryError)),
            Some(false)
        );
        // A finding with no weakness classification cannot be related at all.
        let bare = Finding::new("p", "R", "t", Severity::Low, Location::new("a.c", 1, 1));
        assert_eq!(same_defect_class(&bare, &witness(RuntimeEventKind::MemoryError)), None);
    }

    #[test]
    fn confirmation_tolerates_a_small_line_discrepancy() {
        let r = correlate(
            &[static_finding("src/buf.c", 88)],
            &[dynamic_finding("src/buf.c", 89)],
            Some(&covered("src/buf.c", 88, 1)),
            &CorrelationPolicy::default(),
        );
        assert_eq!(r.count(CorrelationVerdict::Confirmed), 1);
    }

    #[test]
    fn a_defect_in_a_different_file_does_not_confirm() {
        let r = correlate(
            &[static_finding("src/buf.c", 88)],
            &[dynamic_finding("src/other.c", 88)],
            Some(&covered("src/buf.c", 88, 100)),
            &CorrelationPolicy::default(),
        );
        assert_eq!(r.count(CorrelationVerdict::Confirmed), 0);
        assert_eq!(r.count(CorrelationVerdict::Refuted), 1);
        assert_eq!(r.count(CorrelationVerdict::Unpredicted), 1);
    }

    #[test]
    fn heavy_execution_without_fault_refutes_and_demotes() {
        let r = correlate(
            &[static_finding("src/buf.c", 88)],
            &[],
            Some(&covered("src/buf.c", 88, 500)),
            &CorrelationPolicy::default(),
        );
        assert_eq!(r.count(CorrelationVerdict::Refuted), 1);
        assert_eq!(r.findings[0].severity, Severity::Low);
        assert_eq!(r.findings[0].confidence, Confidence::Low);
        assert!(
            r.correlations[0].rationale.contains("not as proof of correctness"),
            "refutation must not be overstated"
        );
    }

    #[test]
    fn light_execution_is_inconclusive_and_changes_nothing() {
        let r = correlate(
            &[static_finding("src/buf.c", 88)],
            &[],
            Some(&covered("src/buf.c", 88, 3)),
            &CorrelationPolicy::default(),
        );
        assert_eq!(r.count(CorrelationVerdict::Inconclusive), 1);
        assert_eq!(r.findings[0].severity, Severity::Medium, "severity is untouched");
        assert_eq!(r.findings[0].confidence, Confidence::Medium);
    }

    #[test]
    fn unexecuted_code_is_unreached_not_refuted() {
        // The critical case: a file that ran, but not this line.
        let r = correlate(
            &[static_finding("src/buf.c", 88)],
            &[],
            Some(&covered("src/buf.c", 10, 1000)),
            &CorrelationPolicy::default(),
        );
        assert_eq!(r.count(CorrelationVerdict::Unreached), 1);
        assert_eq!(r.count(CorrelationVerdict::Refuted), 0);
        assert_eq!(r.findings[0].severity, Severity::Medium, "an untested claim is not weaker");
        assert!(r.correlations[0].rationale.contains("untested"));
    }

    #[test]
    fn a_file_that_never_ran_says_so_distinctly() {
        let r = correlate(
            &[static_finding("src/buf.c", 88)],
            &[],
            Some(&Observation::default()),
            &CorrelationPolicy::default(),
        );
        assert_eq!(r.count(CorrelationVerdict::Unreached), 1);
        assert!(r.correlations[0].rationale.contains("no line of"));
        assert_eq!(coverage_gaps(&r.findings, &r.correlations), vec![("src/buf.c".to_string(), vec![88])]);
    }

    /// The engine sees coverage *records*, not execution. With line-granular
    /// instrumentation an uninstrumented line and an unexecuted one look
    /// identical, so `Unreached` must never assert that code did not run.
    ///
    /// This was not hypothetical: a real run against an MSVC-built target
    /// reported "no line of sda_probe.h was executed" about the `fopen` that had
    /// just written the probe stream the run was reading.
    #[test]
    fn unreached_never_claims_code_did_not_run_when_it_only_lacks_a_probe() {
        // The file demonstrably ran — line 10 has a record — but the line the
        // finding sits on carries no probe.
        let obs = covered("src/buf.c", 10, 50);
        let r = correlate(
            &[static_finding("src/buf.c", 88)],
            &[],
            Some(&obs),
            &CorrelationPolicy::default(),
        );
        assert_eq!(r.count(CorrelationVerdict::Unreached), 1);

        let rationale = &r.correlations[0].rationale;
        assert!(
            !rationale.contains("was never executed"),
            "the engine cannot know this, and must not claim it: {rationale}"
        );
        assert!(
            rationale.contains("no coverage record"),
            "it must say what it actually observed: {rationale}"
        );
        assert!(
            rationale.contains("not instrumented"),
            "and name the other explanation, or a user reads it as a coverage hole: {rationale}"
        );

        // A file with no records at all gets the same treatment.
        let none = correlate(
            &[static_finding("src/other.c", 3)],
            &[],
            Some(&Observation::default()),
            &CorrelationPolicy::default(),
        );
        assert!(!none.correlations[0].rationale.contains("was executed"));
        assert!(none.correlations[0].rationale.contains("produced a coverage record"));
    }

    #[test]
    fn unpredicted_runtime_defects_are_reported_as_rule_set_gaps() {
        let r = correlate(&[], &[dynamic_finding("src/x.c", 4)], Some(&Observation::default()), &CorrelationPolicy::default());
        assert_eq!(r.count(CorrelationVerdict::Unpredicted), 1);
        assert!(r.correlations[0].rationale.contains("gap"));
        assert_eq!(r.findings[0].confidence, Confidence::Certain);
    }

    #[test]
    fn unpredicted_reporting_can_be_switched_off() {
        let policy = CorrelationPolicy { report_unpredicted: false, ..Default::default() };
        let r = correlate(&[], &[dynamic_finding("src/x.c", 4)], Some(&Observation::default()), &policy);
        assert!(r.correlations.is_empty());
    }

    #[test]
    fn suppressed_findings_are_passed_through_untouched() {
        let mut f = static_finding("src/buf.c", 88);
        f.suppressed_by = Some("deviation D-9".into());
        let r = correlate(&[f], &[], Some(&Observation::default()), &CorrelationPolicy::default());
        assert!(r.correlations.is_empty(), "an approved deviation is not re-litigated");
        assert!(r.findings[0].is_suppressed());
        assert_eq!(r.findings[0].phase, AnalysisPhase::Static);
    }

    /// A coverage gap is reported against the finding it belongs to.
    ///
    /// `coverage_gaps` paired `correlations[i]` with `findings[i]`. The two are
    /// pushed in lockstep everywhere except one branch: a suppressed finding
    /// goes into `findings` and produces no correlation, because an approved
    /// deviation is not re-litigated. From that point on the vectors are offset,
    /// and every gap is attributed to the wrong file and line.
    ///
    /// Nothing caught it because the existing tests pass a single unsuppressed
    /// finding, where a wrong pairing and a right one are the same pairing — and
    /// because no production code has ever called this function, so no report
    /// ever showed the wrong answer to anyone.
    #[test]
    fn a_coverage_gap_names_the_finding_it_belongs_to_even_after_a_suppression() {
        let mut approved = static_finding("src/accepted.c", 11);
        approved.suppressed_by = Some("deviation D-9".into());

        let r = correlate(
            &[approved, static_finding("src/untested.c", 42)],
            &[],
            Some(&Observation::default()),
            &CorrelationPolicy::default(),
        );

        // One finding correlated, one passed through: the vectors differ in length.
        assert_eq!(r.findings.len(), 2);
        assert_eq!(r.correlations.len(), 1);
        assert_eq!(r.count(CorrelationVerdict::Unreached), 1);

        assert_eq!(
            coverage_gaps(&r.findings, &r.correlations),
            vec![("src/untested.c".to_string(), vec![42])],
            "the gap is on the line that was never reached, not on the one whose deviation \
             was approved"
        );
    }

    #[test]
    fn the_refutation_threshold_is_configurable() {
        let policy = CorrelationPolicy { refutation_threshold: 2, ..Default::default() };
        let r = correlate(&[static_finding("a.c", 1)], &[], Some(&covered("a.c", 1, 3)), &policy);
        assert_eq!(r.count(CorrelationVerdict::Refuted), 1);
    }

    #[test]
    fn every_finding_records_the_verdict_that_moved_it() {
        let r = correlate(
            &[static_finding("src/buf.c", 88)],
            &[dynamic_finding("src/buf.c", 88)],
            Some(&covered("src/buf.c", 88, 1)),
            &CorrelationPolicy::default(),
        );
        assert!(
            r.findings[0]
                .evidence
                .iter()
                .any(|e| matches!(e, Evidence::Note { text } if text.starts_with("[confirmed]")))
        );
    }

    #[test]
    fn the_summary_names_what_to_do_first() {
        let r = correlate(
            &[static_finding("src/buf.c", 88), static_finding("src/b.c", 2)],
            &[dynamic_finding("src/buf.c", 88)],
            Some(&covered("src/buf.c", 88, 1)),
            &CorrelationPolicy::default(),
        );
        let s = summarize(&r);
        assert!(s.contains("1 static finding(s) were confirmed"));
        assert!(s.contains("fix"));
    }

    #[test]
    fn an_unexercised_file_gets_its_own_finding() {
        let f = unexercised_file_finding("src/dead.c");
        assert_eq!(f.confidence, Confidence::Certain);
        assert!(f.message.contains("vacuous"));
    }
}
