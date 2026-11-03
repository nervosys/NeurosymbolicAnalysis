//! The three modalities over one system, in the order they must run.
//!
//! The unit tests in `neurosymbolic.rs` check each verdict in isolation. This
//! checks the thing that isolation cannot: that deduction, observation and
//! silence compose without one overwriting another, over a single worked
//! example.
//!
//! The example is the shape the architecture is designed around — a shielded
//! neurosymbolic controller:
//!
//! ```text
//!   models/policy/head.onnx        a 7B-parameter policy  (neural, inductive only)
//!            |
//!            v
//!   src/guard/clamp.rs             a verified shield      (symbolic, deductive)
//!            |
//!            v
//!   src/actuator/drive.rs          the effector           (symbolic, unspecified)
//! ```
//!
//! Four static findings, one per interesting case, and the assertion is that
//! each ends up with the verdict its *evidence* justifies rather than the one
//! its severity or convenience would suggest.

use sda_core::verification::{
    Architecture, Assumption, AssumptionSupport, Boundary, NeuralProfile, ObligationStatus,
    ProofObligation, SearchStrategy, VerificationLedger,
};
use sda_core::{
    AnalysisPhase, CorrelationVerdict, Evidence, Finding, Location, RuntimeEvent, RuntimeEventKind,
    Severity,
};
use sda_engine::correlate::{CorrelationPolicy, correlate};
use sda_engine::dynamic::Observation;
use sda_engine::interposition::{self, FAITHFULNESS, FlowGraph};
use sda_engine::neurosymbolic::{Component, SystemMap, adjudicate, summarize};

fn finding(path: &str, line: u32, rule: &str, title: &str) -> Finding {
    Finding::new("sda.static.rust", rule, title, Severity::High, Location::new(path, line, 5))
}

fn system() -> SystemMap {
    SystemMap::new()
                .with(Component::neural("policy", "models/policy").profiled(
            NeuralProfile::new(Architecture::Transformer)
                .with_parameters(7_000_000_000)
                .over_region("L-inf ball on the embeddings, epsilon = 0.01"),
        ))
        .with(Component::symbolic("guard::clamp", "src/guard").guard())
        .with(Component::symbolic("actuator::drive", "src/actuator").effector())
}

/// The guard is proved, and its one premise is paid for by another proof.
fn ledger() -> VerificationLedger {
    VerificationLedger::new()
        .with_obligation(
            ProofObligation::new(
                "guard::clamp/ensures/0",
                "the command handed to the actuator is within its rated range",
                "guard::clamp",
                Boundary::Symbolic,
                ObligationStatus::Discharged,
            )
            .proved_by("ext.verus")
            .settling("RUST-RANGE-01"),
        )
        .with_obligation(ProofObligation::new(
            "guard::clamp/total",
            "clamp terminates and cannot panic on any input, NaN included",
            "guard::clamp",
            Boundary::Symbolic,
            ObligationStatus::Discharged,
        ))
        .with_assumption(
            Assumption::new(
                "guard::interposed",
                "every policy output reaches the actuator through clamp",
                Boundary::Symbolic,
                AssumptionSupport::RuntimeGuard {
                    location: None,
                    totality_obligation: Some("guard::clamp/total".into()),
                },
            )
            .underwrites("guard::clamp/ensures/0"),
        )
}

#[test]
fn each_finding_gets_the_verdict_its_evidence_justifies() {
    let findings = vec![
        // Proved: the guard's obligation settles this rule, premises paid.
        finding("src/guard/clamp.rs", 40, "RUST-RANGE-01", "output may exceed the rated range"),
        // Assumed: inside the model, where no proof reaches.
        finding("models/policy/head.onnx", 1, "AI-BACKDOOR-01", "trigger-like tokenizer entry"),
        // Untouched here: symbolic, but no obligation names this rule. It falls
        // through to the runtime correlator below.
        finding("src/actuator/drive.rs", 88, "RUST-UNSAFE-07", "raw pointer write"),
        // Untouched here: no declared component owns this path at all.
        finding("src/util/parse.rs", 12, "RUST-RANGE-01", "unchecked index"),
    ];

    let a = adjudicate(&findings, &ledger(), &system());

    assert_eq!(a.count(CorrelationVerdict::Proved), 1);
    assert_eq!(a.count(CorrelationVerdict::Assumed), 1);
    assert_eq!(a.correlations.len(), 2, "the other two were left for the correlation engine");

    let proved = &a.adjudicated()[0];
    assert_eq!(proved.severity, Severity::Info, "a proved finding is removed, not softened");

    // The un-owned path is named in NOT CHECKED rather than quietly passing.
    assert!(a.not_checked.iter().any(|l| l.contains("src/util/parse.rs")));
    // And the model's size is given as the reason no prover was run against it,
    // rather than neural verification being silently absent from the report.
    assert!(
        a.not_checked.iter().any(|l| l.contains("sda.intractable[policy]")),
        "at 7B parameters nothing can prove anything about it, and the report says which: {:?}",
        a.not_checked
    );
    // And so is the component nobody wrote a specification for.
    assert!(
        a.not_checked.iter().any(|l| l.contains("sda.vacuous[actuator::drive]")),
        "an unspecified component verifies trivially and must say so: {:?}",
        a.not_checked
    );
}

#[test]
fn a_proved_finding_is_not_re_judged_by_coverage() {
    let f = finding("src/guard/clamp.rs", 40, "RUST-RANGE-01", "output may exceed the rated range");
    let a = adjudicate(std::slice::from_ref(&f), &ledger(), &system());
    assert_eq!(a.count(CorrelationVerdict::Proved), 1);

    // The proved line is also stone cold — measured, and never executed. Handing
    // it to the correlation engine would return `Unreached`, downgrading "there
    // is no such execution" to "we never tried". The pipeline does not hand it
    // over.
    let handed_on = a.unadjudicated();
    assert!(handed_on.is_empty(), "the proved finding must not reach the runtime correlator");

    let obs = Observation::default();
    let r = correlate(&handed_on, &[], Some(&obs), &CorrelationPolicy::default());
    assert_eq!(r.count(CorrelationVerdict::Unreached), 0);
    assert_eq!(
        a.count(CorrelationVerdict::Proved),
        1,
        "the deductive verdict survives the dynamic pass"
    );
}

#[test]
fn what_deduction_leaves_open_is_still_judged_by_execution() {
    let unsafe_write = finding("src/actuator/drive.rs", 88, "RUST-UNSAFE-07", "raw pointer write");
    let a = adjudicate(std::slice::from_ref(&unsafe_write), &ledger(), &system());
    assert!(a.correlations.is_empty(), "no obligation names this rule");

    // A sanitizer fault lands on the same line, and it is the same class of
    // defect. Deduction had nothing to say; observation does.
    let runtime = Finding::new(
        "sda.dynamic",
        "ASAN-HEAP-BUFFER-OVERFLOW",
        "heap-buffer-overflow on write",
        Severity::Critical,
        Location::new("src/actuator/drive.rs", 88, 5),
    )
    .phase(AnalysisPhase::Dynamic)
    .taxonomy(sda_core::TaxonomyRef::cwe(787))
    .evidence(Evidence::Runtime {
        event: RuntimeEvent::new(RuntimeEventKind::MemoryError, "write of size 8 past the end")
            .at(Location::new("src/actuator/drive.rs", 88, 5)),
    });
    let subject = a.unadjudicated()[0].clone().taxonomy(sda_core::TaxonomyRef::cwe(787));

    let r = correlate(&[subject], &[runtime], None, &CorrelationPolicy::default());
    assert_eq!(
        r.count(CorrelationVerdict::Confirmed),
        1,
        "the modalities cover each other's gaps; that is the whole point"
    );
}

#[test]
fn the_system_claim_names_its_premises_and_never_averages() {
    let a = adjudicate(
        &[finding("src/guard/clamp.rs", 40, "RUST-RANGE-01", "output may exceed the rated range")],
        &ledger(),
        &system(),
    );
    let s = summarize(&a, &ledger(), "the actuator is never commanded out of range");

    assert!(s.contains("1 finding(s) proved impossible"));
    assert!(
        s.contains("holds on every execution"),
        "every premise is deductively supported here, so the claim is unconditional: {s}"
    );
    assert!(
        !s.contains('%'),
        "no percentage, ever: a single confidence over mixed modalities is the failure this \
         design exists to prevent"
    );
    assert!(s.contains("NOT CHECKED"), "the unspecified actuator is still owed a mention");
}

#[test]
fn replacing_the_proved_premise_with_a_probe_campaign_downgrades_the_whole_claim() {
    // Same guard, same discharged obligation. The only change is that the
    // premise is now supported by 10_000 quiet probes instead of a proof.
    let ledger = VerificationLedger::new()
        .with_obligation(
            ProofObligation::new(
                "guard::clamp/ensures/0",
                "the command handed to the actuator is within its rated range",
                "guard::clamp",
                Boundary::Symbolic,
                ObligationStatus::Discharged,
            )
            .proved_by("ext.verus")
            .settling("RUST-RANGE-01"),
        )
        .with_assumption(
            Assumption::new(
                "guard::interposed",
                "every policy output reaches the actuator through clamp",
                Boundary::Symbolic,
                AssumptionSupport::Inductive {
                    evidence: vec!["test.interposition".into()],
                    trials: 10_000,
                    counterexamples: 0,
                    search: SearchStrategy::Adversarial,
                },
            )
            .underwrites("guard::clamp/ensures/0"),
        );

    let f = finding("src/guard/clamp.rs", 40, "RUST-RANGE-01", "output may exceed the rated range");
    let a = adjudicate(std::slice::from_ref(&f), &ledger, &system());

    assert_eq!(a.count(CorrelationVerdict::Proved), 0, "10_000 trials do not discharge a premise");
    assert_eq!(a.count(CorrelationVerdict::Assumed), 1);
    assert_eq!(a.findings[0].severity, f.severity, "nothing was learned, so nothing moves");

    let s = summarize(&a, &ledger, "the actuator is never commanded out of range");
    assert!(s.contains("PROVIDED"), "the system claim is now conditional: {s}");
    assert!(s.contains("every policy output reaches the actuator through clamp"));
}

/// The premise the whole safety case rests on, proved rather than trusted.
///
/// In `ledger()` above, `guard::interposed` is an `AssumptionSupport::RuntimeGuard`
/// — the guard is total, so if output goes through it the output is in range.
/// That leaves the *if* unexamined, and at language-model scale the *if* is the
/// entire safety case. Interposition is not a claim about the model; it is a
/// claim about the shape of the program, and reachability over a dataflow graph
/// is decidable. So it gets decided.
#[test]
fn interposition_moves_from_trusted_to_proved_but_keeps_its_own_premise() {
    let flow =
        FlowGraph::new().edge("policy", "guard::clamp").edge("guard::clamp", "actuator::drive");
    let i = interposition::verify(&system(), &flow, &[]);
    assert!(i.is_interposed());

    // The guard's postcondition now cites the interposition proof instead of
    // trusting that output reaches it.
    let ledger = i.merge_into(
        VerificationLedger::new()
            .with_obligation(
                ProofObligation::new(
                    "guard::clamp/ensures/0",
                    "the command handed to the actuator is within its rated range",
                    "guard::clamp",
                    Boundary::Symbolic,
                    ObligationStatus::Discharged,
                )
                .proved_by("ext.verus")
                .settling("RUST-RANGE-01"),
            )
            .with_assumption(
                Assumption::new(
                    "guard::interposed",
                    "every policy output reaches the actuator through clamp",
                    Boundary::Symbolic,
                    AssumptionSupport::Proved {
                        obligation: "flow::policy->actuator::drive/interposed".into(),
                    },
                )
                .underwrites("guard::clamp/ensures/0"),
            ),
    );

    // Locally everything looks paid for. Transitively it is not: the
    // interposition proof rests on the declaration being faithful to the code,
    // and nothing establishes that.
    assert!(ledger.assumptions_for("guard::clamp/ensures/0").iter().all(|a| a.support.is_sound()));
    let unpaid = ledger.unpaid_premises("guard::clamp/ensures/0");
    assert_eq!(unpaid.len(), 1);
    assert_eq!(unpaid[0].id, FAITHFULNESS);

    // So the finding is `Assumed`, not `Proved` — the premise moved two links
    // away, and the verdict followed it.
    let f = finding("src/guard/clamp.rs", 40, "RUST-RANGE-01", "output may exceed the rated range");
    let a = adjudicate(std::slice::from_ref(&f), &ledger, &system());
    assert_eq!(a.count(CorrelationVerdict::Proved), 0, "a chain is only as good as its last link");
    assert_eq!(a.count(CorrelationVerdict::Assumed), 1);
    assert!(a.correlations[0].rationale.contains("declared dataflow graph matches the code"));
}

/// The same system, with a relay the declaration forgot. A taint tool finds it.
#[test]
fn a_taint_observed_bypass_fails_an_interposition_proof_the_declaration_passed() {
    let flow =
        FlowGraph::new().edge("policy", "guard::clamp").edge("guard::clamp", "actuator::drive");
    let bypass = Finding::new(
        "ext.codeql",
        "rust/model-output-to-actuator",
        "model output reaches the actuator",
        Severity::High,
        Location::new("src/actuator/drive.rs", 88, 5),
    )
    .evidence(Evidence::Trace {
        frames: vec![
            sda_core::TraceFrame {
                location: Location::new("models/policy/head.onnx", 1, 1),
                note: "model output".into(),
                step: 0,
            },
            sda_core::TraceFrame {
                location: Location::new("src/actuator/drive.rs", 88, 5),
                note: "written to the actuator".into(),
                step: 1,
            },
        ],
    });

    let clean = interposition::verify(&system(), &flow, &[]);
    assert!(clean.is_interposed(), "the declaration alone says the guard cannot be bypassed");

    let observed = interposition::verify(&system(), &flow, std::slice::from_ref(&bypass));
    assert!(!observed.is_interposed(), "the code disagrees, and the code wins");
    assert!(interposition::summarize(&observed).contains("NOT established"));
    assert!(observed.bypasses[0].describe().contains("observed by taint analysis"));
}
