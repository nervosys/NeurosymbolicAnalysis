//! A runtime defect inside a region a static finding claims is that finding
//! coming true.
//!
//! `CorrelationPolicy::line_tolerance` is a *measurement* allowance — compilers
//! and sanitizers disagree about which line an operation belongs to, so a line or
//! two either side of a point is noise. It is not a scoping mechanism, and
//! raising it to cover a construct would loosen matching for every rule and every
//! tool at once.
//!
//! A stated `end_line` is a different thing: a *claim* that the finding is about
//! a region. `unsafe` forced the distinction. The finding sits on the keyword
//! because that is where the justification is missing, but what it is about is
//! the whole block where the compiler has stopped checking — and Miri faults
//! wherever the defect actually is, which in the case that prompted this was
//! three lines past the noise allowance. One block was reported as two
//! unconnected claims.
//!
//! Only findings that state an extent are affected, and a finding states one only
//! where something measured it.

use sda_core::{
    AnalysisPhase, Confidence, CorrelationVerdict, Evidence, Finding, Location, RuntimeEvent,
    RuntimeEventKind, Severity, TaxonomyRef,
};
use sda_engine::correlate::{CorrelationPolicy, correlate};

/// A static finding about lines 8-12, located at 8.
fn spanning_finding() -> Finding {
    Finding::new(
        "sda.static.rust",
        "RUST-2024-UNSAFE.1",
        "this `unsafe` block has no `// SAFETY:` comment",
        Severity::Medium,
        Location::new("src/lib.rs", 8, 5).spanning(12, 1),
    )
    .confidence(Confidence::High)
    // Taken from the shipped catalogue, not written here. Proximity alone never
    // confirms — the defect must also be of a class the finding is about — so a
    // fixture carrying its own CWE would keep passing after the catalogue's
    // changed underneath it, which is the failure this rule already had.
    .taxonomy(TaxonomyRef::cwe(unsafe_rule_cwe()))
}

/// The same finding with no extent, which is what every other rule emits.
fn point_finding() -> Finding {
    Finding::new(
        "sda.static.rust",
        "RUST-2024-UNSAFE.1",
        "this `unsafe` block has no `// SAFETY:` comment",
        Severity::Medium,
        Location::new("src/lib.rs", 8, 5),
    )
    .confidence(Confidence::High)
    .taxonomy(TaxonomyRef::cwe(unsafe_rule_cwe()))
}

/// The CWE `RUST-2024-UNSAFE.1` actually ships with.
fn unsafe_rule_cwe() -> u32 {
    sda_rules::lookup("RUST-2024-UNSAFE.1")
        .expect("UNSAFE.1 ships")
        .cwe
        .expect("a rule a runtime tool can confirm must state a weakness class")
}

/// A runtime defect three lines below the static finding — outside the default
/// two-line tolerance, inside the block.
fn witness_at(line: u32) -> Finding {
    let loc = Location::new("src/lib.rs", line, 9);
    Finding::new(
        "ext.miri",
        "Undefined Behavior",
        "attempting a read access using a tag that does not exist in the borrow stack",
        Severity::High,
        loc.clone(),
    )
    .phase(AnalysisPhase::Dynamic)
    .confidence(Confidence::Certain)
    .evidence(Evidence::Runtime {
        event: {
            let mut e = RuntimeEvent::new(RuntimeEventKind::SanitizerReport, "miri");
            e.location = Some(loc);
            e
        },
    })
}

fn verdicts(statics: &[Finding], dynamics: &[Finding]) -> Vec<CorrelationVerdict> {
    correlate(statics, dynamics, None, &CorrelationPolicy::default())
        .correlations
        .iter()
        .map(|c| c.verdict)
        .collect()
}

#[test]
fn a_defect_inside_the_claimed_region_confirms_the_finding() {
    let v = verdicts(&[spanning_finding()], &[witness_at(11)]);
    assert_eq!(
        v,
        vec![CorrelationVerdict::Confirmed],
        "line 11 is inside the region lines 8-12 that this finding says it is about"
    );
}

/// The control, and the reason this is not just a bigger tolerance: without the
/// stated extent the very same pair does not match.
#[test]
fn the_same_defect_against_a_point_finding_does_not_confirm() {
    let v = verdicts(&[point_finding()], &[witness_at(11)]);
    // Inconclusive for the static finding, and the runtime defect goes on to be
    // reported as `Unpredicted` in its own right — which is the correct pair for
    // "these are two unrelated claims", and is exactly what the `unsafe` case
    // produced before the extent was stated.
    assert_eq!(
        v,
        vec![CorrelationVerdict::Inconclusive, CorrelationVerdict::Unpredicted],
        "3 lines away, and nothing claimed a region — this must stay unmatched"
    );
}

/// A region is a claim with an end. A defect past it is not inside it.
#[test]
fn a_defect_past_the_end_of_the_region_does_not_confirm() {
    let v = verdicts(&[spanning_finding()], &[witness_at(40)]);
    assert_eq!(
        v,
        vec![CorrelationVerdict::Inconclusive, CorrelationVerdict::Unpredicted],
        "a region has an end, and line 40 is past it"
    );
}

/// And the noise allowance still applies to the point, so a defect just above the
/// region's start is still matched.
#[test]
fn the_measurement_tolerance_still_applies_around_the_start() {
    let v = verdicts(&[spanning_finding()], &[witness_at(7)]);
    assert_eq!(v, vec![CorrelationVerdict::Confirmed]);
}

/// The rationale is the evidence a reader is given for the strongest claim this
/// engine makes, so it must say what actually matched. It read "within 2 line(s)
/// of this static finding" for every confirmation, which is untrue of a match
/// made by span.
#[test]
fn the_rationale_says_which_rule_matched() {
    let r = correlate(
        &[spanning_finding()],
        &[witness_at(11)],
        None,
        &CorrelationPolicy::default(),
    );
    let why = &r.correlations[0].rationale;
    assert!(why.contains("inside the region this finding is about"), "{why}");
    assert!(why.contains("8-12"), "{why}");
    assert!(!why.contains("within 2 line(s)"), "{why}");
}

/// The rule's own citation, pinned.
///
/// The span above is necessary and was not sufficient: `same_defect_class`
/// requires the runtime witness's weakness class to relate to the static
/// finding's CWE, and `UNSAFE.1` was catalogued as **CWE-1108**, "Excessive
/// Reliance on Global Variables" — unrelated to this rule, and in no runtime
/// event's related set. So a sanitizer or interpreter reporting undefined
/// behaviour inside an unjustified `unsafe` block could never confirm the
/// finding. Miri did exactly that, and one block came back as two unrelated
/// claims with the span already in place.
///
/// Both numbers were checked against cwe.mitre.org before the change, because
/// the toolkit's third commitment is that it does not invent citations and the
/// cost of guessing here is a false `confirmed`.
#[test]
fn the_unsafe_rule_cites_the_weakness_a_runtime_tool_can_witness() {
    let rule = sda_rules::lookup("RUST-2024-UNSAFE.1").expect("UNSAFE.1 ships");
    assert_eq!(
        rule.cwe,
        Some(758),
        "CWE-758 is `Reliance on Undefined, Unspecified, or Implementation-Defined Behavior`,          which is what an unjustified `unsafe` block is. A CWE no runtime event relates to          silently disables confirmation for this rule"
    );

    // The behavioural half of this claim is the first test in this file: it
    // builds its static finding from this very catalogue entry and requires a
    // `SanitizerReport` witness — what a tool stating no CWE is labelled — to
    // confirm it. If the relation ever stops holding, that test fails rather
    // than this one quietly passing on a number.
}
