//! Two MISRA implementations, compared where they overlap.
//!
//! Everything else verified in this repository sits *beneath* the rules: the
//! lexer finds the right tokens, the structure analyser finds the right returns,
//! the adapters parse their tools. Whether `MISRA-C-2023-15.5` implements what
//! 15.5 *says* rests on a paraphrase in `crates/sda-rules/data/`, because the
//! normative text is licensed and not in this repository.
//!
//! This is the one check available without the document: a second implementation
//! to disagree with. cppcheck's MISRA addon reports rule *numbers* without the
//! licensed rule texts, so the guidelines it fires and where can be compared with
//! ours.
//!
//! # This is a comparison, not an oracle
//!
//! Neither tool is authoritative. The addon targets MISRA C:**2012** and this
//! toolkit targets **2023**; the numbering carries over for most rules and not
//! for all. A disagreement means one of the two is wrong *or* the editions
//! differ — it does not say which, and this file does not pretend to. What it
//! does is fail when the disagreements change, so somebody looks.

use sda_core::Severity;
use sda_engine::run::{RunConfig, analyze};
use sda_engine::{default_registry, discover};

const FIXTURE: &str = include_str!("fixtures/cppcheck-misra.json");

#[derive(serde::Deserialize)]
struct Fixture {
    cppcheck: String,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    path: String,
    findings: Vec<CppcheckFinding>,
}

#[derive(serde::Deserialize)]
struct CppcheckFinding {
    line: u32,
    rule: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("the captured cppcheck answers")
}

/// `misra-c2012-15.5` and `MISRA-C-2023-15.5` become `15.5`.
fn number(rule: &str) -> String {
    rule.rsplit('-').next().unwrap_or(rule).to_string()
}

fn ours(path: &str) -> Vec<(u32, String)> {
    // Discovery walks a directory, so the file's parent is scanned and the
    // findings are then narrowed to the file the fixture is about. Handing it a
    // file directly yields an empty target and a comparison that passes against
    // nothing, which is the failure this repository has a table of.
    // Paths in the fixture are relative to the workspace root; cargo runs an
    // integration test with the *crate* directory as its working directory.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("the workspace root");
    let owned = root.join(path);
    let file = owned.as_path();
    let dir = file.parent().expect("the corpus paths have a parent");
    let target = discover::discover(dir, &discover::DiscoveryOptions::default());
    assert!(!target.files.is_empty(), "discovery found nothing under {}", dir.display());

    let name = file.file_name().expect("a file name");
    let report = analyze(&default_registry(), &target, &RunConfig::default());
    let mut v: Vec<(u32, String)> = report
        .findings
        .iter()
        .filter(|f| f.location.file.file_name() == Some(name))
        .filter(|f| f.rule.as_str().starts_with("MISRA-C-2023-"))
        .filter(|f| f.severity != Severity::Info)
        .map(|f| (f.location.line, number(f.rule.as_str())))
        .collect();
    v.sort();
    v.dedup();
    v
}

fn theirs(c: &Case) -> Vec<(u32, String)> {
    let mut v: Vec<(u32, String)> =
        c.findings.iter().map(|f| (f.line, number(&f.rule))).collect();
    v.sort();
    v.dedup();
    v
}

/// Whether the catalogue already declines to call a clean result on this
/// guideline evidence of conformance — `semantics` (needs type information this
/// toolkit does not have), `partial` (checked with known gaps), and the rest.
///
/// `sda rules audit`'s central claim is that a clean result is evidence of
/// conformance *for the subset marked `native`*. This is the first time that
/// classification has been checked against a tool that has the type information
/// this one does not.
fn declares_a_gap(number: &str) -> bool {
    let catalog = sda_rules::Catalog::load(sda_rules::Standard::MisraC2023);
    catalog.get(number).is_some_and(|r| !r.coverage.clean_means_conformant())
}

/// Differences that are the two *editions* disagreeing, not the two tools.
///
/// The header of this file says a disagreement means one implementation is
/// wrong *or* the editions differ, and does not say which. Each entry here is a
/// case where that was run down and the answer was "the editions differ", with
/// the evidence. Anything not on this list has to be a declared gap or the test
/// fails, which is what keeps the list from becoming a place to put things.
fn edition_difference(number: &str) -> Option<&'static str> {
    match number {
        // cppcheck's `misra_21_8` fires on `abort`, `exit` and **`getenv`**
        // (addons/misra.py, 2.21.0). MISRA C:2012's 21.8 named specific
        // functions; C:2023 restates it as "the Standard Library *termination*
        // functions of <stdlib.h>", and `getenv` does not terminate anything.
        // This engine implements the 2023 reading — `abort`, `exit`, `_Exit`,
        // `quick_exit` — and adding `getenv` to match cppcheck would make it
        // wrong for the edition it targets.
        //
        // Comparing sets rather than lines makes this allowance coarser than it
        // should be: it excuses 21.8 on any file where cppcheck fires it and
        // this engine does not, including a file whose only 21.8 is a genuine
        // `exit`. The corpus has such a file (`examples/firmware/src/main.c`,
        // where both tools agree on 21.8), so the coarseness is visible rather
        // than hypothetical.
        "21.8" => Some("cppcheck's 21.8 includes `getenv`; C:2023's does not"),
        _ => None,
    }
}

/// Guidelines this engine fires on and cppcheck does not, each run down to a
/// reason.
///
/// The directives (`D4.*`) are excluded elsewhere: the addon does not implement
/// them at all. These are guidelines both tools implement, where the two read
/// the same construct differently and the difference was chased to its source.
fn this_engine_reports_more(number: &str) -> Option<&'static str> {
    match number {
        // The guideline prohibits the standard I/O *functions*; cppcheck flags
        // the calls, and this toolkit also flags `#include <stdio.h>` with a
        // message saying the header "is not permitted in this profile" — a
        // broader claim than 21.6 makes. Whether the citation should be narrowed
        // or the message reworded to a profile rule that cites nothing needs the
        // licensed text, so it is recorded rather than guessed at.
        "21.6" => Some("this engine also flags the include; 21.6 names the functions"),
        // `sizeof(g(a))`. The guideline is about an operand containing an
        // expression with *potential* side effects, and a call to a function
        // whose body is elsewhere has them by definition. cppcheck's
        // `countSideEffectsRecursive` counts assignments and `++`/`--` and
        // carries the comment `# Todo: Check function calls` (addons/misra.py,
        // 2.21.0), so the addon knows it is under-reporting here.
        "13.6" => Some("cppcheck's side-effect counter has a TODO for function calls"),
        // 12.3 is the comma operator, and this engine reports it wherever it is
        // an operator. The captured cppcheck run reports 12.3 only on the comma
        // in a `for` header (`control_flow.c:27`); it does not report the
        // operator in `r = (a++, b);` (`expressions.c:25`), which the corpus
        // exists to show. The guideline reads the same in both editions, so this
        // is cppcheck's coverage, not the edition.
        "12.3" => Some("cppcheck's captured run reports 12.3 only in a for header, not in an operand"),
        // The addon has `misra_3_2` written and **commented out** of its own
        // dispatch table: `#self.executeCheck(302, self.misra_3_2, ...)`
        // (addons/misra.py:4723, 2.21.0). Line-splicing a `//` comment swallows
        // the line after it, so this engine keeps checking it.
        //
        // That is a property of the release and not of the tool. cppcheck
        // 2.17.1, in Debian stable, dispatches it (addons/misra.py:4557) and
        // agrees with this engine to the line — `lexical.c:22`. An oracle is a
        // version, not a tool, and this entry would be wrong against any
        // cppcheck older than the one the fixture is pinned to.
        "3.2" => Some("cppcheck's 3.2 is commented out of its dispatch table"),
        // Not in the addon's dispatch table at all. It is not unchecked, though:
        // clang's `-Wunused-label` decides the same thing, and
        // `misra_agrees_with_clang_warnings.rs` holds the two to each other line
        // for line. A guideline one reference tool does not implement is a
        // reason to find another, not a reason to stop comparing.
        "2.6" => Some("cppcheck does not implement 2.6; clang's `-Wunused-label` does"),
        // The mirror image of the defect this corpus found in 5.4 and 5.5.
        // `get_num_significant_naming_chars` returns 63 for anything past C89 and
        // cppcheck uses that number for 5.1 too — but 63 is the *internal*
        // identifier limit. C23 §5.2.4.1 gives an external identifier 31, which
        // is what 5.1 is about, and what this engine uses. Two thirty-two
        // character externals collide for a linker and cppcheck does not look.
        "5.1" => Some("cppcheck applies the internal-identifier length to external identifiers"),
        // cppcheck's `misra_21_2` covers macro names matching `_+BUILTIN_.*` and
        // functions whose names are standard-library identifiers. The general
        // reserved-identifier shape — a leading underscore before a capital, or a
        // double underscore anywhere — is not implemented there.
        "21.2" => Some("cppcheck's 21.2 covers library names and `__BUILTIN_` macros only"),
        // Absent from the addon's dispatch table (addons/misra.py, 2.21.0), so
        // there is nothing to compare: the corpus holds a violating and a
        // conforming form of each and a fixture in `checks.rs` pins the behaviour,
        // but no second implementation has looked at these. 8.16, 8.17, 17.10,
        // 21.24 and 21.25 are newer than the addon's edition; on `_Alignas` and
        // `_Noreturn` lines it emits 1.4 instead.
        "6.3" | "7.6" | "8.16" | "8.17" | "17.10" | "21.24" | "21.25" => {
            Some("not in cppcheck's dispatch table; no second implementation to compare")
        }
        _ => None,
    }
}

/// Guideline numbers, per file, with the line dropped.
///
/// **Lines are deliberately not compared.** Both tools fire MISRA 16.3 on the
/// same switch and 15.7 on the same `if` chain, and anchor them four lines
/// apart: cppcheck points at the clause that falls through, this toolkit at the
/// statement that should have been followed by a `break`. Neither the guideline
/// nor the standard says where the finding belongs, so asserting line-for-line
/// would pin one tool's presentation choice as truth. What the two can be held
/// to is *which guidelines a file violates*.
fn numbers(pairs: Vec<(u32, String)>) -> std::collections::BTreeSet<String> {
    pairs.into_iter().map(|(_, n)| n).collect()
}

/// Everything cppcheck reports and this toolkit does not must be a guideline
/// this toolkit *declares* it cannot check natively.
///
/// `sda rules audit`'s central claim — that a clean result is evidence of
/// conformance for a stated subset of the catalogue — rests entirely on that
/// classification being honest. This is the first time it has been checked
/// against a tool that has the type information this one does not.
#[test]
fn what_cppcheck_finds_and_this_does_not_is_what_this_says_it_cannot_check() {
    let f = fixture();
    assert!(f.cppcheck.contains("Cppcheck"), "captured from: {}", f.cppcheck);
    let mut checked = 0;

    for c in &f.cases {
        let mine = numbers(ours(&c.path));
        let yours = numbers(theirs(c));
        for n in yours.difference(&mine) {
            if edition_difference(n).is_some() {
                continue;
            }
            assert!(
                declares_a_gap(n),
                "{}: cppcheck reports MISRA {n} and this toolkit does not, while the catalogue                  marks it `native` — meaning a clean result on it is offered as evidence of                  conformance. Either the rule is unimplemented, it missed this file, or the                  classification is too strong",
                c.path
            );
            checked += 1;
        }
    }
    assert!(checked >= 3, "the corpus should exercise the claim, not just satisfy it: {checked}");
}

/// And everything this toolkit reports that cppcheck does not is a directive its
/// addon does not implement, or a difference already run down and written up in
/// [`this_engine_reports_more`].
#[test]
fn what_this_finds_and_cppcheck_does_not_is_directives_or_written_up() {
    for c in &fixture().cases {
        let mine = numbers(ours(&c.path));
        let yours = numbers(theirs(c));
        for n in mine.difference(&yours) {
            assert!(
                n.starts_with("D4.") || this_engine_reports_more(n).is_some(),
                "{}: this toolkit reports MISRA {n} and cppcheck does not, and it is neither a \
                 directive nor a difference run down and written up — one of the two is wrong",
                c.path
            );
        }
    }
}

/// The corpus has to exercise both directions, or the two tests above pass by
/// having nothing to compare.
#[test]
fn the_corpus_makes_both_tools_disagree_in_both_directions() {
    let f = fixture();
    let (mut theirs_only, mut ours_only, mut both) = (0, 0, 0);
    for c in &f.cases {
        let mine = numbers(ours(&c.path));
        let yours = numbers(theirs(c));
        theirs_only += yours.difference(&mine).count();
        ours_only += mine.difference(&yours).count();
        both += mine.intersection(&yours).count();
    }
    assert!(theirs_only >= 2, "cppcheck should find guidelines this does not: {theirs_only}");
    assert!(ours_only >= 2, "and the other way round: {ours_only}");
    assert!(
        both >= 3,
        "and the two should agree somewhere, or the tests above are satisfied by an overlap of \
         nothing: {both}"
    );
}

/// The corpus has to be wide enough for the comparison to mean something.
///
/// It was four files that happened to be in the repository, exercising about
/// twenty guidelines; the two tools implement sixty-one of the same ones —
/// counted from the addon's dispatch table, because one of its checks
/// (`misra_3_2`) is written but commented out of it. This counts what the
/// comparison actually reaches, so shrinking the corpus fails here rather than
/// quietly weakening every assertion above.
#[test]
fn the_comparison_reaches_a_useful_share_of_what_both_tools_implement() {
    let f = fixture();
    let mut reached = std::collections::BTreeSet::new();
    for c in &f.cases {
        reached.extend(numbers(ours(&c.path)));
        reached.extend(numbers(theirs(c)));
    }
    assert!(
        f.cases.len() >= 10,
        "the corpus is {} file(s); it was widened deliberately",
        f.cases.len()
    );
    assert!(
        reached.len() >= 50,
        "only {} guideline(s) are exercised by this corpus: {reached:?}",
        reached.len()
    );
}
