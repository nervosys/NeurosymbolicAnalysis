//! The four checks this engine reports under its own name, and their edges.
//!
//! `SDA-C-COMPLEXITY`, `SDA-C-NESTING`, `SDA-C-MULTICHAR` and `SDA-C-LEXICAL`
//! are not in any catalogue. That is deliberate — they are observations rather
//! than guideline verdicts, and `sda rules audit` does not offer a clean result
//! on them as evidence of anything, which is why `D1.1` and `D4.1` are
//! deliberately absent from `IMPLEMENTED_C`.
//!
//! It also meant nothing tested them. `checks.rs` gives every catalogued rule a
//! fixture proving it fires and a near-miss proving it stays quiet, and both
//! tests iterate `implemented(standard)` — so these four, which are in no
//! standard, fell through the middle. `SDA-C-COMPLEXITY` fires 1,285 times on
//! PX4 and had no test at all.
//!
//! Two of them are threshold checks, `complexity > 15` and `nesting > 5`, and a
//! threshold is where an off-by-one lives. Both edges are asserted here: the
//! value that must stay quiet and the next one up, which must not. They were
//! measured before they were written down, and both were already correct — this
//! pins that rather than fixing it.

use sda_core::Severity;
use sda_engine::run::{RunConfig, analyze};
use sda_engine::{default_registry, discover};

/// A function whose cyclomatic complexity is `decisions + 1`.
fn with_decisions(name: &str, decisions: usize) -> String {
    let body: String = (0..decisions)
        .map(|i| format!("  if (a == {i}) {{ r += {i}; }}\n"))
        .collect();
    format!("int {name}(int a) {{\n  int r = 0;\n{body}  return r;\n}}\n")
}

/// A function nested `depth` levels deep.
fn with_nesting(name: &str, depth: usize) -> String {
    let mut s = format!("int {name}(int a) {{\n  int r = 0;\n");
    for i in 0..depth {
        s.push_str(&format!("{}if (a > {i}) {{\n", "  ".repeat(i + 1)));
    }
    s.push_str(&format!("{}r = 1;\n", "  ".repeat(depth + 1)));
    for i in (1..=depth).rev() {
        s.push_str(&format!("{}}}\n", "  ".repeat(i)));
    }
    s.push_str("  return r;\n}\n");
    s
}

/// Scan one file in a directory of its own and return the rules reported.
fn rules_for(name: &str, source: &str) -> Vec<String> {
    let dir = std::env::temp_dir().join(format!("sda-own-rules-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let file = dir.join(format!("{name}.c"));
    std::fs::write(&file, source).expect("the source");

    let target = discover::discover(&dir, &discover::DiscoveryOptions::default());
    assert!(!target.files.is_empty(), "discovery found nothing under {}", dir.display());
    let report = analyze(&default_registry(), &target, &RunConfig::default());

    let out = report
        .findings
        .iter()
        .filter(|f| f.severity != Severity::Info || f.rule.as_str().starts_with("SDA-"))
        .map(|f| f.rule.to_string())
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn fires(name: &str, source: &str, rule: &str) -> bool {
    rules_for(name, source).iter().any(|r| r == rule)
}

/// Complexity is reported above fifteen and not at it.
#[test]
fn the_complexity_threshold_is_where_it_says_it_is() {
    // Fifteen decisions is a complexity of sixteen.
    assert!(
        fires("cx16", &with_decisions("cx16", 15), "SDA-C-COMPLEXITY"),
        "complexity 16 is over the threshold of 15"
    );
    assert!(
        !fires("cx15", &with_decisions("cx15", 14), "SDA-C-COMPLEXITY"),
        "complexity 15 is *at* the threshold, and the check is `> 15`. A rule that \
         fires 1,285 times on PX4 is worth holding to its own edge"
    );
}

/// And nesting above five, not at it.
#[test]
fn the_nesting_threshold_is_where_it_says_it_is() {
    assert!(
        fires("n6", &with_nesting("n6", 6), "SDA-C-NESTING"),
        "six levels is over the threshold of five"
    );
    assert!(
        !fires("n5", &with_nesting("n5", 5), "SDA-C-NESTING"),
        "five levels is at the threshold, and the check is `> 5`"
    );
}

/// A character constant holding more than one character, and one holding one.
#[test]
fn a_multi_character_constant_is_reported_and_a_single_one_is_not() {
    assert!(
        fires("mc", "int x = 'ab';\n", "SDA-C-MULTICHAR"),
        "`'ab'` has an implementation-defined value"
    );
    assert!(
        !fires("sc", "int y = 'a';\n", "SDA-C-MULTICHAR"),
        "`'a'` is an ordinary character constant"
    );
}

/// Source that does not lex cleanly says so, because everything after it is
/// suspect.
///
/// This is the one of the four that changes how the rest of the report should be
/// read: if the token stream diverges from what a compiler sees, every
/// structural finding in the file is a guess.
#[test]
fn source_that_does_not_lex_cleanly_is_reported_as_such() {
    assert!(
        fires("unterm", "int f(void) { return 0; }\n/* an unterminated comment\n", "SDA-C-LEXICAL"),
        "an unterminated comment swallows the rest of the file"
    );
    assert!(
        !fires("term", "/* a terminated comment */\nint f(void) { return 0; }\n", "SDA-C-LEXICAL"),
        "a closed comment lexes cleanly"
    );
}
