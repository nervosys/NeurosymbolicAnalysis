//! System-scope guidelines, checked across more than one file.
//!
//! The catalogue records each guideline's *scope*: `single` for one that is
//! judged per translation unit, `system` for one that is judged across the whole
//! program. It separately records *coverage*, where `native` means "a clean
//! result is evidence of conformance".
//!
//! A `system`-scope guideline marked `native` is a claim that the engine settles
//! it across the program. The C analyzer's entry point is `check_source(path,
//! source)` — one file, no memory of the others — so that claim needs checking,
//! and the fixtures in `checks.rs` cannot check it: each puts both halves of the
//! violation in the same file.
//!
//! This is the same defect 12.1 and D4.4 turned out to be, arrived at from a
//! third direction, and it is asserted rather than argued: the test builds a
//! two-file project whose violation spans the two files, and holds the
//! classification to what the engine actually finds.

use sda_engine::run::{RunConfig, analyze};
use sda_engine::{default_registry, discover};
use sda_rules::{Catalog, Scope, Standard};

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sda-system-scope-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Guideline numbers reported over a whole directory.
fn numbers_over(dir: &std::path::Path) -> std::collections::BTreeSet<String> {
    let target = discover::discover(dir, &discover::DiscoveryOptions::default());
    assert!(target.files.len() >= 2, "the point is more than one file: {}", dir.display());
    analyze(&default_registry(), &target, &RunConfig::default())
        .findings
        .iter()
        .filter_map(|f| f.rule.as_str().strip_prefix("MISRA-C-2023-"))
        .map(str::to_string)
        .collect()
}

fn write(dir: &std::path::Path, name: &str, source: &str) {
    std::fs::write(dir.join(name), source).unwrap();
}

fn scope_of(number: &str) -> Scope {
    Catalog::load(Standard::MisraC2023).get(number).expect("a catalogued guideline").scope
}

fn is_native(number: &str) -> bool {
    Catalog::load(Standard::MisraC2023)
        .get(number)
        .expect("a catalogued guideline")
        .coverage
        .clean_means_conformant()
}

/// 5.1: external identifiers must be distinct within the significant length.
///
/// The length that matters is the linker's, so a collision between two
/// translation units is the *only* interesting case — a collision inside one
/// file is caught by the compiler long before MISRA is consulted. Both names
/// here agree for 31 characters and differ at the 32nd.
#[test]
fn two_files_whose_external_identifiers_collide_at_link_time() {
    let dir = scratch("5-1");
    let stem = "a".repeat(31);
    write(&dir, "a.c", &format!("int {stem}1(void) {{ return 0; }}\n"));
    write(&dir, "b.c", &format!("int {stem}2(void) {{ return 1; }}\n"));

    assert_eq!(
        scope_of("5.1"),
        Scope::System,
        "5.1 is judged across the program, which is why this test exists"
    );
    assert!(
        numbers_over(&dir).contains("5.1"),
        "two files whose external identifiers are indistinguishable to a conforming linker must \
         produce a finding; this went unreported while the guideline was marked `native`"
    );
}

/// And the case that makes a cross-file name check usable at all.
///
/// Two `static` functions with the same name in different files are correct C —
/// internal linkage, no collision, and the pattern is everywhere in real
/// projects. A whole-program identifier check that does not know the difference
/// reports every one of them, which is why `internal_linkage` had to be
/// recorded before this check could exist.
#[test]
fn two_static_functions_with_the_same_name_are_not_a_collision() {
    let dir = scratch("5-1-static");
    write(&dir, "a.c", "static int helper(void) { return 0; }\nint a(void) { return helper(); }\n");
    write(&dir, "b.c", "static int helper(void) { return 1; }\nint b(void) { return helper(); }\n");

    let found = numbers_over(&dir);
    assert!(
        !found.contains("5.1"),
        "`static int helper(void)` in two files is ordinary C; reporting it would make the \
         check unusable on any real project"
    );
    assert!(!found.contains("D4.5"), "and it is not typographically ambiguous either");
}

/// The identifiers being compared must be the ones the linker sees.
///
/// A name that differs *within* the significant length is not a 5.1 violation,
/// however similar it looks — that is D4.5's business. Without this the check
/// could pass the test above by reporting every pair of external names.
#[test]
fn two_files_whose_external_identifiers_are_actually_distinct_are_left_alone() {
    let dir = scratch("5-1-clean");
    write(&dir, "a.c", "int parse_header(void) { return 0; }\n");
    write(&dir, "b.c", "int parse_body(void) { return 1; }\n");

    assert!(
        !numbers_over(&dir).contains("5.1"),
        "`parse_header` and `parse_body` differ in the second character"
    );
}

/// D4.5: identifiers in the same name space must be typographically unambiguous.
///
/// `lookup1` and `l00kup1` are the pair the single-file fixture uses; here they
/// are external definitions in different files, which is the case the guideline
/// is about — a reader confusing two names that never appear together.
#[test]
fn two_files_whose_identifiers_are_typographically_ambiguous() {
    let dir = scratch("d4-5");
    write(&dir, "a.c", "int lookup1(void) { return 0; }\n");
    write(&dir, "b.c", "int l00kup1(void) { return 1; }\n");

    assert_eq!(scope_of("D4.5"), Scope::System);
    assert!(
        numbers_over(&dir).contains("D4.5"),
        "an ambiguous pair split across two files must produce a finding; the comparison used to \
         be made within one file's identifier list"
    );
}

/// Objects with external linkage are external identifiers, and 5.1 is about
/// external identifiers.
#[test]
fn two_files_whose_global_variables_collide_at_link_time() {
    let dir = scratch("5-1-objects");
    let stem = "g".repeat(31);
    write(&dir, "a.c", &format!("int {stem}1;\nint a(void) {{ return 0; }}\n"));
    write(&dir, "b.c", &format!("int {stem}2;\nint b(void) {{ return 1; }}\n"));

    assert!(
        numbers_over(&dir).contains("5.1"),
        "two globals a conforming linker cannot tell apart must produce a finding"
    );
}

/// And a `static` global is invisible to the linker, like a `static` function.
#[test]
fn two_static_globals_with_the_same_name_are_not_a_collision() {
    let dir = scratch("5-1-static-objects");
    write(&dir, "a.c", "static int state;\nint a(void) { return state; }\n");
    write(&dir, "b.c", "static int state;\nint b(void) { return state; }\n");

    let found = numbers_over(&dir);
    assert!(!found.contains("5.1"), "internal linkage collides with nothing");
    assert!(!found.contains("D4.5"));
}

/// Function-pointer objects, which the first version of this pass refused.
///
/// `int (*handler)(void);` is an external identifier a linker sees like any
/// other. `cstruct::parse_objects` used to skip anything containing a
/// parenthesis, which removed every function declaration by one rule and every
/// function-pointer object with it; it now reads the declarator.
#[test]
fn two_files_whose_function_pointer_objects_collide_at_link_time() {
    let dir = scratch("5-1-fnptr");
    let stem = "h".repeat(31);
    write(&dir, "a.c", &format!("int (*{stem}1)(void);\nint a(void) {{ return 0; }}\n"));
    write(&dir, "b.c", &format!("int (*{stem}2)(void);\nint b(void) {{ return 1; }}\n"));

    assert!(
        numbers_over(&dir).contains("5.1"),
        "a pointer to a function is still an object with external linkage"
    );
}

/// Why both stay `partial` even with a real declarator parser.
///
/// The parser refuses what it cannot read rather than guessing, and two of those
/// refusals hide external identifiers. A declarator carrying an attribute —
/// `int x __attribute__((unused));` — is refused because two names in a row
/// cannot both belong to one object declarator, which is also the rule that
/// keeps a macro invocation with no semicolon from being read as a declaration.
/// Nothing here expands macros, so the two cases are indistinguishable.
///
/// A clean 5.1 result therefore still is not evidence of conformance, and saying
/// `native` would claim it is. This states the remaining gap rather than leaving
/// it to be rediscovered.
#[test]
fn the_remaining_gap_is_declarators_carrying_something_unreadable() {
    let dir = scratch("5-1-attr");
    let stem = "k".repeat(31);
    write(
        &dir,
        "a.c",
        &format!("int {stem}1 __attribute__((unused));\nint a(void) {{ return 0; }}\n"),
    );
    write(
        &dir,
        "b.c",
        &format!("int {stem}2 __attribute__((unused));\nint b(void) {{ return 1; }}\n"),
    );

    assert!(
        !numbers_over(&dir).contains("5.1"),
        "if attributed declarators are now read, replace this test with a stronger one"
    );
    assert!(
        !is_native("5.1"),
        "a declarator the parser refuses is an external identifier the check cannot see, so a \
         clean 5.1 is not evidence of conformance"
    );
    assert!(!is_native("D4.5"), "and D4.5 compares the same set of names");
}

/// The refusal that keeps the parser usable on real code.
///
/// PX4 writes `PARAM_DEFINE_INT32(TEST_1, 2);` at file scope. Read as a
/// declaration it declares an object called `TEST_1`, which then collides with
/// `TEST_I` in another file under D4.5 — a finding against code that has done
/// nothing wrong. A parenthesised declarator has to contain a declarator;
/// `(TEST_1, 2)` is a parameter list.
#[test]
fn a_macro_invocation_at_file_scope_is_not_an_object() {
    let dir = scratch("5-1-macro");
    write(&dir, "a.c", "PARAM_DEFINE_INT32(TEST_1, 2);\nint a(void) { return 0; }\n");
    write(&dir, "b.c", "PARAM_DEFINE_INT32(TEST_I, 3);\nint b(void) { return 1; }\n");

    let found = numbers_over(&dir);
    assert!(!found.contains("D4.5"), "`TEST_1` and `TEST_I` are macro arguments, not identifiers");
    assert!(!found.contains("5.1"));
}
