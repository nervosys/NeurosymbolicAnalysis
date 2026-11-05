//! The authoritative list of guidelines the native engines actually implement.
//!
//! This module exists to make one specific lie impossible. A catalogue entry
//! marked `native` or `partial` claims that a default run exercises the
//! guideline; if no check exists behind that claim, a clean report silently
//! reads as conformance. The test at the bottom of this file fails the build if
//! the catalogue and the implementation ever drift apart, in either direction.

use sda_rules::{Catalog, Coverage, Standard};
use std::collections::BTreeSet;

/// A guideline number, as the standard writes it.
pub type CheckId = &'static str;

/// MISRA C:2023 guidelines implemented by [`crate::cstatic::CStaticAnalyzer`].
pub const IMPLEMENTED_C: &[CheckId] = &[
    // Directives. D1.1 and D4.1 are deliberately absent: the engine reports
    // multi-character constants and high complexity under its own
    // `SDA-C-*` identifiers, because neither observation establishes anything
    // about the directive itself, which is a documentation obligation.
    "D4.2", "D4.3", "D4.4", "D4.5", "D4.6", "D4.9", "D4.10", "D4.12",
    // Unused code
    "2.5", "2.6",
    // Comments
    "3.1", "3.2",
    // Character sets
    "4.1", "4.2",
    // Identifiers
    "5.1", "5.4", "5.5",
    // Types
    "6.2", "6.3",
    // Literals
    "7.1", "7.3", "7.6",
    // Declarations
    "8.2", "8.10", "8.11", "8.14", "8.16", "8.17",
    // Pointer conversions
    "11.9", "11.10",
    // Expressions
    "12.1", "12.3",
    // Side effects
    "13.3", "13.4", "13.6",
    // Control statement expressions
    "14.2", "14.3",
    // Control flow
    "15.1", "15.2", "15.4", "15.5", "15.6", "15.7",
    // Switches
    "16.1", "16.2", "16.3", "16.4", "16.5", "16.6",
    // Functions
    "17.1", "17.2", "17.6", "17.10",
    // Pointers and arrays
    "18.5",
    // Overlapping storage
    "19.2",
    // Preprocessing
    "20.1", "20.2", "20.3", "20.4", "20.5", "20.7", "20.10", "20.11", "20.13", "20.14",
    // Standard libraries
    "21.1", "21.2", "21.3", "21.4", "21.5", "21.6", "21.7", "21.8", "21.9", "21.10", "21.11",
    "21.12", "21.21", "21.24", "21.25",
];

/// MISRA C++:2023 guidelines implemented by the native C++ checker. The C++
/// catalogue is partial, so this list is correspondingly short; each entry is
/// reported against its clause until an authoritative list is imported.
pub const IMPLEMENTED_CPP: &[CheckId] = &[
    "5.7.1", "5.7.2", "5.13.1", "5.13.2", "8.2.1", "8.2.2", "8.2.3", "9.4.1", "9.4.2", "9.4.3",
    "9.6.1", "11.3.1", "12.2.1", "19.0.1", "19.3.1", "19.6.1", "21.6.1", "21.10.1", "21.10.2",
    "24.5.1", "30.0.1",
];

/// Rust 2024 profile rules implemented by [`crate::rstatic::RustStaticAnalyzer`].
pub const IMPLEMENTED_RUST: &[CheckId] = &[
    "UNSAFE.1", "UNSAFE.2", "UNSAFE.3", "UNSAFE.4", "PANIC.1", "PANIC.2", "FFI.1", "ED2024.1",
    "ED2024.3", "ED2024.4", "ED2024.5", "CONC.1", "EMB.1", "DEP.2", "DEP.3", "MODEL.1", "MODEL.3",
];

/// Implemented guidelines for a standard.
pub fn implemented(standard: Standard) -> &'static [CheckId] {
    match standard {
        Standard::MisraC2023 => IMPLEMENTED_C,
        Standard::MisraCpp2023 => IMPLEMENTED_CPP,
        Standard::Rust2024 => IMPLEMENTED_RUST,
    }
}

/// Guidelines the catalogue claims a default run exercises but for which no
/// check exists. Always empty in a shipped build; the test below enforces it.
pub fn claimed_but_missing(standard: Standard) -> Vec<String> {
    let catalog = Catalog::load(standard);
    let have: BTreeSet<&str> = implemented(standard).iter().copied().collect();
    catalog
        .rules()
        .into_iter()
        .filter(|r| r.coverage.checked_by_default() && !have.contains(r.number.as_str()))
        .map(|r| r.number.clone())
        .collect()
}

/// Checks that exist but whose catalogue entry does not admit they run. Also
/// always empty: it means a run is doing work nobody is told about.
pub fn implemented_but_unclaimed(standard: Standard) -> Vec<String> {
    let catalog = Catalog::load(standard);
    implemented(standard)
        .iter()
        .filter(|n| match catalog.get(n) {
            Some(r) => !r.coverage.checked_by_default(),
            None => true,
        })
        .map(|n| n.to_string())
        .collect()
}

/// How many guidelines of each standard the native engines cover.
pub fn coverage_summary() -> Vec<(Standard, usize, usize)> {
    Standard::all()
        .iter()
        .map(|s| {
            let catalog = Catalog::load(*s);
            let native = catalog.by_coverage(Coverage::Native).len();
            (*s, native, catalog.len())
        })
        .collect()
}

/// A snippet that must make a given guideline fire.
///
/// These exist because a list of strings can lie. `IMPLEMENTED_C` claiming a
/// check exists proves nothing on its own — the C++ analyzer once passed every
/// list-based test while emitting no findings at all, because its checks named
/// MISRA C numbers that its catalogue does not contain. A fixture that must
/// produce a finding cannot be satisfied by bookkeeping.
pub struct Fixture {
    pub rule: CheckId,
    pub file: &'static str,
    pub source: &'static str,
}

const fn fx(rule: CheckId, file: &'static str, source: &'static str) -> Fixture {
    Fixture { rule, file, source }
}

/// Fixtures for the MISRA C checks.
pub const C_FIXTURES: &[Fixture] = &[
    fx("D4.2", "a.c", "void f(void) { asm(\"nop\"); g(); h(); }\n"),
    fx("D4.3", "a.c", "void f(void) { int a = 1; asm(\"nop\"); g(a); h(a); }\n"),
    fx("D4.4", "a.c", "/* total = compute(x); */\nint f(void) { return 0; }\n"),
    fx("D4.5", "a.c", "int lookup1(void) { return 0; }\nint l00kup1(void) { return 1; }\n"),
    fx("D4.6", "a.c", "int f(void) { return 0; }\n"),
    fx("D4.9", "a.c", "#define SQUARE(x) ((x) * (x))\n"),
    fx("D4.10", "a.h", "int f(void);\n"),
    fx("D4.12", "a.c", "void f(void) { void *p = malloc(8); (void)p; }\n"),
    fx("D4.12", "a.c", "#include <stdlib.h>\nvoid *(*alloc)(size_t) = malloc;\n"),
    fx("2.5", "a.c", "#define NEVER_USED 1\nint f(void) { return 0; }\n"),
    fx("2.6", "a.c", "void f(void) { done: return; }\n"),
    fx("3.1", "a.c", "/* outer /* inner */\nint x;\n"),
    fx("3.2", "a.c", "// spliced \\\nint dropped;\nint kept;\n"),
    fx("4.1", "a.c", "const char *s = \"\\1234\";\n"),
    fx("4.2", "a.c", "??=define X 1\n"),
    fx("5.1", "a.c", "int aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1(void) { return 0; }\nint aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2(void) { return 1; }\n"),
    // Sixty-three characters is the significant length for a *macro* name — the
    // external-identifier limit of thirty-one is 5.1's, not this rule's — so
    // these two agree everywhere the standard guarantees a compiler looks.
    fx("5.4", "a.c", "#define AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1 1\n#define AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2 2\n"),
    // The macro name is exactly 63 characters — the significant length — so the
    // identifier collides with it despite being spelled differently.
    fx(
        "5.5",
        "a.c",
        "#define VALUE_THAT_IS_QUITE_LONG_INDEED_AND_THEN_SOME_MORE_TO_REACH_SIX 1\nint VALUE_THAT_IS_QUITE_LONG_INDEED_AND_THEN_SOME_MORE_TO_REACH_SIXX(void) { return 0; }\n",
    ),
    fx("6.2", "a.c", "struct S { signed int flag : 1; };\n"),
    fx("6.3", "a.c", "union U { unsigned int f : 2; };\n"),
    fx("7.1", "a.c", "int x = 0777;\n"),
    fx("7.3", "a.c", "long x = 100l;\n"),
    fx("7.6", "a.c", "int x = INT8_C(1);\n"),
    fx("8.2", "a.c", "int f() { return 0; }\n"),
    fx("8.10", "a.c", "inline int f(void) { return 0; }\n"),
    fx("8.11", "a.c", "extern int table[];\n"),
    fx("8.14", "a.c", "void f(int * restrict p) { (void)p; }\n"),
    fx("8.14", "a.c", "void f(int *__restrict__ p) { (void)p; }\n"),
    fx("8.16", "a.c", "alignas(0) int x;\n"),
    fx("8.17", "a.c", "alignas(4) alignas(8) int x;\n"),
    fx("11.9", "a.c", "int *p = (void *)0;\n"),
    fx("11.10", "a.c", "_Atomic(void) x;\n"),
    fx("12.1", "a.c", "void f(void) { if (a && b || c) { g(); } }\n"),
    fx("12.3", "a.c", "void f(void) { if (a, b) { g(); } }\n"),
    fx("12.3", "a.c", "int f(int a) { int x; x = (a = 1, a + 2); return x; }\n"),
    fx("12.3", "a.c", "void f(int a) { int x; x = 1, x = a; (void)x; }\n"),
    fx("13.3", "a.c", "void f(void) { x = y++ + g(); }\n"),
    fx("13.3", "a.c", "unsigned mask; unsigned arr[4]; void f(int i) { mask |= arr[i++]; }\n"),
    fx("13.4", "a.c", "void f(void) { if (x = g()) { h(); } }\n"),
    fx("13.4", "a.c", "int f(int n) { if ((n -= 1) > 0) { return 1; } return 0; }\n"),
    fx("13.4", "a.c", "int next(void); void f(void) { int n = 0; do { n = 1; } while (n = next()); }\n"),
    fx("13.6", "a.c", "void f(void) { int n = sizeof(g()); (void)n; }\n"),
    fx("13.6", "a.c", "int next(void); unsigned long f(void) { return sizeof next(); }\n"),
    fx("13.6", "a.c", "unsigned long f(int a) { return sizeof(a |= 1); }\n"),
    fx("14.2", "a.c", "void f(void) { for (i = 0, j = 0; i < n; i++) { g(); } }\n"),
    fx("14.3", "a.c", "void f(void) { if (0) { g(); } else { h(); } }\n"),
    fx("15.1", "a.c", "void f(void) { goto done; done: return; }\n"),
    fx("15.2", "a.c", "void f(void)\n{\nback:\n    g();\n    goto back;\n}\n"),
    fx("15.4", "a.c", "void f(void) { while (a) { if (b) { break; } if (c) { break; } } }\n"),
    fx("15.4", "a.c", "void f(int x, int y) { for (;;) { do { y++; } while (y < 10); if (x) { break; } if (y > 3) { break; } } }\n"),
    fx("15.4", "a.c", "void f(int x, int y, int a) { for (;;) { while (a) y++; if (x) { break; } if (y > 3) { break; } } }\n"),
    fx("15.5", "a.c", "int f(int a) { if (a) { return 1; } return 0; }\n"),
    fx("15.6", "a.c", "void f(void) { if (a) g(); }\n"),
    fx("15.7", "a.c", "void f(void) { if (a) { g(); } else if (b) { h(); } }\n"),
    fx("16.1", "a.c", "void f(int x) { switch (x) { g(); case 1: break; default: break; } }\n"),
    fx("16.2", "a.c", "void f(int x) { switch (x) { case 1: { case 2: break; } default: break; } }\n"),
    fx("16.2", "a.c", "void g(void); void f(int a) { switch (a) { case 1: switch (a) { default: break; } { case 3: g(); break; } default: break; } }\n"),
    fx("16.3", "a.c", "void f(int x) { switch (x) { case 1: g(); case 2: break; default: break; } }\n"),
    fx("16.3", "a.c", "void g(int); void f(int x, int c) { switch (x) { case 1: if (c) { break; } g(1); case 2: g(2); break; default: break; } }\n"),
    fx("16.3", "a.c", "void g(int); void f(int a, int b){ switch(a){ case 1: switch(b){ case 2: g(2); case 3: g(3); break; default: break; } break; default: break; } }\n"),
    fx("16.4", "a.c", "void f(int x) { switch (x) { case 1: break; case 2: break; } }\n"),
    fx("16.5", "a.c", "void f(int x) { switch (x) { case 1: break; default: break; case 2: break; } }\n"),
    fx("16.6", "a.c", "void f(int x) { switch (x) { default: break; } }\n"),
    fx("17.1", "a.c", "void f(void) { va_list ap; (void)ap; }\n"),
    fx("17.2", "a.c", "int f(int n) { return f(n - 1); }\n"),
    fx("17.6", "a.c", "void f(int a[static 4]) { (void)a; }\n"),
    fx("17.6", "a.c", "void f(int a[const static 10]);\n"),
    fx("17.10", "a.c", "_Noreturn int f(void) { for (;;) { } }\n"),
    fx("18.5", "a.c", "int ***p;\n"),
    fx("18.5", "a.c", "int *const *const *p;\n"),
    fx("19.2", "a.c", "union U { int i; float f; };\n"),
    fx("20.1", "a.c", "int x;\n#include <stddef.h>\n"),
    fx("20.2", "a.c", "#include \"dir\\file.h\"\n"),
    fx("20.3", "a.c", "#include MACRO_HEADER\n"),
    fx("20.4", "a.c", "#define while for\n"),
    fx("20.5", "a.c", "#undef SOMETHING\n"),
    fx("20.7", "a.c", "#define ADD(a, b) a + b\n"),
    fx("20.10", "a.c", "#define STR(x) #x\n"),
    fx("20.11", "a.c", "#define GLUE(a, b) #a ## b\n"),
    fx("20.13", "a.c", "#nonsense here\n"),
    fx("20.14", "a.c", "#endif\n"),
    fx("21.1", "a.c", "#define __RESERVED 1\n"),
    fx("21.2", "a.c", "int __reserved_name(void) { return 0; }\n"),
    fx("21.3", "a.c", "void f(void) { void *p = malloc(8); (void)p; }\n"),
    fx("21.4", "a.c", "void f(void) { setjmp(env); }\n"),
    fx("21.5", "a.c", "void f(void) { signal(1, 0); }\n"),
    fx("21.6", "a.c", "void f(void) { printf(\"x\"); }\n"),
    fx("21.6", "a.c", "void f(void) { fputs(\"x\", 0); }\n"),
    fx("21.7", "a.c", "void f(void) { int n = atoi(s); (void)n; }\n"),
    fx("21.8", "a.c", "void f(void) { exit(1); }\n"),
    fx("21.9", "a.c", "void f(void) { qsort(a, 1, 1, c); }\n"),
    fx("21.10", "a.c", "void f(void) { time(0); }\n"),
    fx("21.11", "a.c", "#include <tgmath.h>\n"),
    fx("21.12", "a.c", "void f(void) { feclearexcept(0); }\n"),
    fx("21.21", "a.c", "void f(void) { system(\"ls\"); }\n"),
    fx("21.24", "a.c", "void f(void) { int n = rand(); (void)n; }\n"),
    fx("21.25", "a.c", "void f(void) { atomic_load_explicit(&x, memory_order_relaxed); }\n"),
    // A return type that is not exactly `void`, with a `*` after the specifiers.
    fx("17.10", "a.c", "_Noreturn void *die(void) { for (;;) { } }\n"),
    // A bit-field in a union whose width is a macro, or a parenthesised number.
    fx("6.3", "a.c", "#define WIDTH 2\nunion U { unsigned int f : WIDTH; };\n"),
    fx("6.3", "a.c", "union U { unsigned int f : (2); };\n"),
    // Parameters that are a typedef name, a tag with no name, or a prototype
    // inside a function body.
    fx("8.2", "a.c", "typedef unsigned char byte_t;\nvoid g(byte_t);\n"),
    fx("8.2", "a.c", "struct point { int x; };\nvoid h(struct point);\n"),
    fx("8.2", "a.c", "void g(void) {\n  int older(int, int);\n  older(1, 2);\n}\n"),
    // An old-style (K&R) definition, with an identifier list and declarations.
    fx("8.2", "a.c", "int add(a, b) int a; int b; { return a + b; }\n"),
    // Consecutive labels with nothing between them are one clause, which is one
    // clause too few for a switch.
    fx("16.6", "a.c", "void f(int x) { switch (x) { case 1: case 2: g(); break; } }\n"),
    fx("17.1", "a.c", "void f(void) { __builtin_va_list ap; (void)ap; }\n"),
    // A label used by a goto in another function is still unused here.
    fx("2.6", "a.c", "void a(void) { unused: return; }\nvoid b(void) { goto unused; unused: return; }\n"),
    fx("20.14", "a.c", "#ifdef A\n#else\n#else\n#endif\n"),
    fx("20.14", "a.c", "#if A\n#else\n#elif B\n#endif\n"),
    fx("8.16", "a.c", "alignas(0u) int x;\n"),
    // Only a literal `#if 0` is decided. `#if FOO` may be live, so its code counts.
    fx("20.1", "a.c", "#if FOO\nint x;\n#endif\n#include <stddef.h>\n"),
    // Review of the batch above.
    fx("6.3", "a.c", "union U { struct { struct { unsigned int a : 2; }; }; int b; };\n"),
    fx("15.2", "a.c", "void f(void) { done: ; goto done; }\n"),
    fx("17.10", "a.c", "__attribute__((noreturn)) int die(void);\n"),
    fx("20.10", "a.c", "#define STR(x) %:x\n"),
    fx("20.10", "a.c", "#define CAT(a, b) a %:%: b\n"),
    // The fifth pass.
    fx("8.11", "a.c", "extern __attribute__((aligned(16))) const struct table_entry_with_long_name entries[];\n"),
    fx("13.6", "a.c", "unsigned long f(int i, int *a) { return sizeof a[i++]; }\n"),
    fx("15.4", "a.c", "void g(void); void f(int x) { while (x) { if (x > 2) { break; } switch (x) { case 1: goto out; default: break; } g(); } out: ; }\n"),
    fx("15.4", "a.c", "void f(int x) { for (;;) { while (x) { goto out; } break; } out: ; }\n"),
    fx("D4.12", "a.c", "void *(*alloc)(unsigned long) = &malloc;\n"),
    fx("D4.12", "a.c", "struct ops o = { malloc };\n"),
    fx("21.6", "a.c", "void f(void) { (printf)(\"x\"); }\n"),
    fx("21.10", "a.c", "void f(void) { (time)(0); }\n"),
    fx("21.12", "a.c", "void f(void) { (fetestexcept)(0); }\n"),
    fx("17.10", "a.c", "__attribute__((noreturn, cold)) int die(void);\n"),
];

/// Fixtures for the MISRA C++ checks.
pub const CPP_FIXTURES: &[Fixture] = &[
    fx("5.7.1", "a.cpp", "/* outer /* inner */\nint x;\n"),
    fx("5.7.2", "a.cpp", "// spliced \\\nint dropped;\nint kept;\n"),
    fx("5.13.1", "a.cpp", "int x = 0777;\n"),
    fx("5.13.2", "a.cpp", "long x = 100l;\n"),
    fx("8.2.1", "a.cpp", "void f(void) { int *q = (int *)p; (void)q; }\n"),
    fx("8.2.2", "a.cpp", "void f(void) { int *q = reinterpret_cast<int *>(p); (void)q; }\n"),
    fx("8.2.3", "a.cpp", "void f(void) { int *q = const_cast<int *>(p); (void)q; }\n"),
    fx("9.4.1", "a.cpp", "void f(void) { if (a) g(); }\n"),
    fx("9.4.2", "a.cpp", "void f(int x) { switch (x) { case 1: g(); case 2: break; default: break; } }\n"),
    fx("9.4.3", "a.cpp", "void f(int x) { switch (x) { case 1: break; case 2: break; } }\n"),
    fx("9.6.1", "a.cpp", "void f(void) { goto done; done: return; }\n"),
    fx("11.3.1", "a.cpp", "int ***p;\n"),
    fx("12.2.1", "a.cpp", "union U { int i; float f; };\n"),
    fx("19.0.1", "a.cpp", "#define SQUARE(x) ((x) * (x))\n"),
    fx("19.3.1", "a.cpp", "#define STR(x) #x\n"),
    fx("19.6.1", "a.hpp", "int f(void);\n"),
    fx("21.6.1", "a.cpp", "void f(void) { void *p = malloc(8); (void)p; }\n"),
    fx("21.10.1", "a.cpp", "void f(void) { setjmp(env); }\n"),
    fx("21.10.2", "a.cpp", "void f(void) { signal(1, 0); }\n"),
    fx("24.5.1", "a.cpp", "void f(void) { strcpy(dst, src); }\n"),
    fx("30.0.1", "a.cpp", "void f(void) { printf(\"x\"); }\n"),
];

/// Fixtures for the Rust profile checks.
pub const RUST_FIXTURES: &[Fixture] = &[
    fx("UNSAFE.1", "src/lib.rs", "fn f() { unsafe { g(); } }\n"),
    fx("UNSAFE.2", "src/lib.rs", "unsafe fn f() { g(); }\n"),
    fx("UNSAFE.4", "src/lib.rs", "static mut COUNT: u32 = 0;\n"),
    fx("PANIC.1", "src/lib.rs", "fn f() { o.unwrap(); }\n"),
    fx("PANIC.2", "src/lib.rs", "fn f() { panic!(\"no\"); }\n"),
    fx("FFI.1", "src/lib.rs", "unsafe extern \"C\" { fn hal(); }\n"),
    fx("ED2024.1", "src/lib.rs", "fn f() { let gen = 1; }\n"),
    fx("ED2024.3", "src/lib.rs", "extern \"C\" { fn hal(); }\n"),
    fx("ED2024.4", "src/lib.rs", "#[no_mangle]\npub fn entry() {}\n"),
    fx("CONC.1", "src/lib.rs", "unsafe impl Send for H {}\n"),
    fx("EMB.1", "src/lib.rs", "#![no_std]\nfn f() -> Vec<u8> { Vec::new() }\n"),
    fx("DEP.2", "build.rs", "fn main() {}\n"),
    fx("MODEL.1", "src/lib.rs", "static W: &[u8] = include_bytes!(\"m.gguf\");\n"),
    fx("MODEL.3", "src/lib.rs", "const P: &str = \"weights.pth\";\n"),
];

/// Rules whose check needs project-level context a single source file cannot
/// provide, and which therefore have a dedicated test elsewhere rather than a
/// fixture here. Kept explicit so the count can never drift silently.
pub const FIXTURE_EXEMPT: &[(CheckId, &str)] = &[
    ("DEP.3", "needs a project directory with a Cargo.toml and no Cargo.lock; \
               covered by rstatic::check_manifest"),
    ("ED2024.5", "needs a Cargo.toml without an edition key; \
                  covered by rstatic::check_manifest"),
    // Moved here when the check moved. It used to fire from a single buffer —
    // any `lib.rs` with no `unsafe` and no `forbid` — so a crate whose root is
    // clean while its modules are not was told to add a crate-wide
    // `#![forbid(unsafe_code)]` that would not compile. A fixture is one file,
    // and one file cannot answer a question about a crate.
    ("UNSAFE.3", "needs a crate directory whose modules can be consulted; covered by \
                  rstatic::check_crate_unsafe_declaration and \
                  unsafe_3_is_a_claim_about_the_crate.rs"),
];

/// A source that *looks* like a violation of `rule` and is not.
///
/// [`Fixture`] proves a check fires. Nothing proved one stays quiet, and a rule
/// that fires on everything passes its fixture. That is not a hypothetical gap:
/// over-reporting is this catalogue's recurring defect — `5.4`/`5.5` comparing
/// 31 significant characters where the standard says 63, `11.9` matching
/// `*revision = 0;` for 28 false positives on PX4, `8.2` reading
/// `PARAM_DEFINE_INT32(...)` as a prototype for 674. Every one was found by
/// running on somebody else's tree, and none by a test.
///
/// `why` is not decoration. A near-miss is only as good as the reason it is
/// conforming, and a reader who cannot reconstruct that reason cannot tell a
/// fixed defect from a silenced check.
pub struct NearMiss {
    pub rule: CheckId,
    pub file: &'static str,
    pub source: &'static str,
    pub why: &'static str,
}

const fn nm(
    rule: CheckId,
    file: &'static str,
    source: &'static str,
    why: &'static str,
) -> NearMiss {
    NearMiss { rule, file, source, why }
}

/// Near-misses for the MISRA C checks.
pub const C_NEAR_MISSES: &[NearMiss] = &[
    nm(
        "5.4",
        "a.c",
        "#define ALPHA_BETA_GAMMA_DELTA_EPSILON_ZETA_ETA_THETA_A 1\n\
         #define ALPHA_BETA_GAMMA_DELTA_EPSILON_ZETA_ETA_THETA_B 2\n",
        "the two macro names differ inside 63 significant characters, which is what C99 and \
         later guarantee; comparing 31 is the internal-identifier limit and reports these as \
         a collision that no translation unit has",
    ),
    nm(
        "11.9",
        "a.c",
        "void f(int *p) { *p = 0; }\n",
        "`0` here is an integer assigned through a pointer, not an integer null pointer \
         constant; 11.9 is about the form of a null pointer constant and says nothing about \
         storing zero",
    ),
    nm(
        "8.2",
        "a.c",
        "#define PARAM_DEFINE_INT32(name, value) int name = (value)\n\
         PARAM_DEFINE_INT32(SLNK_RADIO_CHAN, 80);\n",
        "a macro invocation at file scope is not a function declaration; reading it as one \
         is how 674 findings appeared on PX4",
    ),
    nm(
        "13.6",
        "a.c",
        "unsigned long f(int a, int arr[4]) { return sizeof(int) + sizeof a + sizeof(arr[0]); }\n",
        "a type name, a plain object and an element access: none of the three has a side \
         effect for `sizeof` to skip",
    ),
    nm(
        "13.6",
        "a.c",
        "unsigned long f(int a) { return (unsigned long)sizeof(a); }\n",
        "the operand is a plain object, so it has no side effects; 13.6 is about an operand \
         that does",
    ),
    nm(
        "15.5",
        "a.c",
        "int f(int a) {\n  int r = 0;\n  if (a) { r = 1; }\n  return r;\n}\n",
        "one return, and it is the last statement — exactly the form 15.5 asks for",
    ),
    nm(
        "16.3",
        "a.c",
        "void g(int);\nvoid f(int x, int c) {\n  switch (x) {\n    case 1: if (c) { g(1); break; } else { g(3); break; }\n    default: break;\n  }\n}\n",
        "both arms of the `if` end in a break, so no path from case 1 reaches the next clause",
    ),
    nm(
        "16.3",
        "a.c",
        "void g(int);\nvoid f(int a, int b) {\n  switch (a) {\n    case 1:\n      switch (b) {\n        case 2: g(2); break;\n        default: break;\n      }\n      break;\n    default: break;\n  }\n}\n",
        "a switch nested in a clause, with every clause of both switches ending in a break",
    ),
    nm(
        "16.3",
        "a.c",
        "void g(int v) {\n  switch (v) {\n    case 1: h(); break;\n    default: break;\n  }\n}\n",
        "every switch-clause ends in an unconditional break, which is what 16.3 requires",
    ),
    nm(
        "2.6",
        "a.c",
        "void f(int a) {\n  if (a) goto done;\n  h();\ndone:\n  return;\n}\n",
        "the label is the target of a goto, so it is used; 2.6 is about a label nothing \
         jumps to",
    ),
    nm(
        "12.1",
        "a.c",
        "int f(int a, int b, int c) { return ((a * b) + c); }\n",
        "the precedence is written out in parentheses, which is what 12.1 asks for. Note that \
         12.1 is `partial` — it checks a couple of operator pairs, not the open-ended \
         guideline — so this case proves less than the others here",
    ),
    nm(
        "21.6",
        "a.c",
        "int my_printf(const char *s);\nvoid f(void) { (void)my_printf(\"x\"); }\n",
        "a project function whose name merely contains a library function's name is not the \
         library function; 21.6 names the <stdio.h> functions",
    ),
    nm(
        "D4.6",
        "a.c",
        "#include <stdint.h>\nint32_t f(void) { return 0; }\n",
        "a width-explicit typedef is exactly what D4.6 asks for in place of a basic type",
    ),
    nm(
        "3.1",
        "a.c",
        "/* an ordinary block comment */\nint f(void) { return 0; }\n",
        "no comment marker appears inside the comment, so there is nothing ambiguous to \
         report",
    ),
    nm(
        "7.1",
        "a.c",
        "int zero = 0;\nunsigned int mask = 0x1FU;\n",
        "`0` is the one integer constant the guideline exempts — it is spelled the same in \
         every base — and a hexadecimal constant is not an octal one",
    ),
    nm(
        "7.3",
        "a.c",
        "long total = 100L;\nint little = 1;\n",
        "the suffix is an uppercase `L`, and `little` is an identifier that merely contains \
         the letter; 7.3 is about a lowercase `l` used as a literal suffix",
    ),
    nm(
        "D4.4",
        "a.c",
        "/* Compute the running total before the next sample arrives. */\nint f(void) { return 0; }\n",
        "prose that mentions what the code does is not commented-out code; a check that \
         cannot tell them apart makes every explanatory comment a finding",
    ),
    nm(
        "D4.9",
        "a.c",
        "#define STRINGIFY(x) #x\nconst char *s = STRINGIFY(abc);\n",
        "a macro that stringises its argument cannot be written as a function, so the \
         guideline's `where a function would serve` does not apply",
    ),
    nm(
        "D4.9",
        "a.c",
        "#define ZERO_OF(T) ((T){0})\nint f(void) { return ZERO_OF(int); }\n",
        "the parameter is a type, naming a compound literal, and a function cannot take a \
         type as an argument",
    ),
    nm(
        "2.5",
        "a.c",
        "#define LIMIT 10\nint f(void) { return LIMIT; }\n",
        "the macro is used, and 2.5 is about one that is not",
    ),
    nm(
        "13.4",
        "a.c",
        "int f(int n) {\n  n -= 1;\n  if ((n) > 0) { return 1; }\n  return 0;\n}\n",
        "the compound assignment is a statement of its own, and the condition only compares; \
         13.4 is about an assignment whose value is used",
    ),
    nm(
        "13.4",
        "a.c",
        "void f(int *a, int b) { *a = b; }\n",
        "the assignment stands as its own statement; 13.4 is about *using* the value an \
         assignment produces",
    ),
    nm(
        "15.7",
        "a.c",
        "int f(int a) {\n  if (a == 1) { return 1; }\n  else if (a == 2) { return 2; }\n  else { return 0; }\n}\n",
        "the `if`/`else if` chain ends in an `else`, which is exactly what 15.7 requires",
    ),
    nm(
        "16.4",
        "a.c",
        "void g(int v) {\n  switch (v) {\n    case 1: h(); break;\n    default: break;\n  }\n}\n",
        "the switch has a `default` label, which is what 16.4 asks for",
    ),
    nm(
        "15.1",
        "a.c",
        "int f(int a) {\n  int r = 0;\n  if (a) { r = 1; }\n  return r;\n}\n",
        "there is no `goto` here at all",
    ),
    nm(
        "21.3",
        "a.c",
        "int allocate_slot(void);\nvoid f(void) { (void)allocate_slot(); }\n",
        "a project function whose name contains `alloc` is not `malloc`; 21.3 names the \
         <stdlib.h> allocation functions",
    ),
    nm(
        "12.3",
        "a.c",
        "void g(int, int);\nenum E { E0, E1 };\n__attribute__((section(\".data\"), used)) int z;\nint f(int a, int b) {\n  int x = 0, y = 1;\n  int arr[2] = {a, b};\n  g(a, b);\n  for (int i = 0, j = 0; i < 1; i++) { x += j; }\n  return x + y + arr[0];\n}\n",
        "the commas separate declarators, arguments and initialisers; 12.3 is about the comma \
         operator, which none of these is",
    ),
    nm(
        "12.3",
        "a.c",
        "int g(int x, int y);\nint f(void) {\n  int a = 1, b = 2;\n  return g(a, b);\n}\n",
        "the commas separate declarators and arguments; 12.3 is about the comma *operator*, \
         which sequences two expressions and yields the second",
    ),
    nm(
        "21.1",
        "a.c",
        "#define MY_LIMIT 10\n#define buffer_size_ 32\nint f(void) { return MY_LIMIT; }\n",
        "neither name is reserved: a reserved identifier begins with an underscore followed \
         by an uppercase letter or a second underscore, or is a library name. A trailing \
         underscore reserves nothing",
    ),
    nm(
        "20.1",
        "a.c",
        "#include <stddef.h>\n#include <stdint.h>\n\nint32_t f(void) { return 0; }\n",
        "the includes come before any declaration, which is what 20.1 asks for; one include \
         following another is not a violation",
    ),
    nm(
        "D4.10",
        "a.h",
        "#ifndef A_H\n#define A_H\nint f(void);\n#endif\n",
        "the header has the include guard D4.10 requires",
    ),
    nm(
        "18.5",
        "a.c",
        "int *const *const p;\n",
        "two levels of pointer nesting, with qualifiers between them, is within the limit 18.5 \
         sets",
    ),
    nm(
        "18.5",
        "a.c",
        "int f(int **p) { return **p; }\n",
        "two levels of pointer nesting is what 18.5 permits; it objects to more than two",
    ),
    nm(
        "19.2",
        "a.c",
        "struct S { int a; int b; };\nint f(struct S s) { return s.a + s.b; }\n",
        "a struct gives every member its own storage; 19.2 is about a union, where they \
         overlap",
    ),
    nm(
        "6.2",
        "a.c",
        "struct S { unsigned int flag : 1; };\n",
        "a single-bit bit-field declared `unsigned` has room for its value; 6.2 objects to a \
         single-bit *signed* one, which can only hold 0 and -1",
    ),
    nm(
        "17.2",
        "a.c",
        "int helper(int a);\nint f(int a) { return helper(a); }\n",
        "`f` calls a different function, not itself; 17.2 is about recursion",
    ),
    nm(
        "14.3",
        "a.c",
        "int f(int a) {\n  if (a > 0) { return 1; }\n  return 0;\n}\n",
        "the condition depends on a parameter, so it is not invariant",
    ),
    nm(
        "13.3",
        "a.c",
        "unsigned mask;\nunsigned arr[4];\nvoid f(int i) {\n  mask |= arr[i];\n  arr[i]++;\n}\n",
        "each statement carries one side effect, so no two are unsequenced within one \
         expression",
    ),
    nm(
        "13.3",
        "a.c",
        "void f(int *a) {\n  int i = 0;\n  i++;\n  *a = i;\n}\n",
        "the increment is a statement of its own, so it is the only side effect in its full \
         expression; 13.3 is about one that shares an expression with others",
    ),
    nm(
        "3.2",
        "a.c",
        "// an ordinary line comment\nint f(void) { return 0; }\n",
        "the comment ends at the newline; 3.2 is about a `//` comment spliced into the line \
         below by a trailing backslash",
    ),
    nm(
        "D4.5",
        "a.c",
        "int lookup(void) { return 0; }\nint search(void) { return 1; }\n",
        "the two names share no confusable spelling; D4.5 is about a pair that differ only \
         by characters a reader misreads, such as `l` for `1`",
    ),
    nm(
        "21.3",
        "a.c",
        "struct ops { void (*free)(void *); };\nvoid f(struct ops *o, void *p) { o->free(p); }\n",
        "`o->free(p)` calls through a driver op table, not `<stdlib.h>`'s `free`. Function \
         pointers named after the operation they perform are how most embedded C is \
         structured, so a check that reads the identifier and not what precedes it reports \
         the shape of the codebase",
    ),
    nm(
        "21.6",
        "a.c",
        "struct logger { void (*printf)(const char *); };\nvoid f(struct logger *l) { l->printf(\"x\"); }\n",
        "the same shape for the I/O guideline: a `printf` member of a project logger is not \
         `<stdio.h>`'s",
    ),
    nm(
        "D4.2",
        "a.c",
        "void asm_delay(unsigned int n);\nvoid f(void) { asm_delay(10U); }\n",
        "a function whose name merely begins with `asm` is not an assembly statement; D4.2 \
         is about assembly in the source",
    ),
    nm(
        "14.2",
        "a.c",
        "int f(unsigned int n) {\n  unsigned int i;\n  for (i = 0U; i < n; ++i) { }\n  return 0;\n}\n",
        "the loop counter is initialised, tested and incremented once each, which is the \
         well-formed `for` 14.2 describes",
    ),
    nm(
        "8.11",
        "a.c",
        "extern int table[10];\nint f(void) { return table[0]; }\n",
        "the external array declaration states its size, which is what 8.11 asks for",
    ),
    nm(
        "21.21",
        "a.c",
        "void system_init(void);\nvoid f(void) { system_init(); }\n",
        "a project function whose name begins with `system` is not `<stdlib.h>`'s `system`; \
         21.21 names that one function",
    ),
    nm(
        "11.10",
        "a.c",
        "#include <stdatomic.h>\n_Atomic int counter;\nint f(void) { return counter; }\n",
        "`int` is a complete type; 11.10 is about `_Atomic` applied to the *incomplete* type \
         `void`, which the language forbids outright",
    ),
    nm(
        "17.6",
        "a.c",
        "void f(int a[10], int b[const 4]);\n",
        "qualifiers without `static` promise nothing about the caller, so the array parameters \
         are the form 17.6 permits",
    ),
    nm(
        "17.6",
        "a.c",
        "int f(int a[10]) { return a[0]; }\n",
        "the array parameter states a size and no `static` appears between the brackets, \
         which is the form 17.6 permits",
    ),
    nm(
        "15.4",
        "a.c",
        "void f(int x, int y) {\n  for (;;) {\n    do { y++; } while (y < 10);\n    if (x) { break; }\n  }\n}\n",
        "one `break` leaves the loop; the `while` that closes the `do` is the loop's tail, not a \
         second loop",
    ),
    nm(
        "15.4",
        "a.c",
        "int f(unsigned int n) {\n  unsigned int i;\n  for (i = 0U; i < n; ++i) { if (i > 3U) { break; } }\n  return 0;\n}\n",
        "one `break` terminates the loop, and 15.4 permits one; it objects to more than one",
    ),
    nm(
        "15.4",
        "a.c",
        "void f(int x, int a) {\n  for (;;) {\n    while (a) if (x) break;\n    if (x) { break; }\n  }\n}\n",
        "the `break` under the unbraced `while` leaves the `while`, not the `for`; the `for` has one exit",
    ),
    nm(
        "20.4",
        "a.c",
        "#define WHILE_LIMIT 5U\nunsigned int f(void) { return WHILE_LIMIT; }\n",
        "`WHILE_LIMIT` is not a keyword. 20.4 is about a macro that redefines one, which \
         changes what the language means wherever the header reaches",
    ),
    nm(
        "6.3",
        "a.c",
        "#include <stdint.h>\nstruct S { unsigned int flag : 2; };\n",
        "6.3 objects to a bit-field declared as a member of a *union*, where the members \
         overlap. In a struct it has its own storage",
    ),
    nm(
        "6.3",
        "a.c",
        "union U { struct { unsigned int flag : 1; } bits; unsigned int raw; };\n",
        "the bit-field is a member of the named struct `bits`, which is the union's member",
    ),
    nm(
        "6.3",
        "a.c",
        "union U;\nstruct S { union U *p; unsigned int flag : 1; };\n",
        "`union U *p` names a union and opens no body, so `flag` is a struct member",
    ),
    nm(
        "21.3",
        "a.c",
        "#define free(x) release(x)\n#define NOTE \"free(p) is not called\"\n#define R(s) (s)->free(s)\n",
        "a macro's own name, a string and a member call are not uses of the library function",
    ),
    nm(
        "17.10",
        "a.c",
        "_Noreturn void fail(void);\nvoid f(int a) { if (a == 0) { fail(); } }\n",
        "the `_Noreturn` function returns `void`, which is exactly what 17.10 requires",
    ),
    nm(
        "8.16",
        "a.c",
        "#include <stdalign.h>\nalignas(8) static unsigned char buf[16];\n",
        "the alignment is eight, not zero; 8.16 is about a specification of zero",
    ),
    nm(
        "8.17",
        "a.c",
        "#include <stdalign.h>\nalignas(8) static unsigned char buf[16];\n",
        "one alignment specifier appears, and 8.17 objects to more than one",
    ),
    nm(
        "8.17",
        "a.c",
        "alignas(8) static int first;\nalignas(16) static int second;\n",
        "two declarations with one specifier each; 8.17 is about one declaration",
    ),
    nm(
        "D4.12",
        "a.c",
        "struct S { int free_count; void *free; };\nvoid f(struct S *s) {\n  int n = s->free_count;\n  s->free = 0;\n  (void)n;\n}\n",
        "`free_count` is another identifier, and `s->free` is a member of a struct, not the \
         library function",
    ),
    nm(
        "D4.12",
        "a.c",
        "void *pool_alloc(unsigned int n);\nvoid f(void) { (void)pool_alloc(8U); }\n",
        "a fixed-pool allocator written by the project is not dynamic allocation from \
         `<stdlib.h>`; D4.12 is about the library functions whose timing and fragmentation \
         cannot be bounded",
    ),
    nm(
        "8.10",
        "a.c",
        "static inline int f(void) { return 0; }\n",
        "the inline function carries the `static` storage class 8.10 requires",
    ),
    nm(
        "15.6",
        "a.c",
        "void g(void);\nvoid h(void);\nvoid f(int a) { if (a) { g(); } else { h(); } }\n",
        "both arms of the selection statement are compound statements",
    ),
    nm(
        "16.1",
        "a.c",
        "void g(void);\nvoid f(int v) {\n  switch (v) {\n    case 1: g(); break;\n    case 2: g(); break;\n    default: break;\n  }\n}\n",
        "the switch is well-formed: every clause ends in a break and the default is last",
    ),
    nm(
        "16.5",
        "a.c",
        "void g(void);\nvoid f(int v) {\n  switch (v) {\n    case 1: g(); break;\n    case 2: g(); break;\n    default: break;\n  }\n}\n",
        "the default label is last, which is one of the two positions 16.5 permits",
    ),
    nm(
        "16.6",
        "a.c",
        "void g(void);\nvoid f(int v) {\n  switch (v) {\n    case 1: g(); break;\n    case 2: g(); break;\n    default: break;\n  }\n}\n",
        "three switch-clauses, and 16.6 objects to fewer than two",
    ),
    nm(
        "17.1",
        "a.c",
        "int f(int a, int b) { return a + b; }\n",
        "the parameter list is fixed; 17.1 is about the features of <stdarg.h>",
    ),
    nm(
        "20.7",
        "a.c",
        "#define ADD(a, b) ((a) + (b))\nint f(int x) { return ADD(x, 1); }\n",
        "each macro parameter is enclosed in parentheses where it is used, which is exactly \
         what 20.7 asks for",
    ),
    nm(
        "20.13",
        "a.c",
        "#define VERSION 1U\nunsigned int f(void) { return VERSION; }\n",
        "`#define` is a valid preprocessing directive; 20.13 is about a line starting with \
         `#` that is not one",
    ),
    nm(
        "21.2",
        "a.c",
        "void my_memcpy(void *d, const void *s, unsigned int n);\nvoid f(void *d) { my_memcpy(d, d, 1U); }\n",
        "`my_memcpy` is neither a reserved identifier nor a library name; a check matching \
         `memcpy` anywhere in a name would flag every project wrapper around one",
    ),
    nm(
        "21.4",
        "a.c",
        "int my_setjmp(void);\nint f(void) { return my_setjmp(); }\n",
        "a project function whose name contains `setjmp` is not `<setjmp.h>`'s",
    ),
    nm(
        "5.5",
        "a.c",
        "#define LIMIT 10U\nunsigned int boundary_value(void) { return LIMIT; }\n",
        "the identifier and the macro name share no spelling; 5.5 is about an identifier that \
         collides with one within the significant length",
    ),
    // The `21.*` family shares one code path, and the shape that broke it —
    // reading an identifier without looking at what precedes it — broke it for
    // every guideline at once. These hold the whole family to the same standard
    // rather than the two that happened to be written first.
    nm(
        "21.5",
        "a.c",
        "int my_signal(int s);\nint f(void) { return my_signal(1); }\n",
        "a project function whose name contains `signal` is not `<signal.h>`'s",
    ),
    nm(
        "21.7",
        "a.c",
        "int my_atoi(const char *s);\nint f(const char *s) { return my_atoi(s); }\n",
        "a project conversion helper is not `<stdlib.h>`'s `atoi`; 21.7 names that family, \
         whose fault is that they cannot report a failure",
    ),
    nm(
        "21.9",
        "a.c",
        "void *my_bsearch(const void *k);\nvoid f(const void *k) { (void)my_bsearch(k); }\n",
        "a project search routine is not `<stdlib.h>`'s `bsearch`",
    ),
    nm(
        "21.10",
        "a.c",
        "unsigned long my_time(void);\nunsigned long f(void) { return my_time(); }\n",
        "a project clock reading is not one of the standard time and date functions",
    ),
    nm(
        "21.11",
        "a.c",
        "double my_sqrt(double v);\ndouble f(double v) { return my_sqrt(v); }\n",
        "21.11 names the header `<tgmath.h>`, and a project maths helper is not it",
    ),
    nm(
        "21.12",
        "a.c",
        "int my_feclear(int e);\nint f(void) { return my_feclear(0); }\n",
        "a project routine is not `<fenv.h>`'s exception handling",
    ),
    nm(
        "21.24",
        "a.c",
        "unsigned int my_rand(void);\nunsigned int f(void) { return my_rand(); }\n",
        "a project generator is not `<stdlib.h>`'s `rand`",
    ),
    nm(
        "21.25",
        "a.c",
        "#include <stdatomic.h>\natomic_int c;\nint f(void) { return atomic_load_explicit(&c, memory_order_seq_cst); }\n",
        "sequential consistency is the ordering 21.25 requires; it objects to the weaker ones",
    ),
    nm(
        "20.2",
        "a.c",
        "#include <stdint.h>\nint32_t f(void) { return 0; }\n",
        "the header name contains none of the characters whose behaviour in an include is \
         undefined",
    ),
    nm(
        "20.3",
        "a.c",
        "#include <stdint.h>\nint32_t f(void) { return 0; }\n",
        "the `#include` is followed by a `<filename>`, which is one of the two forms 20.3 \
         permits",
    ),
    nm(
        "20.10",
        "a.c",
        "#define PLAIN(a) ((a) + 1)\nint f(int x) { return PLAIN(x); }\n",
        "the replacement list uses neither `#` nor `##`",
    ),
    nm(
        "20.11",
        "a.c",
        "#define PLAIN(a) ((a) + 1)\nint f(int x) { return PLAIN(x); }\n",
        "there is no `#` operator here at all, so nothing can follow one with a `##`",
    ),
    nm(
        "8.14",
        "a.c",
        "void g(void);\nvoid f(char *d, const char *s) { (void)d; (void)s; g(); }\n",
        "no `restrict` qualifier appears. Worth stating plainly because the first attempt at \
         this near-miss *used* `restrict` and was therefore a violation — 8.14 bans the \
         qualifier outright rather than regulating how it is used",
    ),
    nm(
        "5.1",
        "a.c",
        "int aaaaaaaaaaaaaaaaaaaa_one(void);\nint bbbbbbbbbbbbbbbbbbbb_two(void);\n",
        "the two external names differ from their first character, well inside the \
         thirty-one a C external identifier is guaranteed to distinguish",
    ),
    nm(
        "21.8",
        "a.c",
        "void my_exit(int c);\nvoid f(void) { my_exit(0); }\n",
        "a project shutdown routine is not one of the `<stdlib.h>` termination functions",
    ),
    nm(
        "D4.3",
        "a.c",
        "/* A single nop; see the timing note in docs/hal.md. */\nstatic void delay_one(void) { asm(\"nop\"); }\nvoid f(void) { delay_one(); }\n",
        "the assembly is alone in a function of its own, which is the encapsulation D4.3 \
         asks for — and documented, which is D4.2's separate requirement",
    ),
    nm(
        "4.1",
        "a.c",
        "const char *s = \"line\\n\";\nconst char *t = \"\\x41\" \"B\";\n",
        "`\\n` is a simple escape with nothing to terminate, and the hexadecimal escape ends \
         at the closing quote — the following `B` is a separate string literal, so it cannot \
         be read as another hex digit",
    ),
    nm(
        "4.2",
        "a.c",
        "const char *s = \"what?? really\";\nint f(void) { return 0; }\n",
        "two question marks are only a trigraph when a third character completes one; `?? ` \
         is just punctuation in a string",
    ),
    nm(
        "7.6",
        "a.c",
        "#include <stdint.h>\nint32_t x = INT32_C(1);\n",
        "7.6 names the *small* variants — `INT8_C` and `INT16_C` and their unsigned forms — \
         whose arguments are promoted to `int` anyway. `INT32_C` is not one of them",
    ),
    nm(
        "15.2",
        "a.c",
        "void g(void);\nvoid f(int a) {\n  if (a) { goto done; }\n  g();\ndone:\n  return;\n}\n",
        "the `goto` jumps forward to a label later in the same function, which is the \
         direction 15.2 permits. 15.1 still reports the `goto` itself, and that is a \
         different guideline",
    ),
    nm(
        "16.2",
        "a.c",
        "void g(void);\nvoid f(int a) {\n  switch (a) {\n    case 1: switch (a) { case 2: g(); break; default: break; } break;\n    default: break;\n  }\n}\n",
        "every label sits directly in the body of the switch it belongs to, nested or not",
    ),
    nm(
        "16.2",
        "a.c",
        "void g(void);\nvoid f(int v) {\n  switch (v) {\n    case 1: g(); break;\n    default: break;\n  }\n}\n",
        "every switch label sits directly in the switch's own compound statement, not nested \
         inside another",
    ),
    nm(
        "20.5",
        "a.c",
        "#define KEEP 1U\nunsigned int f(void) { return KEEP; }\n",
        "nothing is undefined here; 20.5 is about `#undef`, which makes a macro's meaning \
         depend on position in the file",
    ),
    nm(
        "20.14",
        "a.h",
        "#ifndef Q_H\n#define Q_H\nint f(void);\n#endif\n",
        "the `#endif` is in the same file as its `#ifndef`, which is what 20.14 requires",
    ),
    nm(
        "15.2",
        "a.c",
        "void a(void) {\n  goto done;\n  g();\ndone:\n  return;\n}\nvoid b(void) {\n  goto done;\n  h();\ndone:\n  return;\n}\n",
        "each `goto` jumps forward to the `done:` of its own function; another function's label of the same name is not the target",
    ),
    nm(
        "17.10",
        "a.c",
        "_Noreturn static inline void die(void) { for (;;) { } }\n",
        "the return type is `void` with other specifiers around it",
    ),
    nm(
        "17.10",
        "a.c",
        "_Noreturn void die(void) { for (;;) { } }\n",
        "a plain `void` return type",
    ),
    nm(
        "8.10",
        "a.c",
        "static __attribute__((unused)) inline int f(void) { return 0; }\n",
        "the `static` storage class comes before an attribute, which does not end the specifiers",
    ),
    nm(
        "D4.10",
        "a.h",
        "#if !defined(FOO_H)\n#define FOO_H\nint f(void);\n#endif\n",
        "the `#if !defined` form of the include guard, with its `#define` directly after",
    ),
    nm(
        "11.10",
        "a.c",
        "_Atomic(void *) p;\n",
        "a pointer to void is a complete type; only `_Atomic(void)` names the incomplete one",
    ),
    nm(
        "20.1",
        "a.c",
        "#if 0\nint dead;\n#endif\n#include <stddef.h>\n",
        "code under a literal `#if 0` is never compiled, so the include does come first",
    ),
    nm(
        "6.3",
        "a.c",
        "struct S { unsigned int f : 2; };\n",
        "a bit-field in a struct, not a union, has a defined layout",
    ),
    nm(
        "6.3",
        "a.c",
        "union U { unsigned int f; };\n",
        "a union member that is not a bit-field",
    ),
    nm(
        "6.3",
        "a.c",
        "int g(int a) { int y = a ? 2 : 1; return y; }\n",
        "a `:` in a conditional expression is not a bit-field",
    ),
    nm(
        "6.2",
        "a.c",
        "int g(int a) { int y = a ? 2 : 1; return y; }\n",
        "a `:` in a conditional expression is not a one-bit signed bit-field",
    ),
    nm(
        "8.2",
        "a.c",
        "typedef unsigned char byte_t;\nvoid g(byte_t b);\n",
        "the parameter has a name after its type",
    ),
    nm(
        "8.2",
        "a.c",
        "struct point { int x; };\nvoid h(struct point p);\n",
        "the tag is followed by the parameter's name",
    ),
    nm(
        "8.2",
        "a.c",
        "void g(void) {\n  int older(int a, int b);\n  older(1, 2);\n}\n",
        "a block-scope prototype with named parameters; the following call is not a prototype",
    ),
    nm(
        "8.2",
        "a.c",
        "void f(int a, int b) {\n  g(a, b);\n}\n",
        "a call statement is not a prototype, because it begins with a name rather than a type",
    ),
    nm(
        "8.2",
        "a.c",
        "int x;\nMACRO(a) int a; { }\n",
        "a macro invocation with the shape of a K&R definition has no return type before its name",
    ),
    nm(
        "16.6",
        "a.c",
        "void f(int x) { switch (x) { case 1: case 2: g(); break; default: break; } }\n",
        "consecutive labels are one clause, and the `default` is a second",
    ),
    nm(
        "17.1",
        "a.c",
        "int __builtin_va_count(void) { return 0; }\n",
        "a name that only resembles a builtin is not one",
    ),
    nm(
        "2.6",
        "a.c",
        "void a(void) { goto done; done: return; }\nvoid b(void) { goto done; done: return; }\n",
        "each label is the target of a `goto` in its own function",
    ),
    nm(
        "20.14",
        "a.c",
        "#ifdef A\n#ifdef B\n#else\n#endif\n#else\n#endif\n",
        "each nested conditional has one `#else` of its own",
    ),
    nm(
        "20.14",
        "a.c",
        "#if A\n#elif B\n#else\n#endif\n",
        "an `#elif` before the `#else` of its level",
    ),
    nm(
        "8.16",
        "a.c",
        "alignas(0x10u) int x;\n",
        "a nonzero alignment, written with a suffix and in hex",
    ),
    nm("17.10", "a.c", "__attribute__((noreturn)) void die(void);\n", "the word is the attribute's, and the return type is void"),
    nm("17.10", "a.c", "__declspec(noreturn) void die(void);\n", "the word is the attribute's, and the return type is void"),
    nm("17.10", "a.c", "[[noreturn]] void die(void);\n", "the word is the attribute's, and the return type is void"),
    nm("17.10", "a.c", "void die(void) __attribute__((noreturn));\n", "a trailing attribute on a void function"),
    nm("17.10", "a.c", "void _Noreturn die(void);\n", "the specifier may follow the return type"),
    nm("8.2", "a.c", "int f(VOID);\n", "`VOID` is the Windows spelling of void"),
    nm("8.2", "a.c", "int f(PARAMS);\n", "a macro may supply the whole parameter list"),
    nm("8.2", "a.c", "static DEFINE_MUTEX(lock);\n", "a macro invocation, not a prototype"),
    nm("8.2", "a.c", "struct S { int a ALIGNED(x); };\n", "a macro on a member; a struct body holds no prototypes"),
    nm("8.2", "a.c", "void f(void) { int a UNUSED(a); }\n", "a macro on a local variable"),
    nm("20.10", "a.c", "#define BANNER \"#1 release\"\n", "a `#` inside a string is not the operator"),
    nm("20.10", "a.c", "#define HASH '#'\n", "a `#` inside a character constant is not the operator"),
    nm("20.10", "a.c", "#define A 1 /* #1 */\n", "a `#` inside a comment is not the operator"),
    nm("D4.9", "a.c", "#define ALLOC(T) ((T *)malloc(sizeof(T)))\n", "a parameter used as `(T *)` is a type, which no function can take"),
    nm("8.11", "a.c", "extern void log_names(const char *const names[]);\n", "the brackets are a parameter's"),
    nm("8.11", "a.c", "extern int g_count;\nstatic int tbl[] = { 1, 2, 3 };\n", "the brackets are the next declaration's"),
    nm("8.11", "a.c", "extern int (*p)[];\n", "a pointer, not an array"),
    nm("D4.6", "a.h", "#ifndef T_H\n#define T_H\ntypedef unsigned int u32_t;\n#endif\n", "how a width-explicit name comes to exist"),
    nm("13.3", "a.c", "int f(int *a, int n) { int i; int sum = 0; for (i = 0; i < n; i++) sum += a[i]; return sum; }\n", "the increment and the addition are separate full expressions"),
    nm("13.3", "a.c", "struct n { struct n *next; };\nint f(struct n *head) { struct n *p; int c = 0; for (p = head; p; p = p->next) c++; return c; }\n", "the assignment is in the header, the increment in the body"),
    nm("13.3", "a.c", "int f(int n) { int t = 0; while (n--) t += 2; return t; }\n", "the condition is a full expression of its own"),
    nm("13.3", "a.c", "int ok(int x);\nint f(int x) { int c = 0; if (ok(x)) c++; return c; }\n", "the call is in the condition, the increment in the body"),
    nm("13.4", "a.c", "struct s { int x; }; int g(struct s *p);\nvoid f(void) { if (g(&(struct s){ .x = 1 }) == 0) { } }\n", "that `=` is a designator's"),
    nm("13.6", "a.c", "struct s { int x; };\nunsigned long n = sizeof((struct s){ .x = 1 });\n", "that `=` is a designator's"),
    nm("13.6", "a.c", "struct s { int a; int b; };\nunsigned long n = sizeof(offsetof(struct s, b));\n", "`offsetof` is a constant, not a call"),
    nm("13.6", "a.c", "typedef int my_t;\nunsigned long n = sizeof(my_t (*)[4]);\n", "a type name with an abstract declarator"),
    nm("12.3", "a.c", "void f(void) { __attribute__((unused)) int a = 0, b = 0; }\n", "a declaration; those commas separate declarators"),
    nm("12.3", "a.c", "void f(void) { MAYBE_UNUSED int a = 0, b = 0; }\n", "a macro before a type; still a declaration"),
    nm("12.3", "a.c", "void f(int x) { __typeof__(x) a = x, b = x; }\n", "`__typeof__` names a type"),
    nm("15.4", "a.c", "void f(int x) { int i; for (i = 0; i < 3; i++) { if (x) goto skip; x++; skip: ; if (i > 1) { break; } } }\n", "that `goto` stays in the loop, so only the `break` leaves it"),
    nm("21.6", "a.c", "int (printf)(const char *format, ...);\n", "a declaration with a parenthesised name"),
    nm("21.10", "a.c", "void f(int time, int x) { if (time)(void)x; }\n", "a variable as a condition, then a cast"),
    nm("8.2", "a.c", "CU_Test(ddsc_userdata, endpoint) { }\n", "a test macro, with no return type before its name"),
    nm("8.2", "a.c", "static DEFINE_mutex(lock);\n", "storage class only, so an invocation"),
    nm("8.2", "a.c", "static unsigned char rx[4] aligned_data(4);\n", "an attribute macro on an array"),
    nm("8.2", "a.c", "struct s; int attribute_format(2, 3);\n", "a number is not a type"),
    nm("17.10", "a.c", "__attribute__((noreturn, cold)) void die(void);\n", "the rest of the list is not the return type"),
    nm("8.2", "a.c", "PRAGMA_OFF\nCU_Test(a, b)\n{\n}\n", "a macro before a macro; a definition must name its parameters"),
    nm("8.2", "a.c", "PRAGMA_OFF(4996)\nCU_Test(a, b)\n{\n}\n", "a macro before a macro; a definition must name its parameters"),
    nm("8.2", "a.c", "static unsigned char v[4] locate_data(\".ram\");\n", "a string is not a parameter"),
];

/// Near-misses for the Rust checks.
pub const RUST_NEAR_MISSES: &[NearMiss] = &[
    nm(
        "UNSAFE.1",
        "src/hw.rs",
        "pub fn read() -> u32 {\n    // SAFETY: the address is a memory-mapped register fixed \
         by the datasheet.\n    unsafe { core::ptr::read_volatile(0x4000_0000 as *const u32) }\n}\n",
        "the unsafe block carries the justification UNSAFE.1 exists to require",
    ),
    nm(
        "PANIC.2",
        "tests/it.rs",
        "#[test]\nfn t() {\n    panic!(\"the test failed\");\n}\n",
        "a panic in a test is how a test reports failure, not a panic shipped to a user",
    ),
    nm(
        "UNSAFE.2",
        "src/hw.rs",
        "/// Reads the status register.\n///\n/// # Safety\n///\n/// The caller must ensure the \
         peripheral clock is enabled before calling this.\npub unsafe fn read_status() -> u32 { 0 }\n",
        "the unsafe function documents its contract under a `# Safety` heading, which is what \
         UNSAFE.2 asks for",
    ),
    nm(
        "UNSAFE.4",
        "src/state.rs",
        "use core::sync::atomic::AtomicU32;\nstatic COUNTER: AtomicU32 = AtomicU32::new(0);\n",
        "a `static` that is not `mut` is exactly the replacement UNSAFE.4 exists to push \
         towards; the word `static` alone is not the violation",
    ),
    nm(
        "PANIC.1",
        "tests/it.rs",
        "#[test]\nfn t() {\n    let v: Option<u32> = Some(1);\n    assert_eq!(v.unwrap(), 1);\n}\n",
        "the guideline says `outside tests`, and this is a test",
    ),
    nm(
        "FFI.1",
        "src/ffi.rs",
        "unsafe extern \"C\" {\n    /// # Safety\n    ///\n    /// `buf` must point to at least \
         `len` writable bytes.\n    pub fn fill(buf: *mut u8, len: usize);\n}\n",
        "the extern declaration documents the invariants the foreign side must uphold",
    ),
    nm(
        "ED2024.1",
        "src/lib.rs",
        "pub fn generate() -> u32 { 7 }\npub struct Generator;\n",
        "`gen` is a keyword in edition 2024, and neither `generate` nor `Generator` is `gen`; \
         a check matching the three letters anywhere would flag both",
    ),
    nm(
        "ED2024.3",
        "src/ffi.rs",
        "unsafe extern \"C\" {\n    pub fn tick();\n}\n",
        "the extern block is already written in the `unsafe extern` form edition 2024 \
         requires",
    ),
    nm(
        "ED2024.4",
        "src/sym.rs",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn entry() {}\n",
        "the attribute is already in its `unsafe(...)` form",
    ),
    nm(
        "CONC.1",
        "src/share.rs",
        "pub struct Handle(u32);\n// SAFETY: `Handle` is a plain integer index with no interior \
         mutability.\nunsafe impl Send for Handle {}\n",
        "the unsafe impl carries the justification comment CONC.1 requires",
    ),
    nm(
        "MODEL.1",
        "src/model.rs",
        "pub const WEIGHTS: &[u8] = include_bytes!(\"weights.bin\");\npub const DIGEST: &str = \
         env!(\"WEIGHTS_SHA256\");\n",
        "the digest is carried alongside the embedded artifact and comes from the build, \
         which is what MODEL.1 asks for",
    ),
    nm(
        "EMB.1",
        "src/lib.rs",
        "#![no_std]\npub fn sum(xs: &[u8; 4]) -> u32 {\n    let mut t = 0u32;\n    for x in xs { t += *x as u32; }\n    t\n}\n",
        "a fixed-size array lives in the caller's storage; EMB.1 is about heap allocation in \
         a `no_std` crate",
    ),
    nm(
        "DEP.2",
        "src/build.rs",
        "pub fn version() -> &'static str { \"1.0\" }\n",
        "a build script is `build.rs` at the package root. A module that happens to be named \
         `build.rs` under `src/` is ordinary code that Cargo never executes at build time, \
         and DEP.2 is about the ones it does",
    ),
    nm(
        "MODEL.3",
        "src/lib.rs",
        "pub const WEIGHTS: &str = \"weights.safetensors\";\n",
        "safetensors is the format MODEL.3 exists to push towards: it carries tensors and no \
         code, so loading it cannot execute anything",
    ),
];

/// Near-misses for the MISRA C++ checks.
pub const CPP_NEAR_MISSES: &[NearMiss] = &[
    nm(
        "8.2.1",
        "a.cpp",
        "int f(double v) { return static_cast<int>(v); }\n",
        "a named cast is the construct 8.2.1 asks for in place of a C-style one",
    ),
    nm(
        "19.0.1",
        "a.cpp",
        "#define STRINGIFY(x) #x\nconst char *s = STRINGIFY(abc);\n",
        "the C++ number for the same guideline as MISRA C D4.9, reported through the same \
         code path — so the stringising exemption is pinned in both catalogues rather than \
         in whichever one happened to be tested",
    ),
    nm(
        "5.7.1",
        "a.cpp",
        "/* an ordinary block comment */\nint f() { return 0; }\n",
        "no `/*` appears inside the comment, so there is nothing ambiguous about where it \
         ends",
    ),
    nm(
        "5.7.2",
        "a.cpp",
        "// an ordinary line comment\nint f() { return 0; }\n",
        "the comment ends at the newline; 5.7.2 is about one spliced into the line below by \
         a trailing backslash",
    ),
    nm(
        "5.13.1",
        "a.cpp",
        "int zero = 0;\nunsigned mask = 0x1FU;\n",
        "`0` is the constant the guideline exempts, and a hexadecimal constant is not an \
         octal one",
    ),
    nm(
        "5.13.2",
        "a.cpp",
        "long total = 100L;\nint little = 1;\n",
        "the suffix is an uppercase `L`, and `little` is an identifier that merely contains \
         the letter",
    ),
    nm(
        "8.2.2",
        "a.cpp",
        "int f(double v) { return static_cast<int>(v); }\n",
        "a `static_cast` is not a `reinterpret_cast`; a check keying on the word `cast` \
         would flag every named cast in C++",
    ),
    nm(
        "8.2.3",
        "a.cpp",
        "struct S { int v; };\nint f(S &s) { return const_cast<const S &>(s).v; }\n",
        "this `const_cast` *adds* const qualification, which is permitted; 8.2.3 names the \
         removal of it. A check keying on the words `const_cast` alone cannot tell the two \
         apart, and only one of them is the guideline",
    ),
    nm(
        "9.4.1",
        "a.cpp",
        "void h();\nvoid f(int n) {\n  if (n > 0) { h(); }\n}\n",
        "the body of the selection statement is a compound statement, which is what 9.4.1 \
         requires",
    ),
    nm(
        "9.4.2",
        "a.cpp",
        "void h();\nvoid g(int v) {\n  switch (v) {\n    case 1: h(); break;\n    default: break;\n  }\n}\n",
        "every non-empty switch-clause ends in an unconditional break",
    ),
    nm(
        "9.4.3",
        "a.cpp",
        "void h();\nvoid g(int v) {\n  switch (v) {\n    case 1: h(); break;\n    default: break;\n  }\n}\n",
        "the switch has a default label",
    ),
    nm(
        "9.6.1",
        "a.cpp",
        "int f(int a) {\n  int r = 0;\n  if (a) { r = 1; }\n  return r;\n}\n",
        "there is no `goto` here at all",
    ),
    nm(
        "11.3.1",
        "a.cpp",
        "int f(int **p) { return **p; }\n",
        "two levels of pointer nesting is what 11.3.1 permits; it objects to more than two",
    ),
    nm(
        "12.2.1",
        "a.cpp",
        "struct S { int a; int b; };\nint f(S s) { return s.a + s.b; }\n",
        "a struct gives every member its own storage; 12.2.1 is about a union",
    ),
    nm(
        "19.6.1",
        "a.hpp",
        "#ifndef A_HPP\n#define A_HPP\nint f();\n#endif\n",
        "the header carries the include guard 19.6.1 asks for",
    ),
    nm(
        "21.6.1",
        "a.cpp",
        "struct S { int v; };\nint f(const S &s) { return s.v; }\n",
        "nothing here allocates; 21.6.1 names the dynamic allocation and deallocation \
         functions",
    ),
    nm(
        "24.5.1",
        "a.cpp",
        "#include <string>\nstd::size_t f(const std::string &s) { return s.size(); }\n",
        "`std::string` is the replacement 24.5.1 exists to push towards, not one of the \
         `<cstring>` functions it names",
    ),
    nm(
        "30.0.1",
        "a.cpp",
        "struct Sink { void write(int); };\nvoid f(Sink &s) { s.write(1); }\n",
        "a project type with a `write` member is not a standard stream facility",
    ),
    nm(
        "19.3.1",
        "a.cpp",
        "#define SQUARE(x) ((x) * (x))\nint f(int v) { return SQUARE(v); }\n",
        "the replacement list uses neither `#` nor `##`; this macro is the subject of other \
         guidelines, but not this one",
    ),
    nm(
        "21.10.1",
        "a.cpp",
        "void my_setjmp();\nvoid f() { my_setjmp(); }\n",
        "a project function whose name merely contains `setjmp` is not `std::setjmp`; 21.10.1 \
         names the features of <csetjmp>",
    ),
    nm(
        "21.10.2",
        "a.cpp",
        "struct Bus { void signal(int); };\nvoid f(Bus &b) { b.signal(1); }\n",
        "neither line reaches `<csignal>`. The call goes through `.` to a member of `b`, and \
         the declaration is a declarator after a type — two adjacent identifiers cannot be a \
         call in C or C++. The spelling is everywhere in event-driven C++, and \
         `logger.printf(..)` and `pool.free(..)` are the same shape; a header declaring such \
         a class was reported with no call anywhere in the file, which matters because this \
         toolkit analyses headers standalone by design",
    ),
];

/// Rules a near-miss cannot speak about, because the check does not run in
/// `check_source`.
///
/// The near-miss test drives one buffer through the per-file checker. A rule
/// decided elsewhere — over the whole crate, or from `Cargo.toml` — will never
/// fire there, so a near-miss for it would pass whatever it contained. That is
/// the vacuous test this table exists to prevent, and listing them is cheaper
/// than discovering later that an entry proved nothing.
pub const NEAR_MISS_EXEMPT: &[(CheckId, &str)] = &[
    ("UNSAFE.3", "decided over the whole crate in rstatic::check_crate_unsafe_declaration;                   covered by unsafe_3_is_a_claim_about_the_crate.rs"),
    ("ED2024.5", "decided from Cargo.toml in rstatic::check_manifest"),
    ("DEP.3", "decided from Cargo.toml in rstatic::check_manifest"),
];

pub fn near_misses(standard: Standard) -> &'static [NearMiss] {
    match standard {
        Standard::MisraC2023 => C_NEAR_MISSES,
        Standard::MisraCpp2023 => CPP_NEAR_MISSES,
        Standard::Rust2024 => RUST_NEAR_MISSES,
    }
}

pub fn fixtures(standard: Standard) -> &'static [Fixture] {
    match standard {
        Standard::MisraC2023 => C_FIXTURES,
        Standard::MisraCpp2023 => CPP_FIXTURES,
        Standard::Rust2024 => RUST_FIXTURES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Calling a recursive function is not recursion. The old search reported
    /// any cycle reachable from `f` against `f`, as "`f` calls itself".
    #[test]
    fn calling_a_recursive_function_is_not_recursion() {
        let src = "int g(int n) { return g(n - 1); }\nint f(int a) { return g(a); }\n";
        let hits: Vec<_> = raw_findings_for(Standard::MisraC2023, "a.c", src)
            .into_iter()
            .filter(|f| f.rule.to_string().ends_with("17.2"))
            .collect();
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].message.contains("`g` calls itself"), "{}", hits[0].message);
        assert_eq!(hits[0].location.line, 1);

        let mutual = "int b(int n);\nint a(int n) { return b(n); }\nint b(int n) { return a(n); }\n";
        let hits: Vec<_> = raw_findings_for(Standard::MisraC2023, "a.c", mutual)
            .into_iter()
            .filter(|f| f.rule.to_string().ends_with("17.2"))
            .collect();
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].message.contains("a -> b -> a"), "{}", hits[0].message);
    }

    /// A scanned file is untrusted. A call chain 20,000 deep overflowed the
    /// stack of the recursive search, and a comment cut inside a multi-byte
    /// character panicked; either one ended the whole scan. Found by a security
    /// audit.
    #[test]
    fn hostile_c_source_is_scanned_rather_than_crashing_the_scan() {
        let mut chain = String::new();
        for i in 0..20_000 {
            chain.push_str(&format!("void f{i}(void) {{ f{}(); }}\n", i + 1));
        }
        chain.push_str("void f20000(void) { f0(); }\n");
        let started = std::time::Instant::now();
        let hits = findings_for(Standard::MisraC2023, "a.c", &chain);
        assert!(hits.iter().any(|r| r.ends_with("17.2")), "the chain closes into one cycle");
        assert!(started.elapsed().as_secs() < 60, "{:?}", started.elapsed());

        let comment = format!("// if(a){{{}é xxxx;\nint f(void) {{ return 0; }}\n", "x".repeat(50));
        let _ = findings_for(Standard::MisraC2023, "a.c", &comment);
    }

    fn findings_for(standard: Standard, file: &str, source: &str) -> Vec<String> {
        raw_findings_for(standard, file, source).into_iter().map(|f| f.rule.to_string()).collect()
    }

    fn raw_findings_for(
        standard: Standard,
        file: &str,
        source: &str,
    ) -> Vec<sda_core::Finding> {
        let path = Path::new(file);
        match standard {
            Standard::MisraC2023 => crate::cstatic::CStaticAnalyzer::c().check_source(path, source),
            Standard::MisraCpp2023 => {
                crate::cstatic::CStaticAnalyzer::cpp().check_source(path, source)
            }
            Standard::Rust2024 => {
                crate::rstatic::RustStaticAnalyzer::new().check_source(path, source)
            }
        }
    }

    /// The precedence trap cppcheck's MISRA addon found on a file this engine
    /// read clean — `strncat(cmd, " \"", sizeof cmd - strlen(cmd) - 1)`.
    ///
    /// Kept here rather than left to `misra_agrees_with_cppcheck.rs`, whose
    /// evidence is a captured corpus: change the corpus and the coverage would
    /// disappear without anything failing.
    #[test]
    fn an_unparenthesized_sizeof_operand_is_a_precedence_finding() {
        let bare = "void f(char *p) { g(p, sizeof buf - strlen(p) - 1); }
";
        assert!(
            findings_for(Standard::MisraC2023, "a.c", bare)
                .iter()
                .any(|r| r == "MISRA-C-2023-12.1"),
            "`sizeof buf - ...` ends its operand at the `-`, which is not how it reads"
        );

        // And the parenthesized form must not, or the check is noise: making
        // the precedence explicit is exactly what 12.1 asks for.
        let explicit = "void f(char *p) { g(p, (sizeof buf) - strlen(p) - 1); }
";
        assert!(
            !findings_for(Standard::MisraC2023, "a.c", explicit)
                .iter()
                .any(|r| r == "MISRA-C-2023-12.1"),
            "parentheses are the fix the guideline asks for and must clear the finding"
        );
    }

    /// Every finding must bracket something.
    ///
    /// Findings used to carry only a start position — `Location::spanning` was
    /// dead code, called once, from a test. A SARIF consumer then highlighted a
    /// single character and the editor underlined everything to the end of the
    /// line. This runs over every fixture, so it covers each implemented check
    /// rather than one hand-picked case.
    #[test]
    fn every_fixture_finding_brackets_its_construct() {
        for standard in Standard::all() {
            for fixture in fixtures(*standard) {
                for f in raw_findings_for(*standard, fixture.file, fixture.source) {
                    let loc = &f.location;
                    let (Some(end_line), Some(end_column)) = (loc.end_line, loc.end_column) else {
                        panic!(
                            "{standard}: `{}` produced a finding with no extent at {}:{}",
                            f.rule, loc.line, loc.column
                        );
                    };
                    assert!(
                        (end_line, end_column) > (loc.line, loc.column),
                        "{standard}: `{}` has an empty or reversed span: {}:{} -> {end_line}:{end_column}",
                        f.rule,
                        loc.line,
                        loc.column
                    );
                    // A span that overruns its line would highlight text that is
                    // not there, which is worse than reporting no extent at all.
                    if end_line == loc.line {
                        let line =
                            fixture.source.lines().nth(loc.line as usize - 1).unwrap_or_default();
                        assert!(
                            (end_column - 1) as usize <= line.len(),
                            "{standard}: `{}` spans past the end of line {}: col {end_column} of {:?}",
                            f.rule,
                            loc.line,
                            line
                        );
                    }
                }
            }
        }
    }

    /// The load-bearing test of this crate's honesty: every guideline the
    /// catalogue says is checked must actually produce a finding.
    /// Every implemented check has a near-miss, or says why it cannot.
    ///
    /// The mirror of `every_claimed_check_actually_fires`. That one proves a
    /// rule fires on code that violates it; this one proves somebody has written
    /// down what *conforming* code looks like for it, which is the half that was
    /// missing while five over-reporting defects sat in the catalogue.
    ///
    /// Adding a rule now means adding both. That is the point: the fixture and
    /// the near-miss are the two halves of a claim, and a rule with only the
    /// first can fire on everything and still look checked.
    #[test]
    fn every_implemented_check_has_a_near_miss_or_an_exemption() {
        let exempt: BTreeSet<&str> = NEAR_MISS_EXEMPT.iter().map(|(r, _)| *r).collect();
        for standard in Standard::all() {
            let have: BTreeSet<&str> =
                near_misses(*standard).iter().map(|c| c.rule).collect();
            for rule in implemented(*standard) {
                assert!(
                    have.contains(rule) || exempt.contains(rule),
                    "{standard}: `{rule}` has no near-miss and no exemption. Write the                      conforming case, or say in NEAR_MISS_EXEMPT why a single buffer cannot                      show one — an unexamined rule is not an innocent one"
                );
            }
        }
    }

    /// A near-miss must be able to fail.
    ///
    /// The near-miss test drives one buffer through the per-file checker, so a
    /// rule decided over a whole crate or from `Cargo.toml` cannot fire there
    /// and an entry for it would pass whatever it held. Naming those rules is
    /// what keeps the table from quietly filling with assertions about nothing.
    #[test]
    fn no_near_miss_targets_a_rule_that_cannot_fire_in_a_single_buffer() {
        let exempt: BTreeSet<&str> = NEAR_MISS_EXEMPT.iter().map(|(r, _)| *r).collect();
        for standard in Standard::all() {
            for case in near_misses(*standard) {
                assert!(
                    !exempt.contains(case.rule),
                    "{standard}: `{}` is decided outside `check_source`, so this near-miss                      would pass whatever it contained",
                    case.rule
                );
            }
        }
        // And the exemptions have to name rules that exist, or the list is a
        // place to hide a typo.
        let known: BTreeSet<&str> =
            Standard::all().iter().flat_map(|s| implemented(*s).iter().copied()).collect();
        for (rule, why) in NEAR_MISS_EXEMPT {
            assert!(known.contains(rule), "`{rule}` is exempted and not implemented anywhere");
            assert!(!why.trim().is_empty(), "`{rule}` is exempted without a reason");
        }
    }

    /// Shapes the near-misses for D4.9 and 8.17 sit beside, which still violate.
    ///
    /// The first exemption for `(T){` also matched `if (N) {` and `catch (...) {`
    /// and the first bound on 8.17 stopped at any brace. The fixtures and near-
    /// misses all passed; a diff over PX4 is what showed it.
    #[test]
    fn the_exemptions_do_not_reach_what_they_sit_beside() {
        let misra = |source| findings_for(Standard::MisraC2023, "a.c", source);
        for source in [
            "#define FREE_IF(p) if (p) { free(p); }\n",
            "#define LOOP(x, ...) while (x) { g(__VA_ARGS__); }\n",
        ] {
            let got = misra(source);
            assert!(got.iter().any(|r| r.ends_with("-D4.9")), "{source:?}: {got:?}");
        }
        let got = misra("alignas(8) struct S { int a; } alignas(16) s;\n");
        assert!(got.iter().any(|r| r.ends_with("-8.17")), "{got:?}");
        let got = misra("struct S { alignas(8) int a; alignas(16) int b; };\n");
        assert!(!got.iter().any(|r| r.ends_with("-8.17")), "{got:?}");
    }

    /// Three places the corpus showed a guideline marked `native` was not: cppcheck
    /// reported the first two, and the third was this engine over-reporting.
    #[test]
    fn the_corpus_cases_stay_found() {
        let misra = |source| findings_for(Standard::MisraC2023, "a.c", source);
        let got = misra("const char *s = \"what??!\";\n");
        assert!(got.iter().any(|r| r.ends_with("-4.2")), "a trigraph in a string: {got:?}");
        let got = misra("#define RELEASE(p) free(p)\n");
        assert!(got.iter().any(|r| r.ends_with("-21.3")), "a call in a macro body: {got:?}");
        let got = misra("#define MAKE(n) malloc(n)\n");
        assert!(got.iter().any(|r| r.ends_with("-D4.12")), "and the directive: {got:?}");
        for source in [
            "union U { struct { unsigned int f : 1; }; unsigned int raw; };\n",
            "union U { union V { int a; } v; unsigned int f : 1; };\n",
        ] {
            let got = misra(source);
            assert!(got.iter().any(|r| r.ends_with("-6.3")), "{source:?}: {got:?}");
        }
    }

    /// And every near-miss stays quiet.
    ///
    /// The complement of `every_claimed_check_actually_fires`, and the half that
    /// was missing. A rule firing here is either over-reporting or the near-miss
    /// is wrong about the guideline — both worth stopping for, and neither
    /// visible to a positive fixture.
    #[test]
    fn a_near_miss_does_not_trip_the_rule_it_resembles() {
        let mut checked = 0;
        for standard in Standard::all() {
            for case in near_misses(*standard) {
                let prefix = standard.id_prefix();
                let unwanted = format!("{prefix}-{}", case.rule);
                let got = findings_for(*standard, case.file, case.source);
                assert!(
                    !got.contains(&unwanted),
                    "{standard}: `{}` fired on a source that does not violate it.
                       why this conforms: {}
  source: {:?}
  all findings: {got:?}",
                    case.rule,
                    case.why,
                    case.source
                );
                checked += 1;
            }
        }
        assert!(checked >= 10, "only {checked} near-miss(es); the claim is thin");
    }

    #[test]
    fn every_claimed_check_actually_fires() {
        for standard in Standard::all() {
            let exempt: BTreeSet<&str> =
                FIXTURE_EXEMPT.iter().map(|(r, _)| *r).collect();

            for rule in implemented(*standard) {
                if exempt.contains(rule) {
                    continue;
                }
                let Some(fixture) = fixtures(*standard).iter().find(|f| f.rule == *rule) else {
                    panic!(
                        "{standard}: `{rule}` is listed as implemented but has no fixture and no \
                         exemption. Add one to prove the check exists, or the claim is unverified."
                    );
                };
                let prefix = standard.id_prefix();
                let want = format!("{prefix}-{rule}");
                let got = findings_for(*standard, fixture.file, fixture.source);
                assert!(
                    got.contains(&want),
                    "{standard}: `{rule}` is claimed as implemented, but its fixture produced no \
                     such finding.\n  fixture: {:?}\n  produced: {got:?}",
                    fixture.source
                );
            }
        }
    }

    /// Fixtures must not drift out of the implemented set either.
    #[test]
    fn every_fixture_names_an_implemented_rule() {
        for standard in Standard::all() {
            let implemented: BTreeSet<&str> = implemented(*standard).iter().copied().collect();
            for f in fixtures(*standard) {
                assert!(
                    implemented.contains(f.rule),
                    "{standard}: fixture for `{}` names a rule not in the implemented list",
                    f.rule
                );
            }
        }
    }

    #[test]
    fn exemptions_are_justified_and_minimal() {
        assert!(FIXTURE_EXEMPT.len() <= 4, "exemptions should stay rare");
        for (rule, why) in FIXTURE_EXEMPT {
            assert!(why.len() > 30, "`{rule}` has no real justification for its exemption");
        }
    }

    #[test]
    fn catalogue_and_implementation_agree_exactly() {
        for s in Standard::all() {
            assert_eq!(
                claimed_but_missing(*s),
                Vec::<String>::new(),
                "{s}: the catalogue claims these guidelines are checked by a default run, but no \
                 check implements them. Either implement the check or change the entry's coverage \
                 to `semantics`, `dynamic`, `external`, or `manual`. A clean report must never \
                 imply a guideline was verified when it was not."
            );
            assert_eq!(
                implemented_but_unclaimed(*s),
                Vec::<String>::new(),
                "{s}: these checks run but the catalogue does not say so, so their findings look \
                 unexplained and their absence looks like coverage nobody claimed."
            );
        }
    }

    #[test]
    fn every_implemented_number_exists_in_its_catalogue() {
        for s in Standard::all() {
            let catalog = Catalog::load(*s);
            for n in implemented(*s) {
                assert!(catalog.get(n).is_some(), "{s}: check `{n}` has no catalogue entry");
            }
        }
    }

    /// Both shapes below came from scanning this project's own C shim, where
    /// each produced a false positive. They are common enough in real headers
    /// that either alone would make its rule unusable.
    #[test]
    fn macro_checks_survive_ordinary_header_idioms() {
        // 20.7: a parameter name occurring inside a string literal is not a use
        // of the parameter — the preprocessor does not substitute into literals.
        let masked = "#define SDA_CHECK_BOUNDS(index, len) \\\n\
                      DO((unsigned long)(index) < (unsigned long)(len), \"index outside container\")\n";
        assert!(
            !findings_for(Standard::MisraC2023, "a.h", masked)
                .contains(&"MISRA-C-2023-20.7".to_string()),
            "a parameter mentioned in a message is not an unparenthesized use"
        );

        // ...but a genuinely bare parameter still is.
        assert!(
            findings_for(Standard::MisraC2023, "a.h", "#define ADD(a, b) a + b\n")
                .contains(&"MISRA-C-2023-20.7".to_string())
        );

        // 5.4: the two arms of an `#if`/`#else` define one macro, not two that
        // collide. This is how every header compiles a facility out.
        let guarded = "#ifdef ENABLED\n\
                       #define TRACE(x) emit(x)\n\
                       #else\n\
                       #define TRACE(x) ((void)0)\n\
                       #endif\n";
        assert!(
            !findings_for(Standard::MisraC2023, "a.h", guarded)
                .contains(&"MISRA-C-2023-5.4".to_string()),
            "conditional definitions of one name are not a distinctness violation"
        );

        // ...while two *different* names colliding within the significant length
        // are. That length is sixty-three for a macro name, not the thirty-one
        // the external-identifier rule uses, so these agree for every character
        // a conforming compiler is guaranteed to look at and differ only after.
        let colliding = "#define AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_ONE 1\n\
                         #define AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_TWO 2\n";
        assert!(
            findings_for(Standard::MisraC2023, "a.h", colliding)
                .contains(&"MISRA-C-2023-5.4".to_string())
        );
    }

    /// A documentation block containing a usage example is not commented-out
    /// code. Every documented header has one; this project's own C shim was
    /// flagged for its.
    #[test]
    fn a_doc_comment_with_an_example_is_not_disabled_code() {
        let documented = "/*\n\
             * probe.h — instrumentation for the analysis build.\n\
             *\n\
             * Records go to the path named by SDA_PROBE_OUT, which the engine sets\n\
             * before launching the target. Faults are written through; coverage is\n\
             * batched, because a buffered fault record is a lost one.\n\
             *\n\
             * Usage:\n\
             *\n\
             *     int read(const uint8_t *buf, size_t i) {\n\
             *         SDA_COV();\n\
             *         return buf[i];\n\
             *     }\n\
             *\n\
             * Define SDA_PROBE_IMPLEMENTATION in exactly one translation unit.\n\
             */\n\
             int f(void);\n";
        assert!(
            !findings_for(Standard::MisraC2023, "a.h", documented)
                .contains(&"MISRA-C-2023-D4.4".to_string()),
            "prose with an example is documentation, not disabled code"
        );

        // Code that really was commented out is still caught.
        let disabled = "int f(void) {\n  /* total = compute(x); */\n  return 0;\n}\n";
        assert!(
            findings_for(Standard::MisraC2023, "a.c", disabled)
                .contains(&"MISRA-C-2023-D4.4".to_string())
        );

        // ...including a multi-line block that is code all the way through.
        let block = "int f(void) {\n  /*\n   * total = compute(x);\n   * emit(total);\n   */\n  return 0;\n}\n";
        assert!(
            findings_for(Standard::MisraC2023, "a.c", block)
                .contains(&"MISRA-C-2023-D4.4".to_string())
        );
    }

    #[test]
    fn implementation_lists_have_no_duplicates() {
        for s in Standard::all() {
            let v = implemented(*s);
            let set: BTreeSet<&str> = v.iter().copied().collect();
            assert_eq!(v.len(), set.len(), "{s}: duplicate entries in the implemented list");
        }
    }

    #[test]
    fn native_coverage_is_a_meaningful_fraction_of_misra_c() {
        let (_, native, total) = coverage_summary()[0];
        assert!(native >= 60, "expected substantial native MISRA C coverage, got {native}/{total}");
    }
}
