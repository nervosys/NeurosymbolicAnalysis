//! The C header and the Rust emitter write the same JSON, and the header says
//! so without anything checking it.
//!
//! `sda_probe_quote_` in `shim/sda_probe.h` carries this comment:
//!
//! > Mirrors the Rust emitter's `quote` exactly; the two must agree or records
//! > become unparseable.
//!
//! That is an invariant, and it had no test. `the_c_shim_and_the_parser_agree`
//! checks that every *record type* the header emits parses, but it builds its
//! lines from values chosen to be benign — `"src/main.c"`, `"bounds"`,
//! `"a message"` — so no quote, backslash, newline or control byte has ever
//! travelled through either escaper in a test.
//!
//! What drift costs is worth stating, because it is not a cosmetic difference.
//! A record that does not parse is dropped, and a dropped `cov` record is a
//! line the program *did* execute being reported as never reached. The
//! correlation engine then leaves a static finding `Unreached` — "we never
//! tried" — on code that ran. An escaping bug in a probe header is a
//! correctness bug in the verdict.
//!
//! This compares the two **sources**, which is blunt: it cannot tell that
//! either one is correct, only that they handle the same set of characters. It
//! catches the way they would actually drift — a case added to one and not the
//! other — and it is the only comparison available without a C compiler in the
//! test, which this gate does not have.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

/// The body of a named function, from `start` to the first line that is a lone
/// closing brace at column zero or four.
fn body_of<'a>(source: &'a str, needle: &str) -> &'a str {
    let at = source
        .find(needle)
        .unwrap_or_else(|| panic!("`{needle}` is not in the source any more"));
    let rest = &source[at..];
    let end = rest.find("\n}").map(|i| i + 2).unwrap_or(rest.len());
    &rest[..end]
}

/// Characters the C escaper names in its `switch`, plus a marker for its
/// control-byte branch.
fn c_cases(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("case '") {
            // `case '"':` and `case '\\':` and `case '\n':`
            let inner: String = rest.chars().take_while(|c| *c != '\'').collect();
            out.push(inner);
        }
    }
    if body.contains("c < 0x20u") {
        out.push("<0x20".to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// The same, from the Rust `match`.
fn rust_cases(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix('\'') {
            let inner: String = rest.chars().take_while(|c| *c != '\'').collect();
            // Skip the catch-all `c => out.push(c)` arm, which has no quotes.
            if !inner.is_empty() {
                out.push(inner);
            }
        }
    }
    if body.contains("< 0x20") {
        out.push("<0x20".to_string());
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn the_c_header_and_the_rust_emitter_escape_the_same_characters() {
    let header = std::fs::read_to_string(repo_root().join("shim").join("sda_probe.h"))
        .expect("the shim header is readable");
    let rust = std::fs::read_to_string(
        repo_root().join("crates").join("sda-probe").join("src").join("lib.rs"),
    )
    .expect("the emitter is readable");

    let c = c_cases(body_of(&header, "static unsigned long sda_probe_quote_"));
    let r = rust_cases(body_of(&rust, "fn quote(s: &str) -> String"));

    // A reader of this failure needs to know the walk worked before believing
    // the comparison: two empty lists are equal.
    assert!(
        c.len() >= 5,
        "only {c:?} recovered from the C escaper; the reader is broken, not the header"
    );
    assert!(
        r.len() >= 5,
        "only {r:?} recovered from the Rust escaper; the reader is broken, not the emitter"
    );

    assert_eq!(
        c, r,
        "the two emitters escape different characters. The header says it mirrors the Rust \
         `quote` exactly and that the two must agree or records become unparseable — and an \
         unparseable record is dropped, which turns a line that ran into a line reported as \
         never reached. C: {c:?}; Rust: {r:?}"
    );
}

/// And the invariant is stated where it can be found.
///
/// The comparison above is only meaningful while somebody knows *why* the two
/// have to match. If that sentence goes, the next person to add a case to one
/// file has nothing pointing at the other.
#[test]
fn the_header_still_says_why_the_two_must_agree() {
    let header = std::fs::read_to_string(repo_root().join("shim").join("sda_probe.h"))
        .expect("the shim header is readable");
    assert!(
        header.contains("the two must agree"),
        "the header has to say that its escaper mirrors the Rust one, or the test comparing \
         them looks arbitrary to whoever it stops"
    );
}
