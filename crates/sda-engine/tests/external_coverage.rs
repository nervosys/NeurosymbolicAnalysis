//! The coverage parsers against output captured from the real tools.
//!
//! `crates/sda-adapters/tests/every_adapter_parses.rs` is the model for this and
//! its reasoning applies unchanged: a fixture written from documentation tests
//! what we believe a tool emits, and `ext.modelscan` shipped fully green while
//! unable to read a single byte of what its tool actually wrote. Both fixtures
//! here were captured from a run of `examples/coverage/main.c`, built and
//! executed under WSL Debian — gcov 14.2.0 and LCOV 2.0-1 — and the assertions
//! name lines of that program.
//!
//! What a real tool already taught this parser, which no reconstruction would
//! have:
//!
//! * `gcov` invoked from the build directory, where it can read its `.gcda` but
//!   not the source it is annotating, writes a well-formed four-line file with a
//!   `Source:` header and no records — while printing
//!   `Lines executed:66.67% of 15` to the terminal. That is the case
//!   `an_empty_report_is_an_error_not_an_empty_measurement` exists for, and it
//!   was found by hitting it rather than by imagining it.
//! * LCOV 2.0 emits `FNL:`/`FNA:` where the documentation and older releases say
//!   `FN:`/`FNDA:`. The parser reads neither, which is why the change cost
//!   nothing — but a parser that had insisted on `FN:` would have been wrong
//!   about the current release of the canonical producer.

use sda_engine::coverage::{self, CoverageFormat};

const GCOV: &str = include_str!("fixtures/gcov-14.2.0.gcov");
const LCOV: &str = include_str!("fixtures/lcov.info");

/// The three lines of `examples/coverage/main.c` the program was written around,
/// and what each is for. Line 21 is the one that matters most: it is measured
/// and zero, which is what makes `unreached` a claim about the code.
#[test]
fn real_gcov_output_locates_the_lines_it_measured() {
    let c = coverage::parse(GCOV).expect("gcov 14.2.0 annotated listing");
    assert_eq!(c.format, CoverageFormat::Gcov);
    assert_eq!(c.files, 1);
    assert_eq!(c.lines_measured, 15, "gcov itself reported `15 lines`");
    assert_eq!(c.lines_executed, 10, "and 66.67% of them executed");

    let obs = &c.observation;
    assert_eq!(obs.covered("main.c", 30), 1, "the leaked allocation ran once");
    assert_eq!(obs.covered("main.c", 37), 40, "the loop body ran forty times");
    assert_eq!(obs.covered("main.c", 21), 0, "`never()` was never called");
    assert!(
        obs.coverage.contains_key(&("main.c".to_string(), 21)),
        "and that zero is a record, not an absence: `#####` is a measurement"
    );
    assert!(
        !obs.coverage.contains_key(&("main.c".to_string(), 14)),
        "an `#include` line is marked `-`, which is not a measurement of zero"
    );
    assert!(obs.file_executed("main.c"));
}

/// The same program, the same `.gcda`, through the canonical producer of the
/// interchange format. The absolute `SF:` path is what `lcov` really writes, and
/// findings carry project-relative paths, so this also exercises the suffix
/// matching that has to bridge them.
#[test]
fn real_lcov_output_agrees_with_gcov_about_the_same_program() {
    let c = coverage::parse(LCOV).expect("LCOV 2.0-1 tracefile");
    assert_eq!(c.format, CoverageFormat::Lcov);
    assert_eq!(c.lines_measured, 15, "`LF:15`");
    assert_eq!(c.lines_executed, 10, "`LH:10`");

    let obs = &c.observation;
    assert!(
        obs.coverage.keys().all(|(f, _)| f.starts_with('/')),
        "lcov records an absolute path; matching a relative finding against it is the parser's job"
    );
    assert_eq!(obs.covered("main.c", 21), 0, "`never()` was never called");
    assert!(obs.covered("main.c", 37) > 25, "the loop body is above the refutation threshold");
    assert!(obs.file_executed("examples/coverage/main.c"), "matched by path suffix");
}

/// Both tools read the same `.gcda`, so they must agree about which lines ran.
///
/// They do not agree about *how many times*: the tracefile was captured after
/// further runs of the program had accumulated into the same `.gcda`, so its
/// counts are higher. That is a fact about gcov's counters, not a disagreement,
/// and it is why this compares the executed/not-executed split rather than the
/// numbers.
#[test]
fn the_two_formats_agree_about_which_lines_ran() {
    let g = coverage::parse(GCOV).unwrap().observation;
    let l = coverage::parse(LCOV).unwrap().observation;
    for line in [19u32, 21, 23, 25, 27, 30, 31, 32, 35, 36, 37, 39, 40, 42, 44] {
        assert_eq!(
            g.covered("main.c", line) > 0,
            l.covered("main.c", line) > 0,
            "gcov and lcov disagree about whether line {line} executed"
        );
    }
}
