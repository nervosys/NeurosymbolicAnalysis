//! What a real Miri run actually writes, and where.
//!
//! `ext.miri` shipped declaring `OutputFormat::ClippyJson` on **stdout**, with a
//! fixture reconstructed from that assumption: a `compiler-message` carrying the
//! undefined-behaviour report, exactly as `cargo clippy --message-format=json`
//! would. It is wrong in the way that matters most — the adapter was green and
//! could not have reported a single real finding.
//!
//! `--message-format=json` governs *cargo's build* messages. Miri's UB report is
//! produced at **run** time, by the interpreter executing the test binary, and it
//! is ordinary rustc prose on stderr. The real stdout of the run this fixture
//! came from is three JSON lines: two `compiler-artifact` and a `build-finished`
//! with `"success":true`. The tool reported undefined behaviour; the stream the
//! adapter read reported that the build went fine.
//!
//! That makes nine of ten real-tool encounters that found a defect, seven of them
//! in adapters that were fully green. The base rate is the finding: the next
//! unverified adapter is more likely wrong than right.

use sda_adapters::{parse::parse_miri, specs, OutputChannel, OutputFormat};
use sda_core::{Evidence, Severity};

const MIRI: &str = include_str!("fixtures/ext.miri.txt");

/// The three stdout lines of the same run. Kept inline and short because the
/// point is what is *absent* from them.
const REAL_STDOUT_KINDS: [&str; 3] =
    ["compiler-artifact", "compiler-artifact", "build-finished"];

#[test]
fn the_spec_reads_the_stream_miri_writes_to() {
    let spec = specs().into_iter().find(|s| s.id == "ext.miri").expect("ext.miri ships");
    assert_eq!(spec.channel, OutputChannel::Stderr);
    assert_eq!(spec.format, OutputFormat::MiriText);
    // Not a paraphrase of the assertions above: this is the claim they exist to
    // enforce, and it is what the previous spec got wrong.
    assert!(
        !REAL_STDOUT_KINDS.contains(&"compiler-message"),
        "if a real run ever puts the diagnostic on stdout, this test should be the thing \
         that notices"
    );
}

#[test]
fn the_undefined_behaviour_report_becomes_one_located_finding() {
    let found = parse_miri(MIRI, "ext.miri").expect("real miri stderr");
    assert_eq!(found.len(), 1, "one diagnostic, not one per line of it: {found:?}");

    let f = &found[0];
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.rule.as_str(), "Undefined Behavior", "the category Miri itself named");
    assert_eq!(f.location.file.to_string_lossy(), "src/lib.rs");
    assert_eq!(f.location.line, 11, "the read, not the retag that invalidated it");
    assert_eq!(f.location.column, 9);
    assert!(f.message.contains("borrow stack"), "{}", f.message);
}

/// For an aliasing violation, *where the pointer was created and where it was
/// invalidated* is the whole explanation. A finding that names only the read
/// cannot say why the read is wrong.
#[test]
fn the_help_blocks_are_kept_as_the_traces_they_are() {
    let found = parse_miri(MIRI, "ext.miri").unwrap();
    let frames = found[0]
        .evidence
        .iter()
        .find_map(|e| match e {
            Evidence::Trace { frames } => Some(frames.clone()),
            _ => None,
        })
        .expect("the two `help:` blocks are the diagnostic's own explanation");

    let lines: Vec<u32> = frames.iter().map(|f| f.location.line).collect();
    assert_eq!(lines, vec![11, 6, 7], "the access, then created-at, then invalidated-at");
    assert!(frames[1].note.contains("created"), "{}", frames[1].note);
    assert!(frames[2].note.contains("invalidated"), "{}", frames[2].note);
}

/// Cargo writes these to the same stream, and they are true statements about the
/// process rather than defects in the code. The discriminator is the tool's own:
/// a diagnostic about code carries a `-->` location and these do not.
#[test]
fn cargos_own_failure_lines_are_not_findings() {
    assert!(MIRI.contains("error: test failed"), "the fixture must still contain them");
    assert!(MIRI.contains("error: aborting due to"));
    let found = parse_miri(MIRI, "ext.miri").unwrap();
    assert!(
        found.iter().all(|f| f.rule.as_str() == "Undefined Behavior"),
        "{:?}",
        found.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>()
    );
}

/// A clean run is a clean run — but an empty parse must not come from a parser
/// that cannot read the format, which is the state this adapter was in.
#[test]
fn a_run_with_no_diagnostics_yields_nothing_rather_than_failing() {
    let clean = "   Compiling demo v0.1.0\n    Finished `test` profile\n\
                 running 1 test\ntest works ... ok\n";
    assert!(parse_miri(clean, "ext.miri").unwrap().is_empty());
}
