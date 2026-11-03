//! What `shim/sda_probe.h` writes is what `ProbeRecord` reads.
//!
//! The probe stream is a contract with two sides written in two languages in two
//! directories: a freestanding C header that must run on a Cortex-M3 with
//! `-nostdlib`, and a serde enum in this crate. Nothing compared them. That is
//! the shape that had `related_weaknesses` and `from_cwe` disagreeing about one
//! class for as long as both existed, and the shape that leaves
//! `RustItem::attributes` empty.
//!
//! The consequence of drift here is quiet. A renamed key does not crash: serde
//! reports a missing field, the line is dropped, and a capture taken off a board
//! arrives thinner than the run that produced it — or empty, which reads as a
//! program that executed nothing.
//!
//! This reads the header itself, recovers the JSON keys each record type emits
//! **in the order it emits them**, builds a line to that shape, and hands it to
//! the parser. No compiler is needed, which matters because the interesting
//! targets for this header are the ones this machine cannot build for.
//!
//! What it catches: a key renamed or dropped on either side, and a record type
//! the header emits that the parser has no variant for. What it does not catch:
//! a key *added* to the header, because serde ignores unknown fields by default —
//! stated here rather than left for someone to discover the hard way.

use sda_engine::dynamic::ProbeRecord;

const SHIM: &str = include_str!("../../../shim/sda_probe.h");

/// The JSON keys one record type emits, in order, read out of the C source.
///
/// The header builds each line from literal fragments — `"{\"t\":\"cov\",\"f\":"`
/// and then `",\"l\":"` and so on — so the keys are recoverable as text without
/// running anything.
fn keys_emitted_for(record: &str) -> Vec<String> {
    let opener = format!("{{\\\"t\\\":\\\"{record}\\\"");
    let start = SHIM
        .find(&opener)
        .unwrap_or_else(|| panic!("the shim no longer emits a `{record}` record at all"));

    // From the opener to the literal that closes the object.
    let rest = &SHIM[start..];
    let end = rest
        .find("\"}\"")
        .or_else(|| rest.find("1}\""))
        .unwrap_or(rest.len().min(2000));
    let window = &rest[..end];

    let mut keys = Vec::new();
    let mut at = 0usize;
    while let Some(i) = window[at..].find("\\\"") {
        let from = at + i + 2;
        let Some(j) = window[from..].find("\\\"") else { break };
        let key = &window[from..from + j];
        at = from + j + 2;
        // `t` is the tag and its value is the record name, not a field.
        if key.len() <= 3 && key != "t" && key != record && !keys.contains(&key.to_string()) {
            keys.push(key.to_string());
        }
    }
    keys
}

/// A JSON value plausible for a key, so the line can be parsed.
fn value_for(key: &str) -> &'static str {
    match key {
        "f" => "\"src/main.c\"",
        "l" => "42",
        "n" => "7",
        "k" => "\"bounds\"",
        "m" => "\"a message\"",
        "v" => "3.5",
        "a" | "b" => "16",
        other => panic!("the shim emits a key `{other}` this test has no value for"),
    }
}

fn line_for(record: &str) -> String {
    let keys = keys_emitted_for(record);
    assert!(!keys.is_empty(), "no keys recovered for `{record}`; the reader is broken, not the shim");
    let body: Vec<String> =
        keys.iter().map(|k| format!("\"{k}\":{}", value_for(k))).collect();
    format!("{{\"t\":\"{record}\",{}}}", body.join(","))
}

/// Every record the header emits parses, into the variant it names.
#[test]
fn every_record_the_shim_emits_is_one_the_parser_accepts() {
    // The five the header writes. A sixth added there and not here fails the
    // test below, which is why both exist.
    let records = ["cov", "fault", "val", "cmp", "mark"];

    for record in records {
        let line = line_for(record);
        let parsed: ProbeRecord = serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!(
                "the shim emits `{line}` and the parser rejects it ({e}). A capture taken off a \
                 board would arrive thinner than the run that produced it, or empty"
            )
        });

        let got = match parsed {
            ProbeRecord::Cov { .. } => "cov",
            ProbeRecord::Fault { .. } => "fault",
            ProbeRecord::Val { .. } => "val",
            ProbeRecord::Cmp { .. } => "cmp",
            ProbeRecord::Mark { .. } => "mark",
        };
        assert_eq!(got, record, "`{line}` parsed as the wrong variant");
    }
}

/// And the header emits no record type this test does not know about.
///
/// Without this, adding a sixth record to the shim would leave the test above
/// passing on the five it already lists — a check that examines less than its
/// subject and says nothing about the difference.
#[test]
fn the_shim_emits_no_record_type_this_test_has_not_listed() {
    let known = ["cov", "fault", "val", "cmp", "mark"];

    let mut found = Vec::new();
    let mut at = 0usize;
    while let Some(i) = SHIM[at..].find("{\\\"t\\\":\\\"") {
        let from = at + i + "{\\\"t\\\":\\\"".len();
        let Some(j) = SHIM[from..].find("\\\"") else { break };
        found.push(SHIM[from..from + j].to_string());
        at = from + j;
    }

    assert!(
        !found.is_empty(),
        "no record types found in the header at all, which is not the same as none existing"
    );
    for f in &found {
        assert!(
            known.contains(&f.as_str()),
            "the shim emits a `{f}` record that nothing here checks; add it to both lists"
        );
    }
}
