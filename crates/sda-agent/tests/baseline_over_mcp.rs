//! "What did we just add" — over the agent surface, on a real scan.
//!
//! The question a team actually asks is not how many findings there are but which
//! ones are new, and every commercial reviewer has some form of this. The two ways
//! to get it wrong are both silent:
//!
//! * **Refreshing the baseline on every scan.** Then every finding was present in
//!   the baseline written moments ago by the run you are looking at, the tool
//!   reports zero new findings forever, and it looks like it is working.
//! * **Treating an absent baseline as "nothing is new".** That is a comparison
//!   nobody made, reported as a comparison that came back clean — the same
//!   confusion `correlate` has a table about.
//!
//! Both are asserted here rather than described.

use sda_agent::dispatch::dispatch;
use serde_json::{Value, json};

fn project(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("sda-baseline-mcp-{name}"));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/main.c"),
        "#include <stdlib.h>\nint main(void) { char *p = malloc(16); (void)p; return 0; }\n",
    )
    .unwrap();
    root
}

fn baseline(path: &str, args: Value) -> Value {
    let mut a = json!({ "path": path });
    for (k, v) in args.as_object().unwrap() {
        a[k] = v.clone();
    }
    dispatch("analysis.baseline", &a).expect("analysis.baseline")
}

#[test]
fn with_no_baseline_new_is_null_rather_than_zero() {
    let root = project("unset");
    let path = root.to_string_lossy().to_string();
    let r = baseline(&path, json!({}));

    assert_eq!(r["has_baseline"], json!(false));
    // The distinction the whole feature rests on. `0` here would be a claim that
    // a comparison was made and found nothing.
    assert!(r["new"].is_null(), "unknown must not be reported as zero: {}", r["new"]);
    assert!(r["recorded"].is_null());
    assert!(
        r["limits"].as_str().unwrap().contains("not the same as answered"),
        "an agent reading this must be told the question was not asked"
    );
    assert!(r["findings_in_scan"].as_u64().unwrap() > 0, "the scan itself still ran");
}

#[test]
fn setting_the_line_makes_everything_currently_present_not_new() {
    let root = project("set");
    let path = root.to_string_lossy().to_string();
    let set = baseline(&path, json!({ "set": true, "note": "before the edit" }));

    assert_eq!(set["has_baseline"], json!(true));
    assert_eq!(set["new"], json!(0), "everything in the scan was just recorded");
    assert_eq!(set["recorded"], set["findings_in_scan"]);
    assert_eq!(set["note"], json!("before the edit"));
}

/// The payoff, and the only test that proves the feature does anything.
#[test]
fn a_finding_added_after_the_line_is_new_and_the_rest_are_not() {
    let root = project("added");
    let path = root.to_string_lossy().to_string();
    let before = baseline(&path, json!({ "set": true }));
    let recorded = before["recorded"].as_u64().unwrap();

    // A second file, so the original findings keep their ids: the whole scheme
    // rests on ids being content-addressed and stable.
    std::fs::write(
        root.join("src/extra.c"),
        "int fresh(void) { int *p = 0; return *p; }\n",
    )
    .unwrap();

    let after = baseline(&path, json!({}));
    let new = after["new"].as_u64().unwrap();
    assert!(new > 0, "a file full of fresh violations produced no new findings");
    assert_eq!(
        after["findings_in_scan"].as_u64().unwrap(),
        recorded + new,
        "every finding is either recorded or new, and nothing is both"
    );
    assert!(
        after["new_findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["location"].as_str().unwrap().contains("extra.c")),
        "only the added file is new: {:?}",
        after["new_findings"]
    );
}

/// A baseline is a record of a run, not a subscription to one. Reading must never
/// move the line — that is the failure mode that reports zero forever.
#[test]
fn reading_the_baseline_does_not_move_it() {
    let root = project("stable");
    let path = root.to_string_lossy().to_string();
    baseline(&path, json!({ "set": true }));

    std::fs::write(root.join("src/extra.c"), "int fresh(void) { int *p = 0; return *p; }\n")
        .unwrap();

    let first = baseline(&path, json!({}));
    let second = baseline(&path, json!({}));
    assert_eq!(first["new"], second["new"], "reading twice changed the answer");
    assert!(first["new"].as_u64().unwrap() > 0, "and the answer was not trivially zero");
}

/// What the line held and this run did not produce. Reported, because *fixed*,
/// *moved* and *filtered out by a scope change* are indistinguishable from here.
#[test]
fn findings_that_disappeared_are_counted_as_resolved() {
    let root = project("resolved");
    let path = root.to_string_lossy().to_string();
    std::fs::write(root.join("src/extra.c"), "int fresh(void) { int *p = 0; return *p; }\n")
        .unwrap();
    let set = baseline(&path, json!({ "set": true }));
    assert!(set["recorded"].as_u64().unwrap() > 0);

    std::fs::remove_file(root.join("src/extra.c")).unwrap();
    let after = baseline(&path, json!({}));
    assert!(
        after["resolved"].as_u64().unwrap() > 0,
        "the file is gone and its findings with it: {}",
        after["resolved"]
    );
    assert!(
        after["limits"].as_str().unwrap().contains("cannot tell fixed from moved"),
        "and the report must not let `resolved` be read as `fixed`"
    );
}
