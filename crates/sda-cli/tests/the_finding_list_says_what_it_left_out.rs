//! The text report's finding list is capped and filtered, and says so.
//!
//! Two ways the list shown is shorter than the findings held:
//!
//! * It prints the first five hundred and stops. Measured on a 200-file project
//!   before this was fixed: 800 findings, 500 lines, and nothing anywhere saying
//!   the other 300 existed. The `Summary` block gives totals, so a reader who
//!   compares two numbers could work it out — but a reader who scrolls to the end
//!   of a list and finds it ended believes they have seen the list.
//! * `--min-severity` removes everything below a threshold. "No findings at the
//!   requested severity" was all it said, which is true and reads far too much
//!   like a clean scan when eight hundred low findings are sitting behind it.
//!
//! The coverage-gaps block in the same function already did this properly —
//! twelve lines per file and then `(+N more)`. The same obligation, understood in
//! one place and not the other twenty lines above it.
//!
//! Driven through the real binary because `render_text` is private to `main.rs`,
//! which is also the reason this kind of defect survives there: a check that
//! lives only in the CLI is one nothing can test.

use std::path::PathBuf;
use std::process::Command;

/// A project with enough findings to pass the list cap.
///
/// Each file carries four, so 150 files is 600 — comfortably past 500 without
/// making the test slow.
fn project_with_many_findings(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sda-list-cap-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch project");
    for i in 0..150 {
        std::fs::write(
            dir.join("src").join(format!("f{i:03}.c")),
            format!(
                "int f{i}(int x) {{\n  if (x == 1) {{ goto done; }}\n  return 0;\ndone:\n  \
                 return 1;\n}}\n"
            ),
        )
        .expect("a source file");
    }
    dir
}

fn scan(dir: &std::path::Path, extra: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .args(["scan", &dir.to_string_lossy()])
        .args(extra)
        .output()
        .expect("the sda binary runs");
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Counted findings and listed findings are reconciled, not left to the reader.
#[test]
fn a_truncated_finding_list_says_how_many_it_did_not_show() {
    let dir = project_with_many_findings("cap");
    let text = scan(&dir, &[]);

    let listed = text.lines().filter(|l| l.starts_with("src")).count();
    assert_eq!(listed, 500, "the cap is five hundred: {listed} lines listed");

    let total: usize = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("low: "))
        .and_then(|n| n.trim().parse().ok())
        .expect("the summary counts low findings");
    assert!(total > 500, "the fixture must exceed the cap; it has {total}");

    assert!(
        text.contains(&format!("and {} more finding(s) not shown", total - 500)),
        "a list that stopped early must say where: {} findings, {listed} shown",
        total
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// And a severity filter says how many it held back.
///
/// Without the count, "No findings at the requested severity" is the whole of
/// what a reader sees above the summary, and it reads like a clean scan.
#[test]
fn a_severity_filter_says_how_many_findings_it_held_back() {
    let dir = project_with_many_findings("filter");
    let text = scan(&dir, &["--min-severity", "critical"]);

    assert!(
        text.contains("No findings at the requested severity"),
        "nothing is critical here: {text}"
    );
    let total: usize = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("low: "))
        .and_then(|n| n.trim().parse().ok())
        .expect("the summary still counts every finding");
    assert!(
        text.contains(&format!(
            "{total} finding(s) are below the requested severity and are not listed"
        )),
        "the filter must account for what it removed, or an empty list reads as a clean \
         result: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
