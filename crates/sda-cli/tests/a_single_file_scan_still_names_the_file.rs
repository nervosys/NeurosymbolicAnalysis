//! Scanning one file is the first thing anyone does with this tool, and it was
//! the one shape in which the report could not say which file it meant.
//!
//! Paths are reported relative to the target root. Point the scanner at a
//! directory and that is right. Point it at a single file and the root *is* the
//! file, so stripping the prefix leaves the empty string, and:
//!
//! * every finding printed as `:2:28: MISRA-C-2023-D4.12` with nothing before
//!   the colon, and
//! * the *NOT CHECKED* entry for a file that could not be read printed as
//!   ``` `` was discovered as a source file and could not be read```.
//!
//! The second is the one that matters. The report did the hard part correctly —
//! it refused to let an unreadable file pass as a clean one — and then named no
//! file, which is the difference between a caveat a reader can act on and a
//! caveat they can only worry about. An exclusion nobody can act on is the
//! failure the whole *NOT CHECKED* section exists to prevent.
//!
//! Found by showing the scanner something it had not been shown: a `.c` file
//! that is not valid UTF-8. The encoding guard worked. The sentence reporting it
//! did not.

use std::path::PathBuf;
use std::process::Command;

/// A directory holding one readable file with a known finding and one file that
/// cannot be decoded. Each test names its own so parallel runs cannot share.
fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sda-single-file-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");

    std::fs::write(
        dir.join("plain.c"),
        "#include <stdlib.h>\nint main(void) { char *p = malloc(10); return *p; }\n",
    )
    .expect("the readable file");

    // 0xE9 is `é` in Latin-1 and an invalid continuation byte in UTF-8. Written
    // as bytes because writing a `&str` could not produce it.
    let mut bytes = b"#include <stdlib.h>\n/* caf".to_vec();
    bytes.push(0xE9);
    bytes.extend_from_slice(b" */\nint main(void) { return 0; }\n");
    std::fs::write(dir.join("latin1.c"), bytes).expect("the undecodable file");

    dir
}

fn scan(path: &std::path::Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .args(["scan", &path.to_string_lossy()])
        .output()
        .expect("the sda binary runs");
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// The exclusion has to name the file it is about.
#[test]
fn an_unreadable_file_is_named_when_it_is_the_whole_target() {
    let dir = fixture("unreadable");
    let text = scan(&dir.join("latin1.c"));

    assert!(
        text.contains("could not be read"),
        "the encoding guard must still fire on a single-file scan: {text}"
    );
    assert!(
        !text.contains("`` was discovered"),
        "the exclusion named no file, which is the defect this test exists for: {text}"
    );
    assert!(
        text.contains("`latin1.c` was discovered"),
        "the exclusion must name the file a reader has to go and look at: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// And so does every finding, for the same reason and from the same cause.
#[test]
fn a_finding_is_located_in_a_named_file_when_it_is_the_whole_target() {
    let dir = fixture("finding");
    let text = scan(&dir.join("plain.c"));

    let located: Vec<&str> =
        text.lines().filter(|l| l.contains("MISRA-C-2023-D4.12")).collect();
    assert!(!located.is_empty(), "the fixture must produce a finding: {text}");

    for line in &located {
        assert!(
            line.starts_with("plain.c:"),
            "a finding must say which file it is in, even when only one was scanned: {line:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The ordinary case was correct and has to stay correct: relativizing against
/// a real directory root still strips it rather than reducing every path to a
/// bare file name, which is what a careless fix would do.
#[test]
fn a_directory_scan_still_reports_paths_relative_to_the_root() {
    let dir = fixture("directory");
    let nested = dir.join("sub");
    std::fs::create_dir_all(&nested).expect("a subdirectory");
    std::fs::write(
        nested.join("deep.c"),
        "#include <stdlib.h>\nint g(void) { char *p = malloc(4); return *p; }\n",
    )
    .expect("a nested source file");

    let text = scan(&dir);
    let located: Vec<&str> =
        text.lines().filter(|l| l.contains("MISRA-C-2023-D4.12")).collect();

    assert!(
        located.iter().any(|l| l.starts_with("sub\\deep.c:") || l.starts_with("sub/deep.c:")),
        "a nested file keeps its directory; naming it `deep.c` would lose where it is: {located:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
