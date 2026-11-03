//! `sda verify` printed "This is not a clean result" and then exited 0.
//!
//! The sentence was true and went to the one reader who was not looking: a CI
//! step sees the exit code. A project with no `.sda/architecture.toml` passed a
//! proof nobody ran, and `--proofs` and `--taint` were never read at all because
//! the command returned before reaching them.
//!
//! `sda scan --fail-on` closed the same trap with exit 3, in
//! `the_gate_does_not_pass_a_scan_that_never_ran.rs`. This is that answer for the
//! other command, and the narrowness matters the same way: a declaration that
//! holds must still exit 0.

use std::path::{Path, PathBuf};
use std::process::Command;

const UNGUARDED: &str = r#"
[[component]]
name = "policy"
path = "policy"
boundary = "neural"

[[component]]
name = "guard::clamp"
path = "guard"
boundary = "symbolic"
role = "guard"

[[component]]
name = "actuator"
path = "actuator"
boundary = "symbolic"
role = "effector"

[[flow]]
from = "policy"
to = "actuator"
"#;

fn verify_exit(path: &Path) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .args(["verify", &path.to_string_lossy()])
        .output()
        .expect("the sda binary runs");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).to_string())
}

fn project(name: &str, declaration: Option<&str>) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sda-verify-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join(".sda")).expect("a scratch directory");
    if let Some(text) = declaration {
        std::fs::write(d.join(".sda/architecture.toml"), text).expect("a declaration");
    }
    d
}

#[test]
fn no_declaration_is_no_verdict() {
    let (code, out) = verify_exit(&project("none", None));
    assert_eq!(code, 3, "nothing was proved, so nothing passed: {out}");
    assert!(out.contains("not a clean result"), "the log says which it was: {out}");
}

#[test]
fn a_declaration_with_nothing_to_prove_is_no_verdict() {
    let (code, out) = verify_exit(&project("empty", Some("")));
    assert_eq!(code, 3, "no obligation means no proof: {out}");
}

#[test]
fn a_refuted_declaration_is_still_a_failure() {
    let (code, out) = verify_exit(&project("refuted", Some(UNGUARDED)));
    assert_eq!(code, 1, "{out}");
}

#[test]
fn a_declaration_that_holds_still_passes() {
    let sound = UNGUARDED.replace(
        "[[flow]]\nfrom = \"policy\"\nto = \"actuator\"",
        "[[flow]]\nfrom = \"policy\"\nto = \"guard::clamp\"\n\n[[flow]]\nfrom = \"guard::clamp\"\nto = \"actuator\"",
    );
    let (code, out) = verify_exit(&project("sound", Some(&sound)));
    assert_eq!(code, 0, "{out}");
}
