//! A scanned tree's `.sda/` is the project speaking about itself, and a
//! deviation in it needs nothing but a non-empty rationale and approver. For a
//! team's own repository that is the point. For code somebody else wrote it is
//! a way to approve its own findings: a security audit put a self-approved
//! deviation beside a critical one and the gate passed.
//!
//! `--ignore-project-config` scans without it, and this test holds the two
//! behaviours side by side: the deviation applies by default, and does not
//! under the flag.

use std::process::Command;

#[test]
fn ignoring_the_project_config_brings_a_self_approved_finding_back() {
    let dir = std::env::temp_dir().join("sda-self-approved");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".sda")).expect("a scratch directory");
    std::fs::write(
        dir.join("a.c"),
        "void g(void);\nvoid f(int x);\n\
         void f(int x) { switch (x) { case 1: g(); case 2: break; default: break; } }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join(".sda").join("deviations.toml"),
        "[[deviation]]\nrule = \"MISRA-C-2023-16.3\"\nscope = \"project\"\n\
         rationale = \"self-approved by the repository\"\napprover = \"repo author\"\n",
    )
    .unwrap();

    let gate = |extra: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_sda"))
            .args(["scan", &dir.to_string_lossy(), "--fail-on", "medium"])
            .args(extra)
            .output()
            .expect("the sda binary runs");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).to_string()
                + &String::from_utf8_lossy(&out.stderr),
        )
    };

    let (code, text) = gate(&[]);
    assert_eq!(code, Some(0), "the project's own deviation applies by default: {text}");
    assert!(text.contains("suppressed by deviation: 1"), "{text}");

    let (code, text) = gate(&["--ignore-project-config"]);
    assert_eq!(code, Some(1), "without it the fall-through is a medium finding: {text}");
    assert!(text.contains("MISRA-C-2023-16.3"), "{text}");
    assert!(!text.contains("suppressed by deviation"), "{text}");

    let _ = std::fs::remove_dir_all(&dir);
}
