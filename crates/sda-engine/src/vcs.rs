//! What revision of the source a scan looked at.
//!
//! `git` is asked rather than reimplemented: parsing `.git` by hand would be a
//! second, worse implementation of something already installed everywhere this
//! runs, and it would be wrong first on the cases that matter (worktrees,
//! submodules, `core.worktree`).
//!
//! Every question is asked in the *target's* directory, not the current one. A
//! scan of `~/dev/other-project` from inside this repository must report that
//! project's revision, and asking git without `-C` reports ours — a report
//! confidently naming the wrong commit, which is worse than naming none.

use sda_core::VcsProvenance;
use std::path::Path;
use std::process::Command;

/// Ask git what revision `root` is, or `None` when it is not a checkout.
///
/// Absent rather than guessed: plenty of real targets are unpacked tarballs,
/// vendored trees or scratch directories, and a report that says nothing about
/// the revision is honest where one that invents a value is not.
pub fn detect(root: &Path) -> Option<VcsProvenance> {
    let revision = git(root, &["rev-parse", "HEAD"])?;
    if revision.is_empty() {
        return None;
    }

    // A detached HEAD prints "HEAD", which is not a branch name.
    let branch = git(root, &["rev-parse", "--abbrev-ref", "HEAD"])
        .filter(|b| !b.is_empty() && b != "HEAD");

    let repository = git(root, &["remote", "get-url", "origin"]).filter(|r| !r.is_empty());

    // Untracked files count. A new source file is analysed and is not in the
    // commit, so a tree carrying one does not describe that commit either —
    // `git diff --quiet` would call that clean and it is not.
    // The `?` is the point: if the status query fails while `rev-parse` worked,
    // the whole provenance is withheld. Reporting `dirty: false` would assert a
    // clean tree on the strength of a check that did not run — the shape of
    // defect this repository keeps a table of — and a revision that cannot be
    // qualified is not one worth stating.
    // Submodules are skipped: git would run `status` inside each, under that
    // submodule's own configuration, which `command` has not read.
    let dirty = !git(
        root,
        &["status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=all"],
    )?
    .trim()
    .is_empty();

    Some(VcsProvenance { revision, branch, repository, dirty })
}

/// One git query, trimmed. `None` for any non-zero exit, which is also how "not
/// a repository" arrives.
fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = command(root).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `git -C root`, unable to run anything the scanned repository names.
///
/// The target is untrusted, and so is its `.git/config`: `core.fsmonitor` is a
/// command `git status` runs, a filter driver's `clean` or `process` is one it
/// runs on any file whose stat data is stale, and `log.showSignature` makes
/// `git log` run `gpg.program` on every signed commit. Scanning a project must
/// not execute any of them, so the monitor and signature display are turned off
/// and every filter driver defined in the repository's own configuration is
/// blanked, which git reads as no filter. Filters from the user's global and
/// system configuration, git-lfs among them, are the user's and are left alone.
pub(crate) fn command(root: &Path) -> Command {
    let mut c = Command::new("git");
    c.arg("-C").arg(root).args(["-c", "core.fsmonitor=false", "-c", "log.showSignature=false"]);
    for key in repository_filters(root) {
        c.arg("-c").arg(format!("{key}="));
    }
    c
}

/// The `filter.<driver>.<clean|smudge|process>` keys the repository itself sets.
/// Reading configuration runs nothing.
fn repository_filters(root: &Path) -> Vec<String> {
    let Ok(out) = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["config", "--show-scope", "--get-regexp", r"^filter\..*\.(clean|smudge|process)$"])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(2, '\t');
            let scope = fields.next()?;
            let key = fields.next()?.split(' ').next()?;
            matches!(scope, "local" | "worktree").then(|| key.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This repository is one, so the happy path is testable without building a
    /// fixture — and the value is checked against git rather than against an
    /// expectation, because a hard-coded commit is wrong by the next commit.
    #[test]
    fn a_checkout_reports_its_revision() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        let v = detect(root).expect("this repository is a git checkout");
        assert_eq!(v.revision.len(), 40, "a full sha: {}", v.revision);
        assert!(v.revision.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(Some(v.revision.clone()), git(root, &["rev-parse", "HEAD"]));
    }

    /// A directory that is not a checkout has no revision, and must not borrow
    /// one from an ancestor of the *process*. `git -C <tmp>` walks up from the
    /// target, so the only thing that could go wrong here is asking git without
    /// `-C` at all — which is exactly the mistake this guards.
    #[test]
    fn somewhere_that_is_not_a_checkout_reports_nothing() {
        let d = std::env::temp_dir().join("sda-vcs-not-a-repo");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert!(detect(&d).is_none(), "the system temp directory is not a git checkout");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Scanning a project must not run what its `.git/config` names. Found by a
    /// security audit: `core.fsmonitor` in a scanned checkout ran on one click of
    /// Scan. The fixture is first shown to be armed under plain git, so a pass
    /// cannot come from hooks that would never have fired.
    #[test]
    fn a_scanned_repository_cannot_make_git_run_its_commands() {
        let dir = std::env::temp_dir().join("sda-vcs-hostile-config");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let plain = |args: &[&str]| {
            Command::new("git").arg("-C").arg(&dir).args(args).output().expect("git runs")
        };
        plain(&["init", "--quiet"]);
        plain(&["config", "user.email", "t@example.invalid"]);
        plain(&["config", "user.name", "T"]);
        std::fs::write(dir.join(".gitattributes"), "*.c filter=evil\n").unwrap();
        std::fs::write(dir.join("a.c"), "int x;\n").unwrap();
        plain(&["add", "."]);
        plain(&["commit", "--quiet", "-m", "one"]);
        plain(&["config", "core.fsmonitor", "echo ran >.git/fsmonitor-ran"]);
        plain(&["config", "filter.evil.clean", "echo ran >.git/filter-ran; cat"]);

        let fsmonitor = dir.join(".git/fsmonitor-ran");
        let filter = dir.join(".git/filter-ran");
        // A changed mtime makes git hash the file again, through the filter.
        let stale = |secs: u64| {
            let f = std::fs::File::options().write(true).open(dir.join("a.c")).unwrap();
            f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(secs))
                .unwrap();
        };

        stale(100);
        plain(&["status", "--porcelain"]);
        assert!(fsmonitor.exists(), "the fixture's fsmonitor did not fire under plain git");
        assert!(filter.exists(), "the fixture's clean filter did not fire under plain git");
        std::fs::remove_file(&fsmonitor).unwrap();
        std::fs::remove_file(&filter).unwrap();

        stale(200);
        let v = detect(&dir).expect("still a checkout with a revision");
        assert!(!fsmonitor.exists(), "detect ran the repository's core.fsmonitor");
        assert!(!filter.exists(), "detect ran the repository's clean filter");
        assert!(!v.dirty, "the content is unchanged, so the tree is clean");

        // `git log`, which hotspots read, verifies signatures when the
        // repository asks it to, by running its `gpg.program`. A commit object
        // with an armoured `gpgsig` header is enough; its body can be junk.
        let gpg = dir.join(".git/fake-gpg");
        std::fs::write(&gpg, "#!/bin/sh\necho ran > \"$(dirname \"$0\")/gpg-ran\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&gpg, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let tree = String::from_utf8(plain(&["rev-parse", "HEAD^{tree}"]).stdout).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let object = format!(
            "tree {}\nparent {}\nauthor T <t@example.invalid> {now} +0000\n\
             committer T <t@example.invalid> {now} +0000\n\
             gpgsig -----BEGIN PGP SIGNATURE-----\n \n junk\n -----END PGP SIGNATURE-----\n\
             \ntwo\n",
            tree.trim(),
            v.revision
        );
        let mut hash = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["hash-object", "-t", "commit", "-w", "--literally", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            hash.stdin.take().unwrap().write_all(object.as_bytes()).unwrap();
        }
        let signed = String::from_utf8(hash.wait_with_output().unwrap().stdout).unwrap();
        plain(&["update-ref", "HEAD", signed.trim()]);
        plain(&["config", "log.showSignature", "true"]);
        plain(&["config", "gpg.program", &gpg.to_string_lossy().replace('\\', "/")]);

        let signature = dir.join(".git/gpg-ran");
        plain(&["log", "-1"]);
        assert!(signature.exists(), "the fixture's gpg.program did not run under plain git log");
        std::fs::remove_file(&signature).unwrap();

        assert!(matches!(crate::history::read(&dir, 30), crate::history::History::Read { .. }));
        assert!(!signature.exists(), "reading history ran the repository's gpg.program");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sentence a human reads has to carry the limit of the claim, not just
    /// the claim.
    #[test]
    fn a_dirty_tree_says_the_findings_are_not_that_commit() {
        let clean = VcsProvenance {
            revision: "abc123".into(),
            branch: Some("master".into()),
            repository: None,
            dirty: false,
        };
        assert!(clean.summary().contains("clean working tree"));
        assert!(clean.summary().contains("master"));

        let dirty = VcsProvenance { dirty: true, ..clean };
        assert!(dirty.summary().contains("uncommitted changes"));
        assert!(
            dirty.summary().contains("which is not that commit"),
            "the revision alone would be read as the thing scanned: {}",
            dirty.summary()
        );
    }
}
