//! Writes into `.sda` that refuse to follow symbolic links.
//!
//! A scanned repository is untrusted input, and it can commit `.sda`, or a file
//! inside it, as a symlink. Every write the tool makes into `.sda` would then
//! land wherever that link points, which may be outside the repository entirely.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Write `contents` to `path`, creating missing parent directories, unless the
/// file or a directory between the nearest `.sda` ancestor and the file is a
/// symlink.
///
/// Every component is inspected before anything is created or written, so a
/// refusal leaves nothing behind. Components that do not exist cannot be links,
/// and are created as real directories. The `.sda` directory itself is inspected,
/// because a symlinked `.sda` is the case that matters most. Components above
/// `.sda` (the repository root, the home directory) are deliberately not
/// inspected: the tool does not control them, and legitimate setups put them
/// behind links. A path with no `.sda` ancestor is checked at its final
/// component only.
///
/// This defends against repository contents, not against another process
/// swapping a component between the check and the write.
pub fn write_refusing_symlinks(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    for checked in components_to_inspect(path) {
        match fs::symlink_metadata(&checked) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refused to write {}: {} is a symlink",
                        path.display(),
                        checked.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(path, contents)
}

/// The file itself, plus every ancestor up to and including the nearest `.sda`.
fn components_to_inspect(path: &Path) -> Vec<PathBuf> {
    let mut checked = vec![path.to_path_buf()];
    let sda = path
        .ancestors()
        .skip(1)
        .find(|a| a.file_name() == Some(OsStr::new(".sda")));
    if let Some(sda) = sda {
        for ancestor in path.ancestors().skip(1) {
            checked.push(ancestor.to_path_buf());
            if ancestor == sda {
                break;
            }
        }
    }
    checked
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system temp dir, unique to this process and tag.
    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sda-core-safe-write-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn symlink_to_dir(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn symlink_to_dir(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(unix)]
    fn symlink_to_file(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn symlink_to_file(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    /// Creating a symlink on Windows needs Developer Mode or elevation. When the
    /// machine refuses, say so and skip that case: the refusal is the machine's,
    /// not the code's. Any other failure is a real error in the test.
    fn created_or_skipped(result: io::Result<()>, what: &str) -> bool {
        match result {
            Ok(()) => true,
            Err(e)
                if e.kind() == io::ErrorKind::PermissionDenied
                    || e.raw_os_error() == Some(1314) =>
            {
                eprintln!(
                    "skipping {what} case: this machine cannot create symlinks ({e}); \
                     on Windows, symlinks need Developer Mode"
                );
                false
            }
            Err(e) => panic!("could not create the {what} symlink: {e}"),
        }
    }

    #[test]
    fn a_symlink_anywhere_under_sda_refuses_the_write_and_writes_nothing_through_it() {
        let base = scratch("refuse");
        let outside = base.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("victim.toml"), "original").unwrap();

        // A symlinked `.sda` directory.
        let repo = base.join("repo-sda-link");
        fs::create_dir_all(&repo).unwrap();
        if created_or_skipped(
            symlink_to_dir(&outside, &repo.join(".sda")),
            "`.sda` directory",
        ) {
            let target = repo.join(".sda").join("triage.toml");
            let err = write_refusing_symlinks(&target, "x").unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("is a symlink"),
                "must say why it was refused: {msg}"
            );
            assert!(
                msg.contains(&repo.join(".sda").display().to_string()),
                "must name the symlinked path: {msg}"
            );
            assert!(
                !outside.join("triage.toml").exists(),
                "nothing may land through `.sda`"
            );
        }

        // A symlinked directory between `.sda` and the file.
        let repo = base.join("repo-dir-link");
        fs::create_dir_all(repo.join(".sda")).unwrap();
        if created_or_skipped(
            symlink_to_dir(&outside, &repo.join(".sda").join("crashes")),
            "crashes directory",
        ) {
            let target = repo.join(".sda").join("crashes").join("crash-0000.bin");
            let err = write_refusing_symlinks(&target, b"input").unwrap_err();
            assert!(err.to_string().contains("is a symlink"), "{err}");
            assert!(
                !outside.join("crash-0000.bin").exists(),
                "nothing may land through a linked directory"
            );
        }

        // A symlinked target file, with an existing file behind it.
        let repo = base.join("repo-file-link");
        fs::create_dir_all(repo.join(".sda")).unwrap();
        if created_or_skipped(
            symlink_to_file(
                &outside.join("victim.toml"),
                &repo.join(".sda").join("triage.toml"),
            ),
            "target file",
        ) {
            let target = repo.join(".sda").join("triage.toml");
            let err = write_refusing_symlinks(&target, "overwritten").unwrap_err();
            assert!(err.to_string().contains("is a symlink"), "{err}");
            assert_eq!(
                fs::read_to_string(outside.join("victim.toml")).unwrap(),
                "original",
                "the file behind the link must be untouched"
            );
        }
    }

    #[test]
    fn an_ordinary_write_under_sda_creates_the_directory_and_writes_the_file() {
        let base = scratch("normal");
        let file = base.join(".sda").join("crashes").join("crash-0000.bin");

        write_refusing_symlinks(&file, b"abc").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"abc");

        write_refusing_symlinks(&file, b"second").unwrap();
        assert_eq!(
            fs::read(&file).unwrap(),
            b"second",
            "overwriting a real file still works"
        );
    }
}
