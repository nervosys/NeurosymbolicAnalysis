//! What is being analyzed.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Source languages the toolkit reasons about.
///
/// `Unknown` is retained rather than dropped so that inventory counts over a
/// firmware tree stay honest about what was seen but not understood.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Language {
    C,
    Cpp,
    Rust,
    Assembly,
    Python,
    /// A serialized machine-learning model, not source code.
    ModelArtifact,
    Other(String),
    Unknown,
}

impl Language {
    /// Best-effort language detection from a path extension.
    pub fn from_path(path: &Path) -> Language {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();
        match ext.as_str() {
            "c" | "h" => Language::C,
            "cc" | "cpp" | "cxx" | "c++" | "hh" | "hpp" | "hxx" | "h++" | "ipp" | "tcc"
            | "cppm" | "ixx" => Language::Cpp,
            "rs" => Language::Rust,
            "s" | "asm" => Language::Assembly,
            "py" => Language::Python,
            "gguf" | "ggml" | "safetensors" | "onnx" | "tflite" | "pt" | "pth" | "pkl"
            | "pickle" | "h5" | "npz" | "ckpt" | "msgpack" | "bin" => Language::ModelArtifact,
            "" => Language::Unknown,
            other => Language::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::Rust => "rust",
            Language::Assembly => "assembly",
            Language::Python => "python",
            Language::ModelArtifact => "model-artifact",
            Language::Other(s) => s,
            Language::Unknown => "unknown",
        }
    }

    /// `.h` is ambiguous between C and C++; callers that have build context
    /// (a compile command, a sibling `.cpp`) should resolve it themselves.
    pub fn is_ambiguous_header(path: &Path) -> bool {
        path.extension().and_then(|e| e.to_str()) == Some("h")
    }

    /// True for languages the native static engine can lex and check today.
    pub fn natively_supported(&self) -> bool {
        matches!(self, Language::C | Language::Cpp | Language::Rust)
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Look for a `compile_commands.json` in the usual places.
///
/// Build systems rarely leave it at the project root — CMake and Ninja put it
/// in the build directory — so a search that only checks the root will miss the
/// database the toolkit itself just generated, and then hand a type-aware tool
/// nothing to resolve types with. This convention lives here, beside the
/// [`Target::compile_commands`] field it fills, so discovery and the build crate
/// cannot disagree about where to look.
pub fn find_compile_commands(root: &Path) -> Option<PathBuf> {
    for candidate in [
        "compile_commands.json",
        "build/compile_commands.json",
        "out/compile_commands.json",
        "builddir/compile_commands.json",
        "cmake-build-debug/compile_commands.json",
    ] {
        let p = root.join(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// One file within an analysis target.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetFile {
    pub path: PathBuf,
    pub language: Language,
    pub bytes: u64,
}

/// The unit of work handed to an [`crate::Analyzer`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    /// Project root; all reported paths are relative to this where possible.
    pub root: PathBuf,
    pub files: Vec<TargetFile>,
    /// Optional path to a `compile_commands.json` describing how the target builds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compile_commands: Option<PathBuf>,
    /// Optional path to a built binary, required by dynamic providers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<PathBuf>,
}

impl Target {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Target { root: root.into(), files: Vec::new(), compile_commands: None, artifact: None }
    }

    pub fn with_files(mut self, files: Vec<TargetFile>) -> Self {
        self.files = files;
        self
    }

    /// Files matching any of `langs`.
    pub fn files_in(&self, langs: &[Language]) -> Vec<&TargetFile> {
        self.files.iter().filter(|f| langs.contains(&f.language)).collect()
    }

    /// Distinct languages present, in a stable order.
    pub fn languages(&self) -> Vec<Language> {
        let mut v: Vec<Language> = self.files.iter().map(|f| f.language.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Render `path` relative to the target root for stable reporting.
    ///
    /// Scanning a single file makes the root *equal to* that file, so stripping
    /// the prefix leaves nothing and every caller — all eight of them want a
    /// name to show a reader — got the empty string. The visible result was an
    /// exclusion reading ``` `` was discovered as a source file and could not be
    /// read```: the report correctly refused to call a file clean, and then
    /// declined to say which file. An unactionable exclusion is the failure this
    /// whole section of the report exists to prevent, so a relativized path is
    /// never allowed to be empty.
    pub fn relativize<'a>(&self, path: &'a Path) -> &'a Path {
        let rel = path.strip_prefix(&self.root).unwrap_or(path);
        if rel.as_os_str().is_empty() {
            return path.file_name().map(Path::new).unwrap_or(path);
        }
        rel
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_languages_by_extension() {
        assert_eq!(Language::from_path(Path::new("a/b.c")), Language::C);
        assert_eq!(Language::from_path(Path::new("a/b.HPP")), Language::Cpp);
        assert_eq!(Language::from_path(Path::new("a/b.rs")), Language::Rust);
        assert_eq!(Language::from_path(Path::new("m.gguf")), Language::ModelArtifact);
        assert_eq!(Language::from_path(Path::new("README")), Language::Unknown);
    }

    /// The single-file scan, which is how anyone tries the tool for the first
    /// time and how every editor integration invokes it.
    #[test]
    fn a_relativized_path_is_never_empty() {
        let file = Path::new("/w/src/app.c");

        let root_is_the_file = Target::new(file);
        assert_eq!(
            root_is_the_file.relativize(file),
            Path::new("app.c"),
            "the root equals the file, so stripping it leaves nothing; a reader needs a name"
        );

        // The ordinary case is untouched.
        let dir = Target::new("/w");
        assert_eq!(dir.relativize(file), Path::new("src/app.c"));

        // And a path outside the root still comes back whole rather than named.
        assert_eq!(dir.relativize(Path::new("/other/x.c")), Path::new("/other/x.c"));
    }

    #[test]
    fn header_ambiguity_is_flagged() {
        assert!(Language::is_ambiguous_header(Path::new("x.h")));
        assert!(!Language::is_ambiguous_header(Path::new("x.hpp")));
    }

    #[test]
    fn target_language_set_is_deduped_and_sorted() {
        let t = Target::new("/p").with_files(vec![
            TargetFile { path: "b.rs".into(), language: Language::Rust, bytes: 1 },
            TargetFile { path: "a.c".into(), language: Language::C, bytes: 1 },
            TargetFile { path: "c.c".into(), language: Language::C, bytes: 1 },
        ]);
        assert_eq!(t.languages(), vec![Language::C, Language::Rust]);
        assert_eq!(t.files_in(&[Language::C]).len(), 2);
    }
}
