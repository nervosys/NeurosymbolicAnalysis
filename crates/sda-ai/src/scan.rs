//! The model-artifact scanner: the static half of AI security analysis.

use crate::formats::{self, Format};
use crate::pickle;
use crate::risk::{Risk, Taxonomy2};
use sda_core::{
    Analyzer, AnalyzerKind, Availability, Capability, Confidence, Evidence, Finding, Language,
    Location, ProviderInfo, RunOptions, Severity, Target,
};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// How much of a file to read for header inspection. Model files are routinely
/// tens of gigabytes; every parser here works from the head alone.
const HEAD_BYTES: usize = 1024 * 1024;

/// What the scanner learned about one artifact.
#[derive(Clone, Debug)]
pub struct ArtifactReport {
    pub path: String,
    pub format: Format,
    pub size: u64,
    /// SHA-256 of the whole file — the identity a supply-chain record needs.
    pub digest: Option<String>,
    pub findings: Vec<Finding>,
}

pub struct ModelScanner {
    taxonomy: Taxonomy2,
    /// Whether to hash whole files. Off for very large artifacts unless asked.
    pub compute_digests: bool,
}

impl Default for ModelScanner {
    fn default() -> Self {
        ModelScanner { taxonomy: Taxonomy2::load(), compute_digests: true }
    }
}

impl ModelScanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan one artifact.
    /// Scan an artifact, reporting it under the path the caller was given.
    ///
    /// `sda ai scan <file>` names a file directly, so the file's own path is the
    /// right one to report. A provider inside a scan is in the other situation:
    /// every other provider reports relative to the target root, and this one
    /// did not — 69 of PX4's 15,528 findings came back with an absolute path,
    /// which is a baseline that will not match on another machine, a triage
    /// record that will not match either, and the scanning machine's directory
    /// layout in the report.
    pub fn scan_file(&self, path: &Path) -> sda_core::Result<ArtifactReport> {
        let display = path.to_string_lossy().to_string();
        self.scan_file_as(path, &display)
    }

    /// Read `path`, but report it as `display`.
    pub fn scan_file_as(&self, path: &Path, display: &str) -> sda_core::Result<ArtifactReport> {
        let meta = std::fs::metadata(path)
            .map_err(|e| sda_core::Error::io(path.display().to_string(), e))?;
        let size = meta.len();

        let mut file = std::fs::File::open(path)
            .map_err(|e| sda_core::Error::io(path.display().to_string(), e))?;
        let mut head = vec![0u8; HEAD_BYTES.min(size as usize)];
        let n = file.read(&mut head).map_err(|e| sda_core::Error::io(path.display().to_string(), e))?;
        head.truncate(n);

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let format = formats::detect(&head, &ext);
        let display = display.to_string();

        let digest = if self.compute_digests {
            digest_of(path).ok()
        } else {
            None
        };

        let mut cx = ScanCx {
            path: &display,
            taxonomy: &self.taxonomy,
            findings: Vec::new(),
        };

        match format {
            Format::Pickle => cx.scan_pickle(&head, size),
            Format::TorchZip => cx.scan_torch_zip(path),
            Format::Gguf => cx.scan_gguf(&head),
            Format::Safetensors => cx.scan_safetensors(&head, size),
            Format::Onnx | Format::TfLite => cx.scan_opaque(format),
            Format::Unknown => cx.scan_unknown(),
        }

        if digest.is_none() {
            cx.note_undigested();
        }
        let findings = cx.findings;

        Ok(ArtifactReport { path: display, format, size, digest, findings })
    }
}

impl Analyzer for ModelScanner {
    fn info(&self) -> ProviderInfo {
        ProviderInfo::native(
            "sda.ai.artifact",
            "NERVOSYS model artifact scanner",
            AnalyzerKind::Static,
            vec![Language::ModelArtifact],
            vec![Capability::ModelArtifactScan, Capability::DependencyAudit],
            "Native parsers for GGUF, safetensors, Python pickle and PyTorch zip containers. \
             Reads headers only, treats every field as attacker-controlled, and reports code \
             execution paths, malformed offsets, missing provenance and tokenizer anomalies \
             against the OWASP LLM Top 10, MITRE ATLAS and the NIST AI RMF.",
        )
    }

    fn available(&self) -> Availability {
        Availability::Available
    }

    fn analyze(&self, target: &Target, _opts: &RunOptions) -> sda_core::Result<Vec<Finding>> {
        let mut out = Vec::new();
        for f in target.files_in(&[Language::ModelArtifact]) {
            let reported = target.relativize(&f.path).to_string_lossy().to_string();
            match self.scan_file_as(&f.path, &reported) {
                Ok(report) => out.extend(report.findings),
                // One unreadable artifact must not abort the scan of the rest.
                Err(e) => out.push(
                    Finding::new(
                        "sda.ai.artifact",
                        "AI-SCAN-ERROR",
                        "model artifact could not be read",
                        Severity::Medium,
                        Location::file_only(target.relativize(&f.path)),
                    )
                    .message(format!("{e}. This artifact was not analyzed."))
                    .confidence(Confidence::Certain),
                ),
            }
        }
        Ok(out)
    }
}

impl sda_core::StaticAnalyzer for ModelScanner {}

struct ScanCx<'a> {
    path: &'a str,
    taxonomy: &'a Taxonomy2,
    findings: Vec<Finding>,
}

impl<'a> ScanCx<'a> {
    fn emit(&mut self, risk_id: &str, message: impl Into<String>, evidence: Vec<Evidence>) {
        let Some(risk) = self.taxonomy.get(risk_id) else {
            return;
        };
        self.push(risk, risk.severity, message.into(), evidence);
    }

    fn emit_with(
        &mut self,
        risk_id: &str,
        severity: Severity,
        message: impl Into<String>,
        evidence: Vec<Evidence>,
    ) {
        let Some(risk) = self.taxonomy.get(risk_id) else {
            return;
        };
        self.push(risk, severity, message.into(), evidence);
    }

    fn push(&mut self, risk: &Risk, severity: Severity, message: String, evidence: Vec<Evidence>) {
        // The offset is already in hand: it is about to be attached as evidence
        // on the lines below. Reporting the finding at `model.pkl:1:1` while its
        // own evidence said "offset 4128" was the report disagreeing with
        // itself, and the location was the half that was wrong.
        //
        // The earliest cited offset is used, because a finding that names
        // several globals is about the first place the artifact goes wrong;
        // that is where a reader opening a hex editor should land.
        let at = evidence
            .iter()
            .filter_map(|e| match e {
                Evidence::ModelArtifact { offset, .. } => *offset,
                _ => None,
            })
            .min();

        let mut location = Location::file_only(self.path);
        if let Some(start) = at {
            location = location.at_bytes(start, None);
        }

        let mut f = Finding::new(
            "sda.ai.artifact",
            risk.rule_id(),
            risk.title.clone(),
            severity,
            location,
        )
        .message(message)
        .confidence(Confidence::High);
        for t in risk.taxonomy_refs() {
            f = f.taxonomy(t);
        }
        for e in evidence {
            f = f.evidence(e);
        }
        self.findings.push(f);
    }

    fn artifact_evidence(&self, format: &str, offset: Option<u64>, detail: impl Into<String>) -> Evidence {
        Evidence::ModelArtifact {
            path: self.path.to_string(),
            format: format.to_string(),
            offset,
            detail: detail.into(),
        }
    }

    // --- pickle ---------------------------------------------------------

    fn scan_pickle(&mut self, head: &[u8], size: u64) {
        let scan = pickle::scan(head);
        self.report_pickle(&scan, "pickle", size);
    }

    fn report_pickle(&mut self, scan: &pickle::PickleScan, container: &str, _size: u64) {
        let critical = scan.critical_globals().into_iter().cloned().collect::<Vec<_>>();
        let suspicious = scan.suspicious_globals().into_iter().cloned().collect::<Vec<_>>();

        if !critical.is_empty() {
            let names: Vec<String> = critical.iter().map(|g| g.qualified()).collect();
            let ev: Vec<Evidence> = critical
                .iter()
                .map(|g| {
                    self.artifact_evidence(
                        container,
                        Some(g.offset),
                        format!("GLOBAL {} — invoked when this file is loaded", g.qualified()),
                    )
                })
                .collect();
            self.emit_with(
                "UNSAFE-DESERIALIZATION",
                Severity::Critical,
                format!(
                    "This artifact calls {} when loaded. Loading it — with torch.load, \
                     pickle.load, or any wrapper around them — executes that code with the \
                     privileges of the loading process. Do not load this file to inspect it; \
                     treat it as a payload, not as weights.",
                    names.join(", ")
                ),
                ev,
            );
        } else if scan.calls_on_load {
            // Every real checkpoint reduces; say so plainly rather than crying wolf.
            self.emit_with(
                "UNSAFE-DESERIALIZATION",
                Severity::High,
                format!(
                    "This is a {container} container. No dangerous callable was found in the \
                     opcode stream, but the format executes whatever GLOBAL it names on load, so \
                     the absence of a known-bad name is not a safety property. Convert to \
                     safetensors or GGUF before shipping it in firmware."
                ),
                vec![self.artifact_evidence(
                    container,
                    None,
                    format!(
                        "protocol {:?}, {} global reference(s), calls on load",
                        scan.protocol,
                        scan.globals.len()
                    ),
                )],
            );
        }

        if !suspicious.is_empty() {
            let names: Vec<String> = suspicious.iter().map(|g| g.qualified()).collect();
            self.emit_with(
                "SUPPLY-CHAIN",
                Severity::Medium,
                format!(
                    "This artifact references {} — modules a normal checkpoint does not need. \
                     Each is a callable the loader will resolve and may invoke.",
                    names.join(", ")
                ),
                vec![self.artifact_evidence(container, None, names.join(", "))],
            );
        }

        if scan.is_incomplete() {
            let why = match scan.unknown_opcode {
                Some((op, at)) => format!("unknown opcode 0x{op:02x} at byte {at}"),
                None => "the opcode stream is truncated".to_string(),
            };
            self.emit_with(
                "MALFORMED-ARTIFACT",
                Severity::High,
                format!(
                    "The pickle scan could not complete: {why}. Everything after that point is \
                     unexamined, so this file must be treated as unscanned rather than clean."
                ),
                vec![self.artifact_evidence(container, None, why)],
            );
        }
    }

    /// PyTorch `.pt`/`.pth` files are zip archives whose `data.pkl` member is a
    /// pickle. The pickle is where the risk lives, so we go and find it.
    fn scan_torch_zip(&mut self, path: &Path) {
        let Ok(file) = std::fs::File::open(path) else {
            return;
        };
        let Ok(mut archive) = zip::ZipArchive::new(file) else {
            self.emit_with(
                "MALFORMED-ARTIFACT",
                Severity::Medium,
                "This file begins with a zip signature but is not a readable archive.",
                vec![self.artifact_evidence("torch-zip", None, "zip central directory unreadable")],
            );
            return;
        };

        let mut scanned_any = false;
        let names: Vec<String> = (0..archive.len())
            .filter_map(|i| archive.by_index(i).ok().and_then(|f| f.name().ok().map(|n| n.to_string())))
            .collect();

        for name in &names {
            if !name.ends_with(".pkl") && !name.ends_with("data.pkl") {
                continue;
            }
            let Ok(mut member) = archive.by_name(name) else { continue };
            let mut buf = Vec::new();
            // Bound the read: a zip bomb should not be able to exhaust memory
            // during a security scan.
            let mut limited = (&mut member).take(8 * 1024 * 1024);
            if limited.read_to_end(&mut buf).is_err() {
                continue;
            }
            scanned_any = true;
            let scan = pickle::scan(&buf);
            self.report_pickle(&scan, &format!("torch-zip:{name}"), buf.len() as u64);
        }

        if !scanned_any {
            self.emit_with(
                "UNSAFE-DESERIALIZATION",
                Severity::Medium,
                format!(
                    "This is a PyTorch zip container with {} member(s) but no pickle stream was \
                     located, so its load-time behaviour was not determined. Treat as unscanned.",
                    names.len()
                ),
                vec![self.artifact_evidence("torch-zip", None, names.join(", "))],
            );
        }
    }

    // --- GGUF -----------------------------------------------------------

    fn scan_gguf(&mut self, head: &[u8]) {
        let header = match formats::parse_gguf(head) {
            Ok(h) => h,
            Err(e) => {
                self.emit_with(
                    "MALFORMED-ARTIFACT",
                    Severity::High,
                    format!(
                        "The GGUF header does not parse: {e}. A runtime that memory-maps this file \
                         and trusts its header will read outside the mapping."
                    ),
                    vec![self.artifact_evidence("gguf", None, e)],
                );
                return;
            }
        };

        for a in &header.anomalies {
            let a = a.clone();
            self.emit_with(
                "MALFORMED-ARTIFACT",
                Severity::Medium,
                format!("GGUF header anomaly: {a}"),
                vec![self.artifact_evidence("gguf", None, a)],
            );
        }

        // Provenance.
        let missing: Vec<&str> = [
            ("general.license", header.license()),
            ("general.architecture", header.architecture()),
            ("general.name", header.name()),
        ]
        .iter()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| *k)
        .collect();

        if !missing.is_empty() {
            let list = missing.join(", ");
            self.emit(
                "UNDOCUMENTED-CAPABILITY",
                format!(
                    "This model declares no {list}. Without them the artifact cannot be placed in \
                     an inventory, its licence obligations cannot be met, and the NIST AI RMF \
                     GOVERN function has nothing to record."
                ),
                vec![self.artifact_evidence("gguf", None, format!("missing metadata: {list}"))],
            );
        }

        // An embedded chat template is model-supplied logic.
        if let Some(t) = header.chat_template() {
            let executable = t.contains("{%") || t.contains("{{");
            if executable {
                let excerpt: String = t.chars().take(160).collect();
                self.emit(
                    "TEMPLATE-INJECTION",
                    "This model ships a chat template containing template control flow. The \
                     runtime renders it with user-controlled input, so the model's author has \
                     supplied logic that executes inside your inference process."
                        .to_string(),
                    vec![self.artifact_evidence("gguf", None, excerpt)],
                );
            }
        }

        self.scan_tokens(&header.tokens());
    }

    /// Tokenizer entries that look like triggers or are structurally anomalous.
    fn scan_tokens(&mut self, tokens: &[&str]) {
        if tokens.is_empty() {
            return;
        }
        let suspicious: Vec<String> = tokens
            .iter()
            .filter(|t| looks_like_trigger(t))
            .take(24)
            .map(|t| (*t).to_string())
            .collect();

        if !suspicious.is_empty() {
            let list = suspicious.join(", ");
            self.emit(
                "TOKENIZER-ANOMALY",
                format!(
                    "{} tokenizer entries look like control markers or trigger phrases rather \
                     than natural text: {list}. This is not evidence of a backdoor — such tokens \
                     are common and usually benign — but they are the right seed set for a \
                     targeted probe campaign (`sda ai probes --trigger`).",
                    suspicious.len()
                ),
                vec![self.artifact_evidence("gguf", None, list)],
            );
        }
    }

    // --- safetensors ----------------------------------------------------

    fn scan_safetensors(&mut self, head: &[u8], size: u64) {
        let header = match formats::parse_safetensors(head) {
            Ok(h) => h,
            Err(e) => {
                self.emit_with(
                    "MALFORMED-ARTIFACT",
                    Severity::High,
                    format!("The safetensors header does not parse: {e}"),
                    vec![self.artifact_evidence("safetensors", None, e)],
                );
                return;
            }
        };

        // The header was parsed from the head only, so bounds checks against the
        // real file size are done here rather than in the parser.
        let data_start = 8 + head
            .get(..8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0);
        // The parser also records out-of-range tensors as anomalies, so the same
        // defect was reported twice — once here as High and once below as
        // Medium, with identical wording. Two findings for one problem inflates
        // the severity counts and doubles the triage.
        let mut reported = Vec::new();
        for t in &header.tensors {
            if data_start.saturating_add(t.end) > size {
                let detail = format!(
                    "tensor `{}` declares data up to byte {} but the file is {size} bytes",
                    t.name,
                    data_start.saturating_add(t.end)
                );
                self.emit_with(
                    "MALFORMED-ARTIFACT",
                    Severity::High,
                    format!(
                        "{detail}. A runtime that maps this file and trusts the header reads out \
                         of bounds — an ordinary memory-safety bug reached through a file format."
                    ),
                    vec![self.artifact_evidence("safetensors", Some(t.start), detail.clone())],
                );
                reported.push(detail);
            }
        }
        for a in &header.anomalies {
            // The anomaly restates the same fact with a trailing explanation,
            // so match on the part that identifies it: the tensor and the byte
            // counts.
            if reported.iter().any(|d| a.starts_with(d.as_str())) {
                continue;
            }
            let a = a.clone();
            self.emit_with(
                "MALFORMED-ARTIFACT",
                Severity::Medium,
                format!("safetensors header anomaly: {a}"),
                vec![self.artifact_evidence("safetensors", None, a)],
            );
        }

        if header.metadata.is_empty() {
            self.emit(
                "UNDOCUMENTED-CAPABILITY",
                "This safetensors file carries no `__metadata__`, so it records nothing about its \
                 own origin, licence, or the training run that produced it.",
                vec![self.artifact_evidence("safetensors", None, "no __metadata__ block")],
            );
        }
    }

    // --- other ----------------------------------------------------------

    fn scan_opaque(&mut self, format: Format) {
        self.emit_with(
            "UNDOCUMENTED-CAPABILITY",
            Severity::Info,
            format!(
                "This is a {} artifact. The scanner records its identity and digest but does not \
                 yet parse its graph, so operator-level risks — custom operators, embedded \
                 scripts — were not examined.",
                format.as_str()
            ),
            vec![self.artifact_evidence(format.as_str(), None, "graph not parsed")],
        );
    }

    fn scan_unknown(&mut self) {
        self.emit_with(
            "UNDOCUMENTED-CAPABILITY",
            Severity::Low,
            "This file was collected as a model artifact but its container format was not \
             recognised, so nothing about its load-time behaviour is known.",
            vec![self.artifact_evidence("unknown", None, "format not recognised")],
        );
    }

    fn note_undigested(&mut self) {
        self.emit_with(
            "SUPPLY-CHAIN",
            Severity::Low,
            "No digest was computed for this artifact, so it cannot be pinned in a supply-chain \
             record or compared against a known-good release.",
            vec![],
        );
    }
}

/// Whether a token looks like a control marker or an implanted phrase rather
/// than ordinary vocabulary.
fn looks_like_trigger(token: &str) -> bool {
    let t = token.trim();
    if t.len() < 4 {
        return false;
    }
    // Angle-bracketed control markers beyond the well-known ones.
    let bracketed = (t.starts_with("<|") && t.ends_with("|>")) || (t.starts_with('<') && t.ends_with('>'));
    let known = matches!(
        t,
        "<|endoftext|>"
            | "<|im_start|>"
            | "<|im_end|>"
            | "<s>"
            | "</s>"
            | "<unk>"
            | "<pad>"
            | "<mask>"
            | "<|begin_of_text|>"
            | "<|end_of_text|>"
            | "<|eot_id|>"
            | "<|start_header_id|>"
            | "<|end_header_id|>"
    );
    if bracketed && !known {
        return true;
    }
    // A long single token containing a year or a version-like marker is the
    // shape a date-triggered backdoor takes.
    if t.len() > 12 && t.chars().filter(|c| c.is_ascii_digit()).count() >= 4 {
        return true;
    }
    false
}

fn digest_of(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sda-ai-{name}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn scan(dir: &Path, name: &str, bytes: &[u8]) -> ArtifactReport {
        let p = dir.join(name);
        fs::write(&p, bytes).unwrap();
        ModelScanner::new().scan_file(&p).unwrap()
    }

    fn rules(r: &ArtifactReport) -> Vec<String> {
        r.findings.iter().map(|f| f.rule.to_string()).collect()
    }

    /// A real PyTorch `.pt`: a zip whose `archive/data.pkl` member is a
    /// protocol-4 pickle reaching `os.system` through `STACK_GLOBAL`. This is
    /// the shape malicious models on model hubs actually take, and it is the one
    /// path that depends on the zip crate rather than on our own parsing, so it
    /// can break without any of our code changing.
    #[test]
    fn a_malicious_pytorch_zip_is_critical_without_being_unpacked_or_unpickled() {
        use std::io::Write;

        // Protocol 4: PROTO, FRAME, SHORT_BINUNICODE ×2, STACK_GLOBAL, REDUCE.
        let mut inner: Vec<u8> = Vec::new();
        for s in ["os", "system"] {
            inner.push(0x8c);
            inner.push(s.len() as u8);
            inner.extend_from_slice(s.as_bytes());
            inner.push(0x94); // MEMOIZE
        }
        inner.extend_from_slice(&[0x93, 0x94]); // STACK_GLOBAL, MEMOIZE
        inner.extend_from_slice(&[0x8c, 0x02]);
        inner.extend_from_slice(b"id");
        inner.extend_from_slice(&[0x94, 0x85, 0x94, 0x52, 0x94, 0x2e]);

        let mut pickle: Vec<u8> = vec![0x80, 0x04, 0x95];
        pickle.extend_from_slice(&(inner.len() as u64).to_le_bytes());
        pickle.extend_from_slice(&inner);

        let d = scratch("torch-zip");
        let path = d.join("model.pt");
        {
            let file = fs::File::create(&path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
            zip.start_file("archive/data.pkl", opts).unwrap();
            zip.write_all(&pickle).unwrap();
            // A weights blob, so the archive is not pickle-only.
            zip.start_file("archive/data/0", opts).unwrap();
            zip.write_all(&[0u8; 128]).unwrap();
            zip.finish().unwrap();
        }

        let r = ModelScanner::new().scan_file(&path).unwrap();
        assert_eq!(r.format, Format::TorchZip);
        let f = r
            .findings
            .iter()
            .find(|f| f.severity == sda_core::Severity::Critical)
            .unwrap_or_else(|| panic!("no critical finding; got {:?}", rules(&r)));
        assert!(
            f.message.contains("os.system"),
            "the callable must be named so a reviewer can judge it: {}",
            f.message
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_weaponized_pickle_is_reported_as_critical_with_the_callable_named() {
        let d = scratch("pickle");
        let mut payload = vec![0x80, 0x04, b'c'];
        payload.extend_from_slice(b"os\nsystem\n");
        payload.extend_from_slice(b")R.");

        let r = scan(&d, "evil.pkl", &payload);
        assert_eq!(r.format, Format::Pickle);
        let f = r
            .findings
            .iter()
            .find(|f| f.rule.as_str() == "AI-UNSAFE-DESERIALIZATION")
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.message.contains("os.system"));
        assert!(f.message.contains("Do not load this file"));
        assert!(f.taxonomy.iter().any(|t| t.id == "LLM03"));
        assert!(f.taxonomy.iter().any(|t| t.scheme == sda_core::Taxonomy::NistAiRmf));

        // The finding sits at the offset of the GLOBAL it is about. It used to
        // report `evil.pkl:1:1` while its own evidence named the offset — the
        // report disagreeing with itself, with the location as the wrong half.
        let cited = f
            .evidence
            .iter()
            .find_map(|e| match e {
                Evidence::ModelArtifact { offset, .. } => *offset,
                _ => None,
            })
            .expect("the evidence names an offset");
        assert_eq!(
            f.location.byte_start,
            Some(cited),
            "the location must be the offset the evidence cites"
        );
        assert!(
            f.location.display().ends_with(&format!("evil.pkl@{cited:#x}")),
            "rendered as {}",
            f.location.display()
        );

        fs::remove_dir_all(&d).ok();
    }

    /// A pickle whose risk is the format itself, rather than a specific opcode,
    /// has no offset to report — and must not invent one. `file_only` is the
    /// honest location for "this whole artifact is the problem".
    #[test]
    fn a_finding_about_the_whole_artifact_claims_no_offset() {
        let d = scratch("whole-artifact");
        let mut payload = vec![0x80, 0x02, b'c'];
        payload.extend_from_slice(b"collections\nOrderedDict\n");
        payload.extend_from_slice(b")R.");

        let r = scan(&d, "ok.pkl", &payload);
        for f in &r.findings {
            let cites_offset = f.evidence.iter().any(|e| {
                matches!(e, Evidence::ModelArtifact { offset: Some(_), .. })
            });
            assert_eq!(
                f.location.byte_start.is_some(),
                cites_offset,
                "`{}` claims an offset it has no evidence for, or drops one it has",
                f.rule.as_str()
            );
        }
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_clean_pickle_is_still_reported_because_the_format_itself_is_the_risk() {
        let d = scratch("clean-pickle");
        let mut payload = vec![0x80, 0x02, b'c'];
        payload.extend_from_slice(b"collections\nOrderedDict\n");
        payload.extend_from_slice(b")R.");

        let r = scan(&d, "ok.pkl", &payload);
        let f = r
            .findings
            .iter()
            .find(|f| f.rule.as_str() == "AI-UNSAFE-DESERIALIZATION")
            .unwrap();
        assert_eq!(f.severity, Severity::High, "lower than weaponized, but not silent");
        assert!(f.message.contains("not a safety property"));

        fs::remove_dir_all(&d).ok();
    }

    /// One defect, one finding. The out-of-range tensor was reported twice —
    /// once by the bounds check against the real file size, and again as a
    /// parser anomaly with identical wording — which double-counted it in the
    /// severity summary and gave a reviewer the same problem to triage twice.
    #[test]
    fn an_out_of_range_tensor_is_reported_once_not_twice() {
        let d = scratch("safetensors-dup");
        let header = br#"{"weight":{"dtype":"F32","shape":[4,4],"data_offsets":[0,999999]},"__metadata__":{"format":"pt"}}"#;
        let mut v = (header.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(header);
        v.extend_from_slice(&[0u8; 64]);

        let r = scan(&d, "truncated.safetensors", &v);
        assert_eq!(r.format, Format::Safetensors);

        let malformed: Vec<_> =
            r.findings.iter().filter(|f| f.rule.as_str() == "AI-MALFORMED-ARTIFACT").collect();
        assert_eq!(
            malformed.len(),
            1,
            "one out-of-range tensor must yield one finding, got: {:?}",
            malformed.iter().map(|f| (&f.severity, &f.message)).collect::<Vec<_>>()
        );
        assert_eq!(malformed[0].severity, Severity::High, "the informative one must survive");
        assert!(malformed[0].message.contains("reads out of bounds"));

        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn gguf_without_provenance_metadata_is_flagged() {
        let d = scratch("gguf");
        let mut v = b"GGUF".to_vec();
        v.extend_from_slice(&3u32.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());

        let r = scan(&d, "bare.gguf", &v);
        assert_eq!(r.format, Format::Gguf);
        assert!(rules(&r).contains(&"AI-UNDOCUMENTED-CAPABILITY".to_string()));
        let f = r.findings.iter().find(|f| f.rule.as_str() == "AI-UNDOCUMENTED-CAPABILITY").unwrap();
        assert!(f.message.contains("general.license"));

        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn safetensors_with_out_of_bounds_offsets_is_high_severity() {
        let d = scratch("st");
        let header = r#"{"__metadata__":{"format":"pt"},"w":{"dtype":"F32","shape":[1024],"data_offsets":[0,999999]}}"#;
        let mut v = (header.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(header.as_bytes());
        v.extend_from_slice(&[0u8; 32]);

        let r = scan(&d, "bad.safetensors", &v);
        let f = r.findings.iter().find(|f| f.rule.as_str() == "AI-MALFORMED-ARTIFACT").unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.message.contains("out of bounds") || f.message.contains("reads out of bounds"));

        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_well_formed_safetensors_file_produces_no_memory_safety_finding() {
        let d = scratch("st-ok");
        let header = r#"{"__metadata__":{"format":"pt","license":"apache-2.0"},"w":{"dtype":"F32","shape":[4],"data_offsets":[0,16]}}"#;
        let mut v = (header.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(header.as_bytes());
        v.extend_from_slice(&[0u8; 16]);

        let r = scan(&d, "ok.safetensors", &v);
        assert!(!rules(&r).contains(&"AI-MALFORMED-ARTIFACT".to_string()), "{:?}", rules(&r));

        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn every_artifact_gets_a_digest_for_supply_chain_pinning() {
        let d = scratch("digest");
        let r = scan(&d, "x.gguf", b"GGUF\x03\x00\x00\x00");
        assert!(r.digest.is_some());
        assert_eq!(r.digest.as_ref().unwrap().len(), 64);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn trigger_shaped_tokens_are_recognised_without_crying_wolf() {
        assert!(!looks_like_trigger("<|endoftext|>"), "standard markers are not triggers");
        assert!(!looks_like_trigger("hello"));
        assert!(looks_like_trigger("<|deploy_mode|>"));
        assert!(looks_like_trigger("release_20260401_x"));
    }

    #[test]
    fn an_unparseable_gguf_header_is_a_finding_not_a_silent_skip() {
        let d = scratch("bad-gguf");
        let r = scan(&d, "trunc.gguf", b"GGUF\x03\x00\x00\x00\x01");
        assert!(rules(&r).contains(&"AI-MALFORMED-ARTIFACT".to_string()));
        fs::remove_dir_all(&d).ok();
    }

    /// Inside a scan, a finding names the file relative to the target root.
    ///
    /// This provider was the only one that did not. Found by running the same
    /// analyzer over PX4 on Windows and on Linux and comparing: 15,528 findings
    /// each, every rule's count identical, and 69 findings that differed only in
    /// carrying an absolute path — `C:/Users/.../boards/...` against
    /// `/mnt/c/Users/.../boards/...`. An absolute path is a baseline entry that
    /// will not match on another machine, a triage record that will not match
    /// either, and the scanning machine's directory layout in the report.
    ///
    /// `scan_file` still reports the path it is handed, because `sda ai scan
    /// <file>` names a file directly and there is no root to be relative to.
    #[test]
    fn a_finding_from_a_scan_names_its_file_relative_to_the_root() {
        let d = scratch("relative-paths");
        let sub = d.join("models");
        fs::create_dir_all(&sub).unwrap();
        let artifact = sub.join("broken.gguf");
        // A GGUF header that stops short: enough to be recognised and rejected.
        fs::write(&artifact, b"GGUF\x03\x00\x00\x00\x01").unwrap();

        let t = Target::new(&d).with_files(vec![sda_core::TargetFile {
            path: artifact.clone(),
            language: Language::ModelArtifact,
            bytes: 9,
        }]);
        let found = ModelScanner::new().analyze(&t, &RunOptions::default()).unwrap();
        assert!(!found.is_empty(), "the artifact is malformed and must be reported");

        for f in &found {
            let named = f.location.file.to_string_lossy().to_string();
            assert!(
                !named.contains(&d.to_string_lossy().to_string()),
                "`{named}` carries the root, so it would not match on another machine"
            );
            assert!(named.ends_with("broken.gguf"), "{named}");
        }

        // And the direct entry point keeps naming what it was given.
        let direct = ModelScanner::new().scan_file(&artifact).unwrap();
        assert_eq!(direct.path, artifact.to_string_lossy().to_string());

        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_unreadable_artifact_produces_a_finding_rather_than_aborting_the_scan() {
        let t = Target::new("/nope").with_files(vec![sda_core::TargetFile {
            path: "/nope/ghost.gguf".into(),
            language: Language::ModelArtifact,
            bytes: 1,
        }]);
        let f = ModelScanner::new().analyze(&t, &RunOptions::default()).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule.as_str(), "AI-SCAN-ERROR");
    }
}



