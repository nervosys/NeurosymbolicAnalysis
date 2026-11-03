//! Native parsers for the model container formats found on embedded systems.
//!
//! Each parser reads only headers and metadata — never tensor payloads — so
//! scanning a 30 GB checkpoint costs a few kilobytes of I/O. Each also treats
//! every field as attacker-controlled, because on a device that loads a model
//! from flash or from the network, it is.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The container format of a model artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Gguf,
    Safetensors,
    /// A bare Python pickle.
    Pickle,
    /// A zip archive containing pickles — the PyTorch `.pt`/`.pth` layout.
    TorchZip,
    Onnx,
    TfLite,
    /// Recognised as a model artifact but of an unknown container.
    Unknown,
}

impl Format {
    pub fn as_str(&self) -> &'static str {
        match self {
            Format::Gguf => "gguf",
            Format::Safetensors => "safetensors",
            Format::Pickle => "pickle",
            Format::TorchZip => "torch-zip",
            Format::Onnx => "onnx",
            Format::TfLite => "tflite",
            Format::Unknown => "unknown",
        }
    }

    /// Whether loading this format can execute code by design.
    ///
    /// This is the single most important property of a model file, and it is a
    /// property of the *container*, not of the model inside it.
    pub fn executes_on_load(&self) -> bool {
        matches!(self, Format::Pickle | Format::TorchZip)
    }
}

/// Identify a format from its leading bytes and, failing that, its extension.
pub fn detect(head: &[u8], extension: &str) -> Format {
    if head.starts_with(b"GGUF") {
        return Format::Gguf;
    }
    if head.starts_with(b"PK\x03\x04") {
        return Format::TorchZip;
    }
    if head.starts_with(b"TFL3") || (head.len() > 8 && &head[4..8] == b"TFL3") {
        return Format::TfLite;
    }
    // safetensors begins with a little-endian u64 header length followed by `{`.
    //
    // This is checked *before* pickle, and the ordering is load-bearing: pickle
    // has no magic number, so it is recognised from a single leading opcode
    // byte, and a safetensors header whose length happens to be 40, 99, 123 or
    // 125 puts `(`, `c`, `{` or `}` in that position. Testing the stronger
    // signature first stops a legitimate safetensors file from being scanned —
    // and reported — as a pickle.
    if head.len() >= 9 {
        let Ok(prefix) = <[u8; 8]>::try_from(&head[..8]) else { return Format::Unknown };
        let n = u64::from_le_bytes(prefix);
        if n > 0 && n < (1 << 32) && head[8] == b'{' {
            return Format::Safetensors;
        }
    }
    if crate::pickle::looks_like_pickle(head) {
        return Format::Pickle;
    }
    // ONNX is protobuf; there is no magic, but the first field is almost always
    // `ir_version` (field 1, varint) and the producer string appears early.
    if head.first() == Some(&0x08) && head.len() > 16 {
        return Format::Onnx;
    }
    match extension {
        "gguf" | "ggml" => Format::Gguf,
        "safetensors" => Format::Safetensors,
        "onnx" => Format::Onnx,
        "tflite" => Format::TfLite,
        "pkl" | "pickle" => Format::Pickle,
        "pt" | "pth" | "ckpt" | "bin" => Format::TorchZip,
        _ => Format::Unknown,
    }
}

// --- GGUF ------------------------------------------------------------------

/// A metadata value from a GGUF header.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GgufValue {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(String),
    Array(Vec<GgufValue>),
}

impl GgufValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            GgufValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn len(&self) -> usize {
        match self {
            GgufValue::Array(v) => v.len(),
            _ => 1,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A parsed GGUF header.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GgufHeader {
    pub version: u32,
    pub tensor_count: u64,
    pub metadata: BTreeMap<String, GgufValue>,
    pub tensor_names: Vec<String>,
    /// Fields that failed validation. Present in the struct rather than thrown
    /// away because a malformed header is a security finding, not a parse error.
    pub anomalies: Vec<String>,
}

impl GgufHeader {
    pub fn architecture(&self) -> Option<&str> {
        self.metadata.get("general.architecture").and_then(|v| v.as_str())
    }
    pub fn name(&self) -> Option<&str> {
        self.metadata.get("general.name").and_then(|v| v.as_str())
    }
    pub fn license(&self) -> Option<&str> {
        self.metadata.get("general.license").and_then(|v| v.as_str())
    }
    /// The chat template, if the model ships one. This is executable-ish content:
    /// it is a Jinja template that the runtime renders with user input.
    pub fn chat_template(&self) -> Option<&str> {
        self.metadata.get("tokenizer.chat_template").and_then(|v| v.as_str())
    }
    pub fn vocabulary_size(&self) -> Option<usize> {
        self.metadata.get("tokenizer.ggml.tokens").map(|v| v.len())
    }
    pub fn tokens(&self) -> Vec<&str> {
        match self.metadata.get("tokenizer.ggml.tokens") {
            Some(GgufValue::Array(v)) => v.iter().filter_map(|t| t.as_str()).collect(),
            _ => Vec::new(),
        }
    }
}

/// Parse a GGUF header. Reads metadata only; tensor data is never touched.
pub fn parse_gguf(data: &[u8]) -> Result<GgufHeader, String> {
    let mut r = Reader::new(data);
    if r.take(4)? != b"GGUF" {
        return Err("not a GGUF file".into());
    }
    let mut h = GgufHeader { version: r.u32()?, ..Default::default() };
    h.tensor_count = r.u64()?;
    let kv_count = r.u64()?;

    // A header claiming millions of entries in a small file is either corrupt or
    // an attempt to make the parser allocate; refuse either way.
    if kv_count > 1_000_000 || h.tensor_count > 10_000_000 {
        return Err(format!(
            "implausible header: {kv_count} metadata entries and {} tensors",
            h.tensor_count
        ));
    }

    for _ in 0..kv_count {
        let key = r.gguf_string()?;
        let vt = r.u32()?;
        let value = r.gguf_value(vt)?;
        if h.metadata.insert(key.clone(), value).is_some() {
            h.anomalies.push(format!("duplicate metadata key `{key}`"));
        }
    }

    for _ in 0..h.tensor_count.min(4096) {
        let name = match r.gguf_string() {
            Ok(n) => n,
            Err(_) => {
                h.anomalies.push("tensor table is truncated".into());
                break;
            }
        };
        let n_dims = r.u32().unwrap_or(0);
        if n_dims > 8 {
            h.anomalies.push(format!("tensor `{name}` claims {n_dims} dimensions"));
            break;
        }
        for _ in 0..n_dims {
            let _ = r.u64();
        }
        let _ = r.u32(); // dtype
        let _ = r.u64(); // offset
        h.tensor_names.push(name);
    }

    Ok(h)
}

// --- safetensors -----------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TensorEntry {
    pub name: String,
    pub dtype: String,
    pub shape: Vec<u64>,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SafetensorsHeader {
    pub tensors: Vec<TensorEntry>,
    pub metadata: BTreeMap<String, String>,
    pub anomalies: Vec<String>,
    /// Total file size, used to validate the declared offsets.
    pub file_size: u64,
}

impl SafetensorsHeader {
    pub fn total_bytes(&self) -> u64 {
        self.tensors.iter().map(|t| t.end.saturating_sub(t.start)).sum()
    }
}

/// Parse a safetensors header.
///
/// safetensors exists precisely because pickle is unsafe, so the format itself
/// cannot execute code. What it *can* do is lie about offsets, and a runtime
/// that maps the file and trusts them will read outside the buffer — so the
/// offsets are validated here rather than assumed.
pub fn parse_safetensors(data: &[u8]) -> Result<SafetensorsHeader, String> {
    if data.len() < 8 {
        return Err("file is too short to contain a safetensors header".into());
    }
    let prefix = <[u8; 8]>::try_from(&data[..8])
        .map_err(|_| "file is too short to contain a safetensors header".to_string())?;
    let n = u64::from_le_bytes(prefix);
    if n as usize > data.len().saturating_sub(8) {
        return Err(format!(
            "declared header length {n} exceeds the {} bytes that follow it",
            data.len() - 8
        ));
    }
    let json = std::str::from_utf8(&data[8..8 + n as usize])
        .map_err(|_| "header is not valid UTF-8".to_string())?;
    let parsed: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("header is not valid JSON: {e}"))?;

    let mut h = SafetensorsHeader { file_size: data.len() as u64, ..Default::default() };
    let data_start = 8 + n;

    let Some(obj) = parsed.as_object() else {
        return Err("header is not a JSON object".into());
    };

    for (key, value) in obj {
        if key == "__metadata__" {
            if let Some(m) = value.as_object() {
                for (k, v) in m {
                    h.metadata.insert(k.clone(), v.as_str().unwrap_or_default().to_string());
                }
            }
            continue;
        }
        let dtype = value.get("dtype").and_then(|d| d.as_str()).unwrap_or("?").to_string();
        let shape: Vec<u64> = value
            .get("shape")
            .and_then(|s| s.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
            .unwrap_or_default();
        let offsets: Vec<u64> = value
            .get("data_offsets")
            .and_then(|s| s.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
            .unwrap_or_default();

        let (start, end) = match offsets.as_slice() {
            [a, b] => (*a, *b),
            _ => {
                h.anomalies.push(format!("tensor `{key}` has no usable data_offsets"));
                (0, 0)
            }
        };

        if end < start {
            h.anomalies.push(format!("tensor `{key}` has an inverted range [{start}, {end})"));
        }
        // Saturating: the offsets are the file's, and a wrapped sum read as in
        // bounds, hiding exactly the header this check exists to catch.
        if data_start.saturating_add(end) > h.file_size {
            h.anomalies.push(format!(
                "tensor `{key}` declares data up to byte {} but the file is {} bytes — a runtime \
                 that maps this file and trusts the header will read out of bounds",
                data_start.saturating_add(end),
                h.file_size
            ));
        }
        h.tensors.push(TensorEntry { name: key.clone(), dtype, shape, start, end });
    }

    Ok(h)
}

// --- reader ----------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.data.len() {
            return Err(format!("truncated at byte {}", self.pos));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read a fixed-width array.
    ///
    /// Exists so the integer readers below need no `unwrap`. The conversion
    /// cannot fail once `take` has succeeded — but "cannot fail" is a proof the
    /// reader has to reconstruct, and this file parses attacker-controlled
    /// model headers, which is the worst place to ask anyone to take that on
    /// trust.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let at = self.pos;
        <[u8; N]>::try_from(self.take(N)?)
            .map_err(|_| format!("short read of {N} bytes at byte {at}"))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array::<8>()?))
    }
    fn gguf_string(&mut self) -> Result<String, String> {
        let n = self.u64()? as usize;
        // A string longer than the remaining file is a corrupt or hostile length.
        if n > self.data.len() - self.pos {
            return Err(format!("string length {n} exceeds the remaining file"));
        }
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
    fn gguf_value(&mut self, vt: u32) -> Result<GgufValue, String> {
        self.gguf_value_at(vt, 0)
    }
    /// Arrays nest, and each level recursed: a file of nested arrays overflowed
    /// the stack. Real metadata nests one or two deep.
    fn gguf_value_at(&mut self, vt: u32, depth: u32) -> Result<GgufValue, String> {
        if depth > 32 {
            return Err(format!("arrays nested more than 32 deep at byte {}", self.pos));
        }
        Ok(match vt {
            0 => GgufValue::Int(self.array::<1>()?[0] as i64),
            1 => GgufValue::Int(self.array::<1>()?[0] as i8 as i64),
            2 => GgufValue::Int(u16::from_le_bytes(self.array::<2>()?) as i64),
            3 => GgufValue::Int(i16::from_le_bytes(self.array::<2>()?) as i64),
            4 => GgufValue::Int(self.u32()? as i64),
            5 => GgufValue::Int(self.u32()? as i32 as i64),
            6 => GgufValue::Float(f32::from_le_bytes(self.array::<4>()?) as f64),
            7 => GgufValue::Bool(self.take(1)?[0] != 0),
            8 => GgufValue::Str(self.gguf_string()?),
            9 => {
                let elem = self.u32()?;
                let count = self.u64()?;
                if count > 10_000_000 {
                    return Err(format!("array claims {count} elements"));
                }
                let mut v = Vec::with_capacity(count.min(1024) as usize);
                for _ in 0..count {
                    v.push(self.gguf_value_at(elem, depth + 1)?);
                }
                GgufValue::Array(v)
            }
            10 => GgufValue::Int(self.u64()? as i64),
            11 => GgufValue::Int(self.u64()? as i64),
            12 => GgufValue::Float(f64::from_le_bytes(self.array::<8>()?)),
            other => return Err(format!("unknown GGUF value type {other}")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gguf_string(s: &str) -> Vec<u8> {
        let mut v = (s.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(s.as_bytes());
        v
    }

    fn minimal_gguf(kvs: &[(&str, &str)]) -> Vec<u8> {
        let mut v = b"GGUF".to_vec();
        v.extend_from_slice(&3u32.to_le_bytes()); // version
        v.extend_from_slice(&0u64.to_le_bytes()); // tensor count
        v.extend_from_slice(&(kvs.len() as u64).to_le_bytes());
        for (k, val) in kvs {
            v.extend_from_slice(&gguf_string(k));
            v.extend_from_slice(&8u32.to_le_bytes()); // string type
            v.extend_from_slice(&gguf_string(val));
        }
        v
    }

    fn safetensors(header: &str, payload: usize) -> Vec<u8> {
        let mut v = (header.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(header.as_bytes());
        v.extend_from_slice(&vec![0u8; payload]);
        v
    }

    #[test]
    fn detects_formats_by_magic_before_extension() {
        assert_eq!(detect(b"GGUF\x03\x00\x00\x00", "bin"), Format::Gguf);
        assert_eq!(detect(b"PK\x03\x04", "pt"), Format::TorchZip);
        assert_eq!(detect(&[0x80, 0x04, b'c'], "bin"), Format::Pickle);
        assert_eq!(detect(&safetensors("{\"a\":1}", 0), "bin"), Format::Safetensors);
    }

    #[test]
    fn a_safetensors_header_length_colliding_with_a_pickle_opcode_is_still_safetensors() {
        // Header length 125 puts `}` — a pickle opcode — in the first byte.
        let header = format!("{{{}}}", "\"x\":1");
        let padded = format!("{}{}", header, " ".repeat(125 - header.len()));
        assert_eq!(padded.len(), 125);
        assert_eq!(detect(&safetensors(&padded, 0), "bin"), Format::Safetensors);
    }

    #[test]
    fn falls_back_to_extension_when_magic_is_absent() {
        assert_eq!(detect(b"", "safetensors"), Format::Safetensors);
        assert_eq!(detect(b"", "onnx"), Format::Onnx);
        assert_eq!(detect(b"", "txt"), Format::Unknown);
    }

    #[test]
    fn only_pickle_bearing_containers_execute_on_load() {
        assert!(Format::Pickle.executes_on_load());
        assert!(Format::TorchZip.executes_on_load());
        assert!(!Format::Safetensors.executes_on_load());
        assert!(!Format::Gguf.executes_on_load());
    }

    #[test]
    fn parses_gguf_metadata() {
        let data = minimal_gguf(&[
            ("general.architecture", "llama"),
            ("general.name", "tiny-test"),
            ("general.license", "apache-2.0"),
        ]);
        let h = parse_gguf(&data).unwrap();
        assert_eq!(h.version, 3);
        assert_eq!(h.architecture(), Some("llama"));
        assert_eq!(h.name(), Some("tiny-test"));
        assert_eq!(h.license(), Some("apache-2.0"));
        assert!(h.anomalies.is_empty());
    }

    #[test]
    fn a_gguf_header_claiming_absurd_counts_is_refused_not_allocated() {
        let mut v = b"GGUF".to_vec();
        v.extend_from_slice(&3u32.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend_from_slice(&u64::MAX.to_le_bytes()); // kv_count
        let err = parse_gguf(&v).unwrap_err();
        assert!(err.contains("implausible"));
    }

    #[test]
    fn a_gguf_string_length_past_the_end_is_an_error_not_a_panic() {
        let mut v = b"GGUF".to_vec();
        v.extend_from_slice(&3u32.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&u64::MAX.to_le_bytes()); // key length
        assert!(parse_gguf(&v).is_err());
    }

    #[test]
    fn duplicate_gguf_keys_are_recorded_as_anomalies() {
        let data = minimal_gguf(&[("general.name", "a"), ("general.name", "b")]);
        let h = parse_gguf(&data).unwrap();
        assert!(h.anomalies.iter().any(|a| a.contains("duplicate")));
    }

    #[test]
    fn parses_safetensors_header_and_metadata() {
        let header = r#"{"__metadata__":{"format":"pt"},"w":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}"#;
        let h = parse_safetensors(&safetensors(header, 16)).unwrap();
        assert_eq!(h.tensors.len(), 1);
        assert_eq!(h.tensors[0].dtype, "F32");
        assert_eq!(h.tensors[0].shape, vec![2, 2]);
        assert_eq!(h.metadata.get("format").map(|s| s.as_str()), Some("pt"));
        assert!(h.anomalies.is_empty());
    }

    #[test]
    fn safetensors_offsets_past_the_end_of_file_are_flagged() {
        // Declares 4 KB of tensor data in a file with 16 bytes of payload.
        let header = r#"{"w":{"dtype":"F32","shape":[1024],"data_offsets":[0,4096]}}"#;
        let h = parse_safetensors(&safetensors(header, 16)).unwrap();
        assert!(
            h.anomalies.iter().any(|a| a.contains("out of bounds")),
            "anomalies: {:?}",
            h.anomalies
        );
    }

    /// An end offset of `u64::MAX` wrapped the bounds check and read as in
    /// bounds. Found by a security audit.
    #[test]
    fn a_wrapping_safetensors_offset_is_still_out_of_bounds() {
        let header = r#"{"w":{"dtype":"F32","shape":[4],"data_offsets":[0,18446744073709551615]}}"#;
        let h = parse_safetensors(&safetensors(header, 16)).unwrap();
        assert!(h.anomalies.iter().any(|a| a.contains("out of bounds")), "{:?}", h.anomalies);
    }

    /// Nested arrays recursed once per level, and 80,000 of them overflowed the
    /// stack. Found by a security audit.
    #[test]
    fn deeply_nested_gguf_arrays_are_an_error_not_a_stack_overflow() {
        let mut v = b"GGUF".to_vec();
        v.extend_from_slice(&3u32.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&gguf_string("k"));
        v.extend_from_slice(&9u32.to_le_bytes());
        for _ in 0..80_000 {
            v.extend_from_slice(&9u32.to_le_bytes()); // an array of arrays
            v.extend_from_slice(&1u64.to_le_bytes()); // of one
        }
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_gguf(&v).unwrap_err().contains("nested"));
    }

    #[test]
    fn inverted_safetensors_ranges_are_flagged() {
        let header = r#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[64,0]}}"#;
        let h = parse_safetensors(&safetensors(header, 128)).unwrap();
        assert!(h.anomalies.iter().any(|a| a.contains("inverted")));
    }

    #[test]
    fn a_declared_header_longer_than_the_file_is_rejected() {
        let mut v = 999_999u64.to_le_bytes().to_vec();
        v.extend_from_slice(b"{}");
        assert!(parse_safetensors(&v).unwrap_err().contains("exceeds"));
    }

    #[test]
    fn gguf_tokenizer_arrays_are_reachable_for_trigger_analysis() {
        let mut v = b"GGUF".to_vec();
        v.extend_from_slice(&3u32.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&gguf_string("tokenizer.ggml.tokens"));
        v.extend_from_slice(&9u32.to_le_bytes()); // array
        v.extend_from_slice(&8u32.to_le_bytes()); // of strings
        v.extend_from_slice(&2u64.to_le_bytes());
        v.extend_from_slice(&gguf_string("hello"));
        v.extend_from_slice(&gguf_string("<|endoftext|>"));

        let h = parse_gguf(&v).unwrap();
        assert_eq!(h.vocabulary_size(), Some(2));
        assert_eq!(h.tokens(), vec!["hello", "<|endoftext|>"]);
    }
}

