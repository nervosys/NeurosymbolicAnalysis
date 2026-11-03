//! Stable, human-readable identifiers.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! string_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
        }
        impl From<&str> for $name {
            fn from(s: &str) -> Self { Self(s.to_string()) }
        }
        impl From<String> for $name {
            fn from(s: String) -> Self { Self(s) }
        }
    };
}

string_id!(
    /// Identifies an analysis provider, e.g. `sda.static.c` or `ext.cppcheck`.
    ProviderId
);
string_id!(
    /// Identifies a rule within a standard, e.g. `MISRA-C-2023-15.5` or `RUST-2024-UNSAFE-01`.
    RuleId
);
string_id!(
    /// Content-addressed identity of a finding; stable across runs for unchanged code.
    FindingId
);

/// Compute a stable fingerprint from the parts that define a finding's identity.
///
/// Deliberately excludes line numbers beyond a coarse bucket so that unrelated
/// edits above a finding do not churn its identity across runs.
pub fn fingerprint(parts: &[&str]) -> FindingId {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0u8]);
    }
    let digest = h.finalize();
    let mut s = String::with_capacity(16);
    for b in &digest[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    FindingId(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let a = fingerprint(&["MISRA-C-2023-15.5", "src/main.c", "multiple returns"]);
        let b = fingerprint(&["MISRA-C-2023-15.5", "src/main.c", "multiple returns"]);
        let c = fingerprint(&["MISRA-C-2023-15.5", "src/other.c", "multiple returns"]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_str().len(), 16);
    }

    #[test]
    fn field_separator_prevents_collisions() {
        assert_ne!(fingerprint(&["ab", "c"]), fingerprint(&["a", "bc"]));
    }
}
