//! Portable attribution values. Acquisition and inference belong to the optional ML crate.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Versioned, canonical local inference recipe. Values describe effective settings, never paths.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct InferenceIdentity {
    version: u32,
    digest: String,
    fields: BTreeMap<String, String>,
}

impl InferenceIdentity {
    pub fn new(fields: BTreeMap<String, String>) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"please.local-inference\0v1\0");
        // Sorted UTF-8 key/value pairs, each prefixed with its u64 big-endian byte length.
        hash.update((fields.len() as u64).to_be_bytes());
        for (key, value) in &fields {
            for item in [key, value] {
                hash.update((item.len() as u64).to_be_bytes());
                hash.update(item.as_bytes());
            }
        }
        Self {
            version: 1,
            digest: format!("{:x}", hash.finalize()),
            fields,
        }
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn fields(&self) -> &BTreeMap<String, String> {
        &self.fields
    }
}

/// A window's byte envelope describes tokenized input, not exact attack localization.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MlWindowResult {
    pub index: usize,
    pub token_start: usize,
    pub token_end: usize,
    pub span: crate::Span,
    pub model_tokens: usize,
    pub raw_score: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_identity_is_order_independent_and_unambiguous() {
        let a = InferenceIdentity::new(BTreeMap::from([
            ("ab".into(), "c".into()),
            ("x".into(), "1".into()),
        ]));
        let b = InferenceIdentity::new(BTreeMap::from([
            ("x".into(), "1".into()),
            ("ab".into(), "c".into()),
        ]));
        assert_eq!(a, b);
        assert_ne!(
            a,
            InferenceIdentity::new(BTreeMap::from([
                ("a".into(), "bc".into()),
                ("x".into(), "1".into())
            ]))
        );
    }
}
