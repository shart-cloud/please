//! Trusted task and permission context supplied by the calling application.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum BoundaryKind {
    InstructionHierarchy,
    HiddenApplicationContext,
    ToolActions,
    ProtectedDataDestinations,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct Boundary {
    pub kind: BoundaryKind,
    /// The objects/actions to which this constraint applies, without secret values.
    pub scope: String,
    pub constraint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct ContextCompleteness {
    pub relevant: Vec<BoundaryKind>,
    pub known: Vec<BoundaryKind>,
    pub unavailable: Vec<BoundaryKind>,
}

/// Caller-owned configuration. Never populate these fields from the document or model response.
/// `relevant` is the host's attestation of the scopes needed to adjudicate this document's use.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct CallerContext {
    pub task_context: Option<String>,
    pub boundaries: Vec<Boundary>,
    pub context_completeness: ContextCompleteness,
}

impl CallerContext {
    pub fn identity(&self) -> String {
        use sha2::{Digest, Sha256};
        format!(
            "{:x}",
            Sha256::digest(format!("caller-context-v1:{self:?}"))
        )
    }
}

#[cfg(feature = "serde")]
pub(crate) fn serialize_identity<S: serde::Serializer>(
    context: &Option<CallerContext>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::Serialize;
    context
        .as_ref()
        .map(CallerContext::identity)
        .serialize(serializer)
}
