use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    ArtifactDetection,
    ContextualAlignment,
}

impl Surface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactDetection => "artifact_detection",
            Self::ContextualAlignment => "contextual_alignment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Split {
    Development,
    Holdout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPurpose {
    Development,
    Holdout,
    Instrument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactLabel {
    Injection,
    Benign,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextRelation {
    AlignedInstruction,
    ConflictingInstruction,
    NonInstruction,
    Indeterminate,
}

impl ContextRelation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AlignedInstruction => "aligned_instruction",
            Self::ConflictingInstruction => "conflicting_instruction",
            Self::NonInstruction => "non_instruction",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroundTruth {
    Artifact { label: ArtifactLabel },
    Contextual { relation: ContextRelation },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    pub resource: String,
    pub action: String,
    pub decision: PermissionDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedContext {
    pub context_id: String,
    pub task: String,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchCase {
    pub case_id: String,
    pub surface: Surface,
    pub source: String,
    pub provenance: String,
    pub ground_truth: GroundTruth,
    pub label_provenance: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_disagreement: Option<String>,
    pub group_id: String,
    pub family_id: String,
    pub split: Split,
    pub delivery_vector: String,
    #[serde(default)]
    pub techniques: Vec<String>,
    pub presentation_context: String,
    pub asset_path: PathBuf,
    pub asset_sha256: String,
    pub byte_length: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_context: Option<TrustedContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CasePackManifest {
    pub schema_version: String,
    pub pack_id: String,
    pub version: String,
    pub content_digest: String,
    pub created_at: String,
    pub creation_provenance: String,
    pub license_summary: String,
    pub purpose: PackPurpose,
    pub taxonomy_path: PathBuf,
    pub taxonomy_sha256: String,
    #[serde(default)]
    pub group_baselines: BTreeMap<String, String>,
    pub cases: Vec<BenchCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyManifest {
    pub schema_version: String,
    pub taxonomy_id: String,
    pub version: String,
    pub techniques: Vec<String>,
    pub delivery_vectors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureRecord {
    pub schema_version: String,
    pub pack_digest: String,
    pub case_id: String,
    pub input_sha256: String,
    pub normalized_sha256: String,
    pub family_id: String,
    pub use_kind: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PleaseMode {
    Product,
    Mechanism,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdapterManifest {
    /// The same advisory client and response contract as `plz jev`.
    Jev {
        model: String,
        max_requests: u64,
        max_errors: u64,
    },
    Please {
        mode: PleaseMode,
        profile: String,
        threshold: String,
        provenance_mapping: BTreeMap<String, String>,
        #[serde(default)]
        rules: Vec<PathBuf>,
        #[serde(default)]
        disabled_rules: Vec<String>,
    },
    Subprocess {
        program: PathBuf,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        sandbox_command: Vec<String>,
        executable_sha256: String,
        #[serde(default)]
        environment: BTreeMap<String, String>,
        network_capable: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NormalizerKind {
    PleaseArtifactV1,
    NativeV1 {
        #[serde(default)]
        positive_labels: Vec<String>,
        #[serde(default)]
        negative_labels: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizerManifest {
    pub normalizer_id: String,
    pub version: String,
    pub surface: Surface,
    pub mapping: NormalizerKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatingPoint {
    pub threshold: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemIdentities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemManifest {
    pub schema_version: String,
    pub system_id: String,
    pub version: String,
    pub adapter_version: String,
    pub configuration_identity: String,
    pub supported_surfaces: Vec<Surface>,
    pub requires_trusted_context: bool,
    pub deterministic: bool,
    pub review_authority: String,
    pub operating_point: OperatingPoint,
    pub identities: SystemIdentities,
    pub adapter: AdapterManifest,
    pub normalizers: Vec<NormalizerManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunLimits {
    pub max_input_bytes: u64,
    pub max_request_bytes: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub startup_timeout_ms: u64,
    pub case_timeout_ms: u64,
    /// Number of replacement process starts allowed after the initial start.
    pub max_restarts: u32,
    pub max_in_flight: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Offline,
    NetworkAllowed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentManifest {
    pub schema_version: String,
    pub experiment_id: String,
    pub version: String,
    pub pack_path: PathBuf,
    pub system_paths: Vec<PathBuf>,
    #[serde(default)]
    pub exposure_paths: Vec<PathBuf>,
    pub repetitions: u32,
    pub execution_mode: ExecutionMode,
    pub limits: RunLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Completed,
    Unsupported,
    Abstained,
    Timeout,
    Crashed,
    InvalidOutput,
    Unavailable,
}

impl CoverageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Unsupported => "unsupported",
            Self::Abstained => "abstained",
            Self::Timeout => "timeout",
            Self::Crashed => "crashed",
            Self::InvalidOutput => "invalid_output",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactDecision {
    Detected,
    NotDetected,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "surface", rename_all = "snake_case", deny_unknown_fields)]
pub enum NormalizedDecision {
    ArtifactDetection { decision: ArtifactDecision },
    ContextualAlignment { relation: ContextRelation },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEvidence {
    pub kind: String,
    pub start: u64,
    pub end: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeResponse {
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_permille: Option<u16>,
    #[serde(default)]
    pub evidence: Vec<NativeEvidence>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
    #[serde(default)]
    pub abstained: bool,
    #[serde(default)]
    pub remote_requests: u64,
    #[serde(default)]
    pub declared_cost_microusd: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOutput {
    pub transport: String,
    pub native_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<NativeResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTelemetry {
    pub elapsed_micros: u64,
    #[serde(default)]
    pub runner_overhead_micros: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_memory_bytes: Option<u64>,
    pub remote_requests: u64,
    pub declared_cost_microusd: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchResult {
    pub schema_version: String,
    pub row_id: String,
    pub run_id: String,
    pub request_id: String,
    pub pack_digest: String,
    pub case_id: String,
    pub case_digest: String,
    pub input_sha256: String,
    pub normalized_input_sha256: String,
    pub system_id: String,
    pub system_digest: String,
    pub normalizer_id: String,
    pub normalizer_version: String,
    pub repetition: u32,
    pub surface: Surface,
    pub source: String,
    pub provenance: String,
    pub group_id: String,
    pub family_id: String,
    pub split: Split,
    pub delivery_vector: String,
    pub techniques: Vec<String>,
    pub ground_truth: GroundTruth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_context_id: Option<String>,
    pub coverage: CoverageState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<RawOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized: Option<NormalizedDecision>,
    pub telemetry: ExecutionTelemetry,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

pub use crate::saved_run::SavedFile;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSystem {
    pub system_id: String,
    pub system_digest: String,
    pub manifest_path: PathBuf,
    pub adapter_version: String,
    pub normalizers: Vec<NormalizerManifest>,
    pub operating_point: OperatingPoint,
    pub runtime_identity: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_executable: Option<StagedExecutable>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_command: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedExecutable {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessTelemetry {
    pub system_id: String,
    pub system_digest: String,
    pub spawn_index: u32,
    pub stderr_bytes: u64,
    pub stderr_sha256: String,
    pub retained_stderr_hex: String,
    pub retained_stderr_sha256: String,
    pub stderr_overflow: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    pub terminated_by_runner: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    pub schema_version: String,
    pub run_id: String,
    pub status: String,
    pub experiment_id: String,
    pub experiment_digest: String,
    pub pack_id: String,
    pub pack_digest: String,
    #[serde(default)]
    pub group_baselines: BTreeMap<String, String>,
    pub ordered_case_digests: Vec<String>,
    pub systems: Vec<PlannedSystem>,
    pub repetitions: u32,
    pub execution_mode: ExecutionMode,
    pub limits: RunLimits,
    pub max_observed_in_flight: u32,
    #[serde(default)]
    pub processes: Vec<ProcessTelemetry>,
    pub host: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<SavedFile>,
}
