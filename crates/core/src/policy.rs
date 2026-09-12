//! Caller-owned scan configuration.
//!
//! Every value here belongs to the caller and is **never** derived from scanned content (FR-020). That
//! is not a stylistic point: a policy inferred from the text being analysed is a policy an attacker
//! writes, and the first thing they would turn off is the detector that catches them.
//!
//! Bounds are counted, not timed — bytes, depth, matches — because a wall-clock deadline needs a clock
//! and `std::time::Instant` does not work on `wasm32-unknown-unknown` (research D10). Counted bounds
//! are also deterministic, which SC-011's byte-identical output requires anyway. A wall-clock budget
//! belongs to whoever launched the process.

use crate::finalize::types::{DetectionClass, RiskLevel};

/// Default maximum input size: 1 MiB.
///
/// An order of magnitude above the largest single prompt in the evaluation corpus (82,300 bytes) while
/// staying far below anything that threatens the linear-time budget.
pub const DEFAULT_MAX_INPUT_BYTES: u64 = 1024 * 1024;

/// Default decode depth. Three layers of nesting covers observed obfuscation with room to spare;
/// beyond that the remainder is reported unexamined rather than chased.
pub const DEFAULT_MAX_DECODE_DEPTH: u8 = 3;

/// Default matches collected per rule.
///
/// This is the bound that keeps analysis linear. The matching engine guarantees `O(m·n)` for a single
/// search but `O(m·n²)` for iteration, because each match restarts a search — so an uncapped
/// all-matches scan is quadratic in input length, which is the denial-of-service vector the whole
/// design forbids. Capping at a constant makes it `O(K·m·n)` (research D2).
pub const DEFAULT_MAX_MATCHES_PER_RULE: u32 = 16;

/// Maximum observations retained across active and suppressed evidence.
pub const DEFAULT_MAX_OBSERVATIONS: u32 = 4096;

/// Default reasons reported per verdict. Bounded independently of input length (FR-007).
pub const DEFAULT_MAX_REASONS: u32 = 64;

/// Default excerpt length in bytes.
pub const DEFAULT_MAX_EXCERPT_BYTES: u32 = 256;

/// Every detection class, in a stable order.
///
/// Seven. Five after 002's T048 removed `Encoding`, which named a delivery mechanism rather than a kind of
/// finding; six after 003 added `AgentDirected`; seven after `ExternalAction`, which names the half of
/// indirect injection that asks the agent to act rather than to disclose. See [`DetectionClass`].
pub const ALL_CLASSES: [DetectionClass; 8] = [
    DetectionClass::Override,
    DetectionClass::Concealment,
    DetectionClass::Confusable,
    DetectionClass::Boundary,
    DetectionClass::Solicitation,
    DetectionClass::AgentDirected,
    DetectionClass::ExternalAction,
    DetectionClass::Privilege,
];

/// Compatibility vocabulary combining origin and purpose. New callers should set `InputProvenance`
/// and `ScanProfile` separately. Only `ScanPolicy::for_source` maps SecurityReference to reference analysis.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ScanSource {
    /// No caller-established provenance; the default profile is enforcement.
    #[default]
    Unspecified,
    /// Compatibility request for caller-provided reference material.
    SecurityReference,
    /// Compatibility provenance for tool output.
    UntrustedToolResponse,
    /// Compatibility provenance for user input.
    UntrustedUserInput,
}

impl ScanSource {
    /// Stable name used in verdict attribution.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::SecurityReference => "security_reference",
            Self::UntrustedToolResponse => "untrusted_tool_response",
            Self::UntrustedUserInput => "untrusted_user_input",
        }
    }
}

/// The caller's use of the scan. Formatting in the input cannot select a profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ScanProfile {
    #[default]
    Enforcement,
    ReferenceAnalysis,
}
impl ScanProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforcement => "enforcement",
            Self::ReferenceAnalysis => "reference_analysis",
        }
    }
}

/// Origin established by the host, independently of the purpose of analysis or review authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum InputProvenance {
    #[default]
    Unspecified,
    CallerProvided,
    UserInput,
    ToolResponse,
}
impl InputProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::CallerProvided => "caller_provided",
            Self::UserInput => "user_input",
            Self::ToolResponse => "tool_response",
        }
    }
}

/// Caller-assessed impact of an admitted classifier finding, independent of its raw score.
/// The default 75 is a provisional policy choice, not a model calibration claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct MlImpact(u8);
impl MlImpact {
    pub fn new(severity: u8) -> Result<Self, &'static str> {
        if severity > 100 {
            Err("ML impact must be in 0..=100")
        } else {
            Ok(Self(severity))
        }
    }
    pub fn severity(self) -> u8 {
        self.0
    }
}
impl Default for MlImpact {
    fn default() -> Self {
        Self(75)
    }
}

/// Configuration governing one scan.
///
/// Defaults are **provisional** pending calibration against per-source corpus metrics, and
/// `docs/limits.md` says so rather than implying a calibration that has not happened.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ScanPolicy {
    /// Compatibility input. Prefer `provenance` and `profile` for new integrations.
    pub source: ScanSource,
    pub provenance: InputProvenance,
    pub profile: ScanProfile,
    pub ml_impact: MlImpact,
    /// Host-established task and permissions, never derived from scanned content.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            rename = "caller_context_id",
            serialize_with = "crate::context::serialize_identity"
        )
    )]
    pub caller_context: Option<crate::context::CallerContext>,
    /// Optional caller-owned permissions for experimental protected-data export detection.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub export_policy: Option<crate::ExportPolicy>,
    /// Inputs larger than this are not analysed; the verdict is inconclusive (FR-017).
    pub max_input_bytes: u64,
    /// Nested decoding stops here, and the unexamined remainder is reported (FR-018).
    pub max_decode_depth: u8,
    /// Matches collected per rule before saturation is recorded (research D2).
    pub max_matches_per_rule: u32,
    /// Total retained observations, independent of reporting limits. Exhaustion is a coverage gap.
    pub max_observations: u32,
    /// Reasons displayed per list; shortening never changes analysis or decisions.
    pub max_reasons: u32,
    /// Excerpt length before truncation (FR-021).
    pub max_excerpt_bytes: u32,
    /// The band at or above which a caller's tooling treats a verdict as actionable (FR-029).
    ///
    /// Recorded with the verdict; the caller applies it to risk findings (FR-006).
    pub threshold: RiskLevel,
    /// Active detection classes (FR-015). Order-insensitive; a `Vec` rather than a set so iteration
    /// order is deterministic (SC-011).
    pub classes: Vec<DetectionClass>,
    /// Optional quote suppression within reference analysis. Enforcement always ignores this preference.
    pub suppress_in_quotes: bool,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self {
            source: ScanSource::Unspecified,
            provenance: InputProvenance::Unspecified,
            profile: ScanProfile::Enforcement,
            ml_impact: MlImpact::default(),
            caller_context: None,
            export_policy: None,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_decode_depth: DEFAULT_MAX_DECODE_DEPTH,
            max_matches_per_rule: DEFAULT_MAX_MATCHES_PER_RULE,
            max_observations: DEFAULT_MAX_OBSERVATIONS,
            max_reasons: DEFAULT_MAX_REASONS,
            max_excerpt_bytes: DEFAULT_MAX_EXCERPT_BYTES,
            threshold: RiskLevel::High,
            classes: ALL_CLASSES.to_vec(),
            suppress_in_quotes: false,
        }
    }
}

impl ScanPolicy {
    /// Review identity excludes report-only settings. Their defaults provide a canonical representation.
    pub(crate) fn analysis_identity(&self) -> Self {
        Self {
            max_reasons: DEFAULT_MAX_REASONS,
            max_excerpt_bytes: DEFAULT_MAX_EXCERPT_BYTES,
            ..self.clone()
        }
    }

    /// Compatibility adapter for the former combined source/use enum. A security reference explicitly
    /// selects reference analysis; every other source selects enforcement.
    pub fn for_source(source: ScanSource) -> Self {
        let mut policy = if source == ScanSource::SecurityReference {
            Self::reference_analysis()
        } else {
            Self::default()
        };
        policy.source = source;
        policy.provenance = policy.effective_provenance();
        policy
    }

    pub fn reference_analysis() -> Self {
        Self {
            profile: ScanProfile::ReferenceAnalysis,
            suppress_in_quotes: true,
            ..Self::default()
        }
    }

    pub fn effective_provenance(&self) -> InputProvenance {
        if self.provenance != InputProvenance::Unspecified {
            return self.provenance;
        }
        match self.source {
            ScanSource::Unspecified => InputProvenance::Unspecified,
            ScanSource::SecurityReference => InputProvenance::CallerProvided,
            ScanSource::UntrustedUserInput => InputProvenance::UserInput,
            ScanSource::UntrustedToolResponse => InputProvenance::ToolResponse,
        }
    }

    pub fn suppresses_quotes(&self) -> bool {
        self.profile == ScanProfile::ReferenceAnalysis && self.suppress_in_quotes
    }

    /// Snapshot the values actually used by the engine for attribution.
    pub(crate) fn effective(&self) -> Self {
        Self {
            suppress_in_quotes: self.suppresses_quotes(),
            provenance: self.effective_provenance(),
            ..self.clone()
        }
    }

    /// True when `class` is active under this policy.
    pub fn is_active(&self, class: DetectionClass) -> bool {
        self.classes.contains(&class)
    }
}

impl std::str::FromStr for ScanProfile {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "enforcement" => Ok(Self::Enforcement),
            "reference-analysis" | "reference_analysis" => Ok(Self::ReferenceAnalysis),
            _ => Err("profile must be enforcement or reference-analysis"),
        }
    }
}
impl std::str::FromStr for InputProvenance {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unspecified" => Ok(Self::Unspecified),
            "caller-provided" | "caller_provided" => Ok(Self::CallerProvided),
            "user-input" | "user_input" => Ok(Self::UserInput),
            "tool-response" | "tool_response" => Ok(Self::ToolResponse),
            _ => {
                Err("provenance must be unspecified, caller-provided, user-input, or tool-response")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_values() {
        let p = ScanPolicy::default();
        assert_eq!(p.max_input_bytes, 1024 * 1024);
        assert_eq!(p.max_decode_depth, 3);
        assert_eq!(p.max_matches_per_rule, 16);
        assert_eq!(p.max_reasons, 64);
        assert_eq!(p.max_excerpt_bytes, 256);
        assert_eq!(p.threshold, RiskLevel::High);
        assert!(!p.suppresses_quotes());
        assert_eq!(p.profile, ScanProfile::Enforcement);
    }

    #[test]
    fn all_classes_are_active_by_default() {
        let p = ScanPolicy::default();
        for class in ALL_CLASSES {
            assert!(p.is_active(class), "{class:?} should be active by default");
        }
        assert_eq!(p.classes.len(), 8, "ALL_CLASSES must cover every variant");
    }

    #[test]
    fn max_input_default_exceeds_the_largest_corpus_prompt() {
        // The largest single prompt measured in the evaluation corpus is 82,300 bytes
        // (docs/research/corpus-analysis.md). The default must clear it comfortably, or the scanner
        // would report inconclusive on inputs the corpus itself contains.
        assert!(ScanPolicy::default().max_input_bytes > 82_300);
    }
}
