//! One scannable row, whatever it came from.
//!
//! A fetched corpus row, a hand-written fixture, a generated document and a repository `.md` file all
//! reach the scan loop as the same type. That is deliberate: the alternative is four scan loops, and
//! four places for a metric to be computed slightly differently — which is how the two earlier ad-hoc
//! measurements ended up irreconcilable.
//!
//! Everything optional on this type is optional because some sources genuinely do not have it. A
//! fixture has no upstream `source`; a downloaded row has no `injected_span`. `Option` rather than a
//! sentinel string, so a metric that needs span ground truth cannot silently compute over rows that
//! have none.

use serde::{Deserialize, Serialize};

/// A row to be scanned, and everything known about it that a metric might stratify on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    /// Identity within the slice. For fetched rows this is the first 16 hex digits of the content
    /// hash — see [`crate::manifest`] for why the hash is the identity and why 16 is checked for
    /// collisions rather than assumed safe. For committed rows it is the case id or the file path.
    pub id: String,
    /// The upstream source stratum. **Metrics are reported per source**, never blended, so this field
    /// is what makes a report defensible rather than decorative (Principle IV).
    pub source: String,
    /// The text to scan, verbatim.
    pub text: String,
    /// BCP-47-ish language tag as the corpus records it. `en` for everything adversarial in the
    /// primary corpus, which is Finding 4 and a declared gap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// `attack_technique` where the corpus labels one — 5.2% of positives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub technique: Option<String>,
    /// Where hostile text would reach an agent: `email_body`, `tool_result`, `skill_md`,
    /// `mcp_tool_description`, `file_read`, `repo_config`, `manifest`, `issue_body`. Present on
    /// fixtures and generated rows; absent on public-corpus rows, which do not record it and whose
    /// agentic subset is 0.45%.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// `easy` | `medium` | `hard`, on fixtures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<String>,
    /// Byte range of the injected payload, on generated rows only.
    ///
    /// **The unlock**, in `docs/research/indirect-structure.md` §5's words: every hypothesis about
    /// indirect injection is a hypothesis about a span, and every public corpus label is about a
    /// document. This field is the only span-level ground truth in the harness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injected_span: Option<(usize, usize)>,
    /// `calibration` | `report`, assigned by carrier on generated rows.
    ///
    /// Split by carrier and never by row. `document-map.md` §5.3 names this as the mitigation for the
    /// critique levelled at TaskTracker's evaluation — holding out attack types while sharing benign
    /// text between splits — so a carrier appearing in the threshold-selection set may not appear in
    /// the reporting set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split: Option<String>,
    /// Generated rows: which carrier and which payload, for the per-carrier and per-position ablations
    /// (M3, M4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<String>,
}

impl Row {
    /// A row whose only stratum is its source. The shape a fetched corpus row arrives in.
    pub fn new(id: impl Into<String>, source: impl Into<String>, text: impl Into<String>) -> Self {
        Row {
            id: id.into(),
            source: source.into(),
            text: text.into(),
            language: None,
            technique: None,
            context: None,
            difficulty: None,
            injected_span: None,
            split: None,
            carrier_id: None,
            payload_id: None,
            position: None,
        }
    }
}

/// One row's scan outcome, as written to the results file.
///
/// Flat and per-row rather than a summary, because a summary cannot be re-cut. Every metric `report`
/// produces — per source, per context, per position, per technique, direct against via-decode — is a
/// different grouping of this same file, and a results format that only held totals would need a
/// re-scan for each of them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowResult {
    pub id: String,
    pub source: String,
    /// `clean` | `risk_found` | `inconclusive`. Carried as the string the engine reports so a new
    /// outcome cannot be silently folded into an existing one.
    pub outcome: String,
    pub score: u8,
    pub risk: String,
    /// Whether the verdict reached the configured floor. Precomputed so that the report and the gate
    /// cannot disagree about what counts as a detection.
    pub detected: bool,
    /// Findings, in the engine's order.
    pub reasons: Vec<ResultReason>,
    /// Findings suppressed by a quoting context. Counted, because suppression is an accepted and
    /// unquantified false-negative channel (`docs/limits.md`, "Quoted payloads can suppress
    /// detection") and this is the first thing that can put a number on it.
    pub suppressed: usize,
    /// Causes of incompleteness, if any. An input over the size cap or a decoder that bailed out is
    /// **not** a clean verdict, and a harness that scored it as one would be reproducing the exact
    /// failure Principle I forbids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incomplete: Vec<String>,
    /// Strata carried through from the row so a report needs one file, not a join.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub technique: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split: Option<String>,
    /// Whether any finding's span overlaps `injected_span`. `None` when the row has no span ground
    /// truth, which is every row that was not generated.
    ///
    /// This is span localisation for the SHIPPED detectors — a real number about the current engine.
    /// It is not M1 from `document-map.md`, which asks whether the injected segment is the top
    /// register outlier and needs `DocumentMap` in the core first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_hit: Option<bool>,
}

/// One finding, reduced to what a metric groups by.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultReason {
    pub rule_id: String,
    pub class: String,
    pub start: usize,
    pub end: usize,
    /// The decode chain, empty for a direct match. `actionable-directive-results.md` §3 split
    /// detections this way and found it worth having: the decode channel was a small contributor to
    /// true positives and produced one of three prose false positives.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
}
