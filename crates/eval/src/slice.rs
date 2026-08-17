//! The corpus slice model, parsed from `corpus/slices.toml`.
//!
//! A *slice* is one named population with one label: `pos_llmail` is 28,174 rows that are attacks,
//! `neg_orbench` is 3,000 rows that are not. Metrics are reported per slice and, within a slice, per
//! source — never blended — because `docs/research/corpus-analysis.md` Finding 1 established that an
//! aggregate over this corpus is a score on `jayavibhav-PI`.
//!
//! The file replaces a shell history. Both previously-published measurements
//! (`docs/research/actionable-directive-results.md`, `docs/research/judge-precision-results.md`) were
//! produced by ad-hoc scripts, and `docs/limits.md` records the cost: two runs of the same
//! measurement disagreed by a factor of twenty on the size of the concealment false-positive
//! population, and neither could be re-derived. A slice definition that lives in a reviewed file, with
//! the SQL that produced it, is the fix.

use serde::Deserialize;
use std::collections::BTreeMap;

use crate::Result;

/// What a slice's rows are, for scoring purposes.
///
/// Three variants rather than two. A hard negative is not merely a negative: it is a population
/// *chosen* to be difficult, so it is the one the gate is entitled to run against. Blending OR-Bench's
/// deliberate over-refusal traps into the same denominator as ordinary benign chatter would let an
/// easy population dilute a gate that exists to be hard to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SliceKind {
    /// Rows that are attacks. Detection rate is measured here.
    Positive,
    /// Rows that are not attacks. False-positive rate is measured here.
    Negative,
    /// Negatives chosen for difficulty — an over-refusal control set, security prose, matched
    /// carriers. The gate's denominator.
    HardNegative,
}

impl SliceKind {
    pub fn is_positive(self) -> bool {
        self == SliceKind::Positive
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SliceKind::Positive => "positive",
            SliceKind::Negative => "negative",
            SliceKind::HardNegative => "hard_negative",
        }
    }
}

/// Where a slice's rows come from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Origin {
    /// A DuckDB query against the pinned upstream dataset, run through the `hf` CLI. Needs the
    /// network and an approved gate; the text it returns is cached and never committed.
    Query { sql: String },
    /// Rows this repository owns and commits: `tests/fixtures/*.jsonl`, the generated corpus, the
    /// documentation tree. No network, and available in CI.
    Local { reader: LocalReader },
}

/// The committed corpora, each with its own reader in [`crate::cases`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalReader {
    /// Labelled cases from `tests/fixtures/*.jsonl`, filtered to `expected = injection`.
    FixturesPositive,
    /// The same file set, filtered to `expected = benign`.
    FixturesBenign,
    /// Generated rows carrying a payload, from `corpus/generated.jsonl`.
    GeneratedPositive,
    /// Generated carriers with no payload — the matched negative. Identical to its positive in every
    /// respect except the thing under test, which is what makes it worth more than a downloaded one.
    GeneratedMatchedNegative,
    /// Every `.md` under `docs/` and `specs/`. Security prose: documents *about* payloads, containing
    /// payload strings as subject matter. `docs/limits.md` calls this the false-positive class most
    /// likely to make a developer disable the firewall, and
    /// `docs/research/actionable-directive-results.md` §2.3 shows it firing on this repository's own
    /// research.
    RepositoryProse,
}

/// A source whose hit rate is an artifact of its serialisation rather than of its content.
///
/// Exclusions are data in a reviewed file rather than a footnote in a results document, because the
/// first one found is worth 8.9 percentage points. Every SPML row begins `[System: …]` — that is SPML's
/// serialisation format, not its content — and `boundary.forged_role_marker` fires on all 400.
/// `actionable-directive-results.md` §2.1: *"any FP rate computed over this corpus without excluding it
/// is wrong by 8.9 percentage points."*
///
/// **It applies to positive slices too, and that is not symmetry for its own sake.** The same wrapper
/// appears in TensorTrust, whose rows are labelled adversarial — so the identical non-fact reads as a
/// 100% false-positive rate on one slice and a 100% *detection* rate on another. A mechanism that
/// excluded only the embarrassing direction would be a mechanism for flattering the tool.
///
/// The rows are still fetched, still scanned, and still reported. What an exclusion changes is two
/// things: the hits do not count against the gate, and the report prints the caveat beside the number.
/// A dropped population would hide a real defect; a reported-but-caveated one names it.
#[derive(Debug, Clone, Deserialize)]
pub struct ExcludedSource {
    pub source: String,
    pub reason: String,
}

/// One slice definition.
#[derive(Debug, Clone, Deserialize)]
pub struct Slice {
    /// Stable identifier, e.g. `pos_llmail`. Names the cache file, the manifest, and every row in
    /// every report, so it is not renamed casually.
    pub id: String,
    pub kind: SliceKind,
    /// One line a reader can understand without opening the SQL.
    pub label: String,
    pub origin: Origin,
    /// Whether this slice counts toward the false-positive gate. Meaningless on a positive slice, and
    /// [`SliceSet::load`] rejects the combination rather than silently ignoring it.
    #[serde(default)]
    pub gate_eligible: bool,
    /// Sources within this slice whose hits are reported but not gated.
    #[serde(default)]
    pub excluded_sources: Vec<ExcludedSource>,
    /// The false-positive rate this slice achieves today, in per-mille — the gate's regression floor.
    ///
    /// Two thresholds rather than one, and the reason is `crates/core/tests/scaling.rs`: SC-004a's
    /// 10 MB/s throughput criterion is not met, so that file asserts against a measured floor and
    /// reports the criterion separately, because *"an absolute figure measured there is not a weaker
    /// signal, it is a meaningless one."* The same applies to a false-positive gate whose criterion is
    /// 1% and whose measured rate on security prose is 31.0%: a gate that is red every day is a gate
    /// people learn to ignore, while a gate that goes red on the thirteenth prose document catches the
    /// change that made it thirteen.
    ///
    /// `None` means nobody has pinned this slice, and [`crate::metrics::Gate`] treats that as a failure
    /// rather than a pass. A floor that does not exist cannot be regressed against.
    #[serde(default)]
    pub baseline_permille: Option<u32>,
    /// Why this slice exists and what its number is worth. Required, for the reason
    /// `tests/fixtures/README.md` requires `notes` on every fixture: a case nobody can justify is one
    /// nobody can safely change later.
    pub notes: String,
}

impl Slice {
    /// Whether `source`'s hits count against the gate.
    pub fn source_is_gated(&self, source: &str) -> bool {
        self.gate_eligible && !self.excluded_sources.iter().any(|e| e.source == source)
    }

    /// Whether this slice needs the network and an approved dataset gate.
    pub fn needs_network(&self) -> bool {
        matches!(self.origin, Origin::Query { .. })
    }
}

/// The pinned upstream dataset.
///
/// Revision-pinned, not branch-pinned. `corpus-analysis.md` measured a specific revision, and a
/// manifest verifying against `main` would silently stop verifying anything the moment upstream
/// appended a shard.
#[derive(Debug, Clone, Deserialize)]
pub struct Dataset {
    pub repo: String,
    pub revision: String,
    pub glob: String,
}

impl Dataset {
    /// The `hf://` URL a slice's SQL interpolates as `{dataset}`.
    pub fn url(&self) -> String {
        format!(
            "hf://datasets/{}@{}/{}",
            self.repo, self.revision, self.glob
        )
    }
}

/// The gate's operating point.
#[derive(Debug, Clone, Deserialize)]
pub struct GateConfig {
    /// Maximum false-positive rate over gate-eligible rows, in per-mille.
    ///
    /// Per-mille rather than a percentage float, so the threshold is exact and the comparison is an
    /// integer one. SC-003 states the budget as 1%; 10 per-mille is that number, expressed in units
    /// that cannot round.
    pub max_fp_permille: u32,
    /// The band at or above which a finding counts as a detection.
    ///
    /// `low`, matching `DETECTION_FLOOR` in `crates/core/tests/fixtures.rs` and for the same reason:
    /// these metrics measure whether the mechanism fires, not whether provisional band boundaries
    /// happen to be tuned. Conflating the two would make every future recalibration look like a
    /// detection regression — and, on the negative side, would let a recalibration silently pass the
    /// gate by moving findings from `low` to `none`.
    pub floor: String,
}

/// Everything in `corpus/slices.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct SliceSet {
    pub dataset: Dataset,
    pub gate: GateConfig,
    /// Sources excluded from the gate wherever they appear.
    ///
    /// Global rather than per-slice, and the reason is a mistake this file caught while it was being
    /// written. SPML's exclusion was recorded on `neg_nonadversarial` only — and SPML is also 400 rows
    /// of `neg_clean`, where it fired on 400 of 400 and carried that slice's rate from 1.8% to 7.7%.
    /// One source's serialisation artifact was about to be published as a false-positive rate for the
    /// second time, in a file whose own comments quote the first time.
    ///
    /// A per-slice list makes each slice remember. A global list makes the exclusion a property of the
    /// source, which is what it actually is: `[System: …]` is SPML's wrapper in every slice that
    /// contains it.
    #[serde(default, rename = "excluded_source")]
    pub excluded_sources: Vec<ExcludedSource>,
    #[serde(rename = "slice")]
    pub slices: Vec<Slice>,
}

impl SliceSet {
    /// Parse and validate `corpus/slices.toml`.
    pub fn load() -> Result<Self> {
        let path = crate::crate_path("corpus/slices.toml");
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut set: SliceSet =
            toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        set.resolve_exclusions();
        set.validate()?;
        Ok(set)
    }

    /// Push the global exclusions down into every gate-eligible slice.
    ///
    /// Resolved once at load rather than consulted at every call site, so there is exactly one place
    /// that can forget — and it is this function rather than each of the seven gate-eligible slices.
    fn resolve_exclusions(&mut self) {
        for slice in self.slices.iter_mut() {
            for global in &self.excluded_sources {
                if !slice
                    .excluded_sources
                    .iter()
                    .any(|local| local.source == global.source)
                {
                    slice.excluded_sources.push(global.clone());
                }
            }
        }
    }

    /// Rejects definitions that would produce a misleading number.
    ///
    /// Each of these is a mistake somebody will make once. A duplicate id silently overwrites a cache
    /// file and a manifest; a gated positive slice would count true positives as false ones; an
    /// exclusion naming a source the slice cannot contain looks like a live protection and is not.
    fn validate(&self) -> Result<()> {
        let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
        for slice in &self.slices {
            if seen.insert(slice.id.as_str(), ()).is_some() {
                return Err(format!(
                    "duplicate slice id `{}` — ids name cache files, manifests and report rows, and \
                     two slices sharing one would silently overwrite each other",
                    slice.id
                )
                .into());
            }
            if slice.kind.is_positive() && slice.gate_eligible {
                return Err(format!(
                    "slice `{}` is a positive slice and gate_eligible — the gate counts false \
                     positives, so this would score detections as failures",
                    slice.id
                )
                .into());
            }
            for excluded in &slice.excluded_sources {
                if excluded.reason.trim().is_empty() {
                    return Err(format!(
                        "slice `{}` excludes source `{}` with no reason. An unexplained exclusion is \
                         indistinguishable from a number somebody found inconvenient",
                        slice.id, excluded.source
                    )
                    .into());
                }
            }
            if slice.notes.trim().is_empty() {
                return Err(format!("slice `{}` has empty notes", slice.id).into());
            }
        }
        crate::metrics::parse_floor(&self.gate.floor)?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<&Slice> {
        self.slices.iter().find(|s| s.id == id).ok_or_else(|| {
            format!(
                "no slice `{id}` in corpus/slices.toml. Known: {}",
                self.slices
                    .iter()
                    .map(|s| s.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .into()
        })
    }

    /// Slices that need no network, in definition order. What CI can run.
    pub fn offline(&self) -> impl Iterator<Item = &Slice> {
        self.slices.iter().filter(|s| !s.needs_network())
    }

    /// The SQL for one slice, with `{dataset}` resolved.
    pub fn sql(&self, slice: &Slice) -> Result<String> {
        match &slice.origin {
            Origin::Query { sql } => Ok(sql.replace("{dataset}", &self.dataset.url())),
            Origin::Local { .. } => Err(format!(
                "slice `{}` is local; it has no SQL and needs no fetch",
                slice.id
            )
            .into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_slice_set_loads_and_validates() {
        let set = SliceSet::load().expect("corpus/slices.toml must load");
        assert!(!set.slices.is_empty());
        // The gate is worthless without something hard to run it against.
        assert!(
            set.slices
                .iter()
                .any(|s| s.kind == SliceKind::HardNegative && s.gate_eligible),
            "no gate-eligible hard-negative slice: the false-positive gate would pass vacuously"
        );
        // And it must be runnable where it is enforced. A gate whose only populations need an
        // approved dataset gate is a gate that never runs in CI.
        assert!(
            set.slices
                .iter()
                .any(|s| s.gate_eligible && !s.needs_network()),
            "every gate-eligible slice needs the network; CI could not enforce the gate"
        );
    }

    #[test]
    fn every_query_slice_interpolates_the_pinned_dataset() {
        let set = SliceSet::load().expect("corpus/slices.toml must load");
        for slice in set.slices.iter().filter(|s| s.needs_network()) {
            let sql = set.sql(slice).expect("query slice must yield SQL");
            assert!(
                sql.contains(&set.dataset.revision),
                "slice `{}` does not pin the dataset revision — a manifest that verifies against a \
                 moving branch verifies nothing",
                slice.id
            );
            assert!(
                !sql.contains("{dataset}"),
                "slice `{}` has an unresolved placeholder",
                slice.id
            );
        }
    }

    #[test]
    fn a_gated_positive_slice_is_rejected() {
        let toml = r#"
[dataset]
repo = "x/y"
revision = "abc"
glob = "**/*.parquet"

[gate]
max_fp_permille = 10
floor = "low"

[[slice]]
id = "pos_x"
kind = "positive"
label = "x"
gate_eligible = true
notes = "n"
[slice.origin]
kind = "local"
reader = "fixtures_positive"
"#;
        let set: SliceSet = toml::from_str(toml).expect("parses");
        let err = set.validate().expect_err("must be rejected");
        assert!(err.to_string().contains("score detections as failures"));
    }
}
