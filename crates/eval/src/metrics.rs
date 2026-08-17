//! Stratified aggregation, report rendering, and the false-positive gate.
//!
//! Three rules govern everything here, and all three come from constitution Principle IV.
//!
//! **Per source, never blended.** `corpus-analysis.md` Finding 1: one source supplies 49.2% of the
//! adversarial rows, so an aggregate over the corpus is substantially a score on that source. Slice
//! totals are printed for orientation; the per-source table is the result.
//!
//! **The false-positive rate is a gate, not a footnote.** [`Gate`] exits non-zero. It has two
//! thresholds and they answer different questions: the *criterion* (SC-003's 1%) is what the tool must
//! eventually achieve, and the per-slice *baseline* is what it achieves today. Failing only on
//! regression, while reporting the criterion as unmet, is the pattern `crates/core/tests/scaling.rs`
//! already uses for SC-004a's 10 MB/s throughput target — *"the throughput assertion is a regression
//! floor rather than the criterion, because SC-004a's 10 MB/s is not currently met."* A gate that is
//! red for a year teaches people to ignore it; a gate that only goes red on new damage does not.
//!
//! **Known gaps are generated, not written.** [`Report::known_gaps`] derives them from the rows it just
//! counted, so a gap cannot drift from the metric beside it. Principle IV requires gaps *"stated
//! explicitly alongside the metrics rather than left for a reader to infer"*, and a hand-written
//! paragraph satisfies that on the day it is written.
//!
//! # Every ratio is integer arithmetic
//!
//! Per-mille, computed with `u64` and rendered from integers. No floats anywhere. `document-map.md`
//! §1.2 sets the rule for the same reason it applies here: a figure that differs in its last digit
//! between an x86 CI runner and an ARM laptop is a figure nobody can reconcile, and this crate exists
//! because two measurements could not be reconciled once already.

use std::collections::BTreeMap;

use please_core::verdict::RiskLevel;

use crate::rows::RowResult;
use crate::slice::{Slice, SliceSet};
use crate::Result;

/// Parse the configured detection floor.
pub fn parse_floor(name: &str) -> Result<RiskLevel> {
    match name {
        "none" => Ok(RiskLevel::None),
        "low" => Ok(RiskLevel::Low),
        "medium" => Ok(RiskLevel::Medium),
        "high" => Ok(RiskLevel::High),
        "critical" => Ok(RiskLevel::Critical),
        other => Err(format!(
            "unknown risk band {other:?} — expected none, low, medium, high or critical"
        )
        .into()),
    }
}

/// A count of hits out of a population.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub n: u64,
    pub hits: u64,
}

impl Tally {
    pub fn add(&mut self, hit: bool) {
        self.n += 1;
        self.hits += u64::from(hit);
    }

    /// Hit rate in per-mille, rounded half-up, saturating at an empty population.
    ///
    /// Integer throughout: `hits * 1000` then divide, with the `+ n/2` doing the rounding. An empty
    /// population reports zero rather than dividing — and callers that could mistake "0 of 0" for a
    /// good result are the reason [`Self::n`] is printed beside every rate this produces.
    pub fn permille(&self) -> u32 {
        if self.n == 0 {
            return 0;
        }
        (((self.hits * 1000) + self.n / 2) / self.n) as u32
    }
}

/// Render a per-mille value as a percentage with one decimal, from integers only.
pub fn pct(permille: u32) -> String {
    format!("{}.{}%", permille / 10, permille % 10)
}

/// Everything counted for one slice.
#[derive(Debug, Clone, Default)]
pub struct SliceMetrics {
    pub slice_id: String,
    pub kind: String,
    pub label: String,
    /// Whole-slice tally. **Not the result** on a stratified slice; the per-source table is.
    pub total: Tally,
    pub by_source: BTreeMap<String, Tally>,
    pub by_context: BTreeMap<String, Tally>,
    pub by_difficulty: BTreeMap<String, Tally>,
    pub by_technique: BTreeMap<String, Tally>,
    pub by_position: BTreeMap<String, Tally>,
    pub by_carrier: BTreeMap<String, Tally>,
    pub by_language: BTreeMap<String, Tally>,
    /// Per payload, on the generated corpus.
    ///
    /// The cut that separates the two hypotheses. If detection is a property of the payload's WORDS, this
    /// table is bimodal — near 100% on the `phrase-*` payloads, near 0% on the `plain-*` ones — and the
    /// per-carrier and per-position tables are flat. If detection is a property of the payload's
    /// PLACEMENT, the reverse. One table cannot be read without the other, which is why both are printed
    /// and neither is summarised away.
    pub by_payload: BTreeMap<String, Tally>,
    /// Rows where a finding was suppressed, per insertion position.
    ///
    /// Suppression is position-sensitive by construction: a payload inside a JSON string value or a
    /// markdown table cell is inside a quoting context, and quoting contexts suppress. That makes the
    /// json-field and table-cell rows a direct measurement of a false-negative channel `docs/limits.md`
    /// has carried as *"accepted false negative, unquantified"* for four features.
    pub suppression_by_position: BTreeMap<String, Tally>,
    /// Detections that came only out of decoded content, against those with a direct match.
    ///
    /// `actionable-directive-results.md` §3 split detections this way and found it worth having: the
    /// decode channel was a small contributor to true positives and produced one of three prose false
    /// positives, which is evidence about a known defect rather than about the decoder being wrong.
    pub direct_hits: u64,
    pub decode_only_hits: u64,
    /// Rows where at least one finding was suppressed by a quoting context.
    ///
    /// The first number anyone has put on this. `docs/limits.md` carries quoted-payload suppression as
    /// an *"accepted false negative, unquantified"*; on a positive slice this column is the size of the
    /// population that suppression is acting on.
    pub rows_with_suppression: u64,
    /// Rows whose analysis did not complete, by cause. Never counted as clean (Principle I).
    pub incomplete: BTreeMap<String, u64>,
    /// Span localisation, on rows that carry ground truth. `None` when none do.
    pub span: Option<Tally>,
    /// Localisation broken out by insertion position (M4) and by carrier format (M3).
    pub span_by_position: BTreeMap<String, Tally>,
    pub span_by_carrier: BTreeMap<String, Tally>,
    /// Whether this slice came from the upstream dataset.
    ///
    /// Needed by [`Report::known_gaps`], which must not count the generated corpus's `intent` tags as
    /// upstream `attack_technique` labels: the generated rows carry an intent in the same field for
    /// reporting convenience, and folding the two together would report the corpus as better labelled
    /// than it is.
    pub from_query: bool,
    /// The gate's view of this slice: rows whose source is not excluded.
    pub gated: Tally,
    /// Per-source tallies excluded from the gate, with the reason, reported separately so an exclusion
    /// is visible rather than merely applied.
    pub excluded: BTreeMap<String, (Tally, String)>,
}

impl SliceMetrics {
    /// Aggregate one slice's results.
    pub fn compute(slice: &Slice, results: &[RowResult]) -> Self {
        let mut m = SliceMetrics {
            slice_id: slice.id.clone(),
            kind: slice.kind.as_str().to_string(),
            label: slice.label.clone(),
            from_query: slice.needs_network(),
            ..Default::default()
        };

        for r in results {
            // On a positive slice a "hit" is a detection; on a negative slice the identical event is a
            // false positive. One field, two readings, and the slice kind is what distinguishes them —
            // which is why every table in the rendered report is headed by the kind.
            let hit = r.detected;
            m.total.add(hit);
            m.by_source.entry(r.source.clone()).or_default().add(hit);

            if slice.gate_eligible && slice.source_is_gated(&r.source) {
                m.gated.add(hit);
            }
            // Recorded on positive slices as well as negative ones. The `[System: …]` wrapper produces a
            // 100% rate on SPML negatives and a 100% rate on TensorTrust positives, and only one of those
            // is uncomfortable — which is exactly why both are caveated.
            if let Some(excluded) = slice.excluded_sources.iter().find(|e| e.source == r.source) {
                m.excluded
                    .entry(r.source.clone())
                    .or_insert((Tally::default(), excluded.reason.clone()))
                    .0
                    .add(hit);
            }

            for (key, map) in [
                (&r.context, &mut m.by_context),
                (&r.difficulty, &mut m.by_difficulty),
                (&r.technique, &mut m.by_technique),
                (&r.position, &mut m.by_position),
                (&r.carrier_id, &mut m.by_carrier),
                (&r.language, &mut m.by_language),
                (&r.payload_id, &mut m.by_payload),
            ] {
                if let Some(value) = key {
                    map.entry(value.clone()).or_default().add(hit);
                }
            }
            if let Some(position) = &r.position {
                m.suppression_by_position
                    .entry(position.clone())
                    .or_default()
                    .add(r.suppressed > 0);
            }

            if hit {
                if r.reasons.iter().any(|reason| reason.chain.is_empty()) {
                    m.direct_hits += 1;
                } else {
                    m.decode_only_hits += 1;
                }
            }
            if r.suppressed > 0 {
                m.rows_with_suppression += 1;
            }
            for cause in &r.incomplete {
                *m.incomplete.entry(cause.clone()).or_default() += 1;
            }

            if let Some(localised) = r.span_hit {
                m.span.get_or_insert_with(Tally::default).add(localised);
                if let Some(position) = &r.position {
                    m.span_by_position
                        .entry(position.clone())
                        .or_default()
                        .add(localised);
                }
                if let Some(carrier) = &r.carrier_id {
                    m.span_by_carrier
                        .entry(carrier.clone())
                        .or_default()
                        .add(localised);
                }
            }
        }
        m
    }
}

/// One gate-eligible slice's verdict.
#[derive(Debug, Clone)]
pub struct GateSlice {
    pub slice_id: String,
    pub gated: Tally,
    pub permille: u32,
    pub baseline: Option<u32>,
    /// The rate exceeds the committed baseline: new damage, and the gate's failure condition.
    pub regressed: bool,
    /// The rate meets SC-003's budget. Reported always; enforced only under `--strict`.
    pub criterion_met: bool,
}

/// The gate's overall result.
#[derive(Debug, Clone)]
pub struct Gate {
    pub max_fp_permille: u32,
    pub slices: Vec<GateSlice>,
    /// Gate-eligible slices with no committed baseline. A slice nobody has pinned cannot detect a
    /// regression, so this is a failure by default rather than a silent pass — see [`Gate::failed`].
    pub unpinned: Vec<String>,
}

impl Gate {
    pub fn evaluate(set: &SliceSet, metrics: &[SliceMetrics]) -> Self {
        let mut slices = Vec::new();
        let mut unpinned = Vec::new();
        for m in metrics {
            let Ok(slice) = set.get(&m.slice_id) else {
                continue;
            };
            if !slice.gate_eligible {
                continue;
            }
            let permille = m.gated.permille();
            if slice.baseline_permille.is_none() {
                unpinned.push(m.slice_id.clone());
            }
            slices.push(GateSlice {
                slice_id: m.slice_id.clone(),
                gated: m.gated,
                permille,
                baseline: slice.baseline_permille,
                regressed: slice
                    .baseline_permille
                    .is_some_and(|baseline| permille > baseline),
                criterion_met: permille <= set.gate.max_fp_permille,
            });
        }
        Gate {
            max_fp_permille: set.gate.max_fp_permille,
            slices,
            unpinned,
        }
    }

    /// Whether the gate fails.
    ///
    /// `strict` enforces SC-003's criterion as well as the regression floor. It is off by default and
    /// on in one place — the operator asking whether the criterion is met yet — so that "the gate
    /// passes" never quietly comes to mean "the criterion is met".
    pub fn failed(&self, strict: bool, allow_unpinned: bool) -> bool {
        if !allow_unpinned && !self.unpinned.is_empty() {
            return true;
        }
        self.slices
            .iter()
            .any(|s| s.regressed || (strict && !s.criterion_met))
    }
}

/// A whole run: what was measured, with what, and the numbers.
pub struct Report {
    pub run: String,
    pub ruleset: String,
    pub ruleset_digest: String,
    pub floor: String,
    pub dataset: String,
    pub metrics: Vec<SliceMetrics>,
    pub gate: Gate,
}

impl Report {
    /// Gaps derived from the rows just counted.
    ///
    /// Each entry is a sentence a reader needs in order not to over-read the tables above it, and each
    /// is computed rather than asserted — so a gap that closes stops being printed, and one that opens
    /// starts.
    pub fn known_gaps(&self) -> Vec<String> {
        let mut gaps = Vec::new();

        // Finding 4. The asymmetry that flatters a detector: a good multilingual false-positive rate and
        // no evidence at all about multilingual detection.
        let positive_non_english: u64 = self
            .metrics
            .iter()
            .filter(|m| m.kind == "positive")
            .flat_map(|m| m.by_language.iter())
            .filter(|(language, _)| language.as_str() != "en")
            .map(|(_, tally)| tally.n)
            .sum();
        let negative_non_english: u64 = self
            .metrics
            .iter()
            .filter(|m| m.kind != "positive")
            .flat_map(|m| m.by_language.iter())
            .filter(|(language, _)| language.as_str() != "en")
            .map(|(_, tally)| tally.n)
            .sum();
        if positive_non_english == 0 && negative_non_english > 0 {
            gaps.push(format!(
                "**Multilingual detection is unmeasured, not supported.** This run scanned \
                 {negative_non_english} non-English negatives and **zero** non-English positives. Any \
                 false-positive rate above for non-English text is therefore real, and no detection \
                 rate for non-English attacks exists to report. PLEASE makes no multilingual detection \
                 claim (`docs/limits.md`)."
            ));
        }

        // Finding 3. Per-technique reporting is honest on 5.2% of positives and nowhere else.
        //
        // Counted as total-minus-labelled rather than by summing an "unlabelled" bucket, because there is
        // no such bucket: an absent technique is `None` on the row and never reaches `by_technique`. The
        // first version of this summed the bucket, got zero, and silently omitted the gap — and a gap that
        // vanishes because the field measuring it is empty is the worst available failure for a section
        // whose whole purpose is to state what the metrics do not cover.
        let positive_total: u64 = self
            .metrics
            .iter()
            .filter(|m| m.kind == "positive" && m.from_query)
            .map(|m| m.total.n)
            .sum();
        let labelled: u64 = self
            .metrics
            .iter()
            .filter(|m| m.kind == "positive" && m.from_query)
            .flat_map(|m| m.by_technique.iter())
            .filter(|(technique, _)| !technique.is_empty())
            .map(|(_, tally)| tally.n)
            .sum();
        let unlabelled = positive_total.saturating_sub(labelled);
        if unlabelled > 0 {
            let total = positive_total;
            gaps.push(format!(
                "**`attack_technique` is unlabelled for most positives.** {labelled} of {total} \
                 positive rows in this run carry a technique label. Any per-technique table above \
                 describes that subset and must not be extrapolated to the rest, which is not a sample \
                 of it (`corpus-analysis.md` Finding 3)."
            ));
        }

        // The size of the population that quoting suppression is acting on, on positives. The first
        // number anyone has attached to an entry that has read "unquantified" for four features.
        let suppressed_positives: u64 = self
            .metrics
            .iter()
            .filter(|m| m.kind == "positive")
            .map(|m| m.rows_with_suppression)
            .sum();
        if suppressed_positives > 0 {
            gaps.push(format!(
                "**Quoting suppression acted on {suppressed_positives} positive rows.** Each is a row \
                 where a finding was moved to the suppressed channel because it sat in a quoting \
                 context. Some of those are correct — a document discussing an attack — and some are \
                 false negatives. This run cannot tell them apart; it can only say how many rows the \
                 mechanism touched (`docs/limits.md`, \"Quoted payloads can suppress detection\")."
            ));
        }

        // Principle I, checked against the instrument's own output.
        let incomplete: u64 = self
            .metrics
            .iter()
            .flat_map(|m| m.incomplete.values())
            .sum();
        if incomplete > 0 {
            gaps.push(format!(
                "**{incomplete} rows did not analyse completely** and are reported as inconclusive, \
                 not clean. Their causes are listed per slice. A rate computed as if these were clean \
                 would be the exact failure Principle I forbids."
            ));
        }

        // The agentic vector gap: what the public corpus cannot measure at all.
        let has_public_positive = self
            .metrics
            .iter()
            .any(|m| m.kind == "positive" && m.by_context.is_empty() && m.total.n > 100);
        if has_public_positive {
            gaps.push(
                "**The public corpus cannot measure the product's target vector.** Its rows carry no \
                 delivery context, and its agentic subset — InjecAgent plus ToolEmu — is 0.45% of \
                 adversarial rows. Detection rates for `skill_md`, `mcp_tool_description`, \
                 `repo_config` and `manifest` come only from the hand-written fixtures and the \
                 generated corpus, whose per-context tables are above."
                    .to_string(),
            );
        }

        if self.metrics.iter().any(|m| m.slice_id == "gen_positive") {
            gaps.push(
                "**The generated corpus may be measuring its own seams.** Its carriers and payloads \
                 were written by the same people as the detectors, so a strong result there with a weak \
                 result on the held-out fixtures means the generator was fitted rather than the signal \
                 found (`document-map.md` §5.1). Compare `gen_positive` against `fix_positive` before \
                 believing either."
                    .to_string(),
            );
        }

        gaps
    }

    /// Render the report as Markdown.
    ///
    /// Deterministic: `BTreeMap` everywhere, integer ratios, and no timestamp. Running `report` twice
    /// over the same results produces byte-identical output, which is what makes a committed research
    /// document diffable — and what stops a re-render from looking like a re-measurement.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let w = &mut out;
        use std::fmt::Write;

        let _ = writeln!(w, "# Evaluation report — `{}`\n", self.run);
        let _ = writeln!(
            w,
            "| | |\n|---|---|\n| rule set | `{}` |\n| rule-set digest | `{}` |\n| detection floor | \
             `{}` |\n| corpus | `{}` |\n",
            self.ruleset, self.ruleset_digest, self.floor, self.dataset
        );
        let _ = writeln!(
            w,
            "A finding at or above the detection floor counts as a hit. On a **positive** slice a hit \
             is a detection; on a **negative** slice the same event is a false positive.\n"
        );

        // The gate first, because it is the number with a consequence.
        let _ = writeln!(w, "## The false-positive gate\n");
        let _ = writeln!(
            w,
            "Criterion: **{}** (SC-003). The gate fails on a rate above a slice's committed baseline, \
             not on an unmet criterion — see `src/metrics.rs` for why.\n",
            pct(self.max_fp_permille_display())
        );
        let _ = writeln!(
            w,
            "| slice | gated rows | false positives | rate | baseline | criterion | verdict |"
        );
        let _ = writeln!(w, "|---|---:|---:|---:|---:|---|---|");
        for slice in &self.gate.slices {
            let _ = writeln!(
                w,
                "| `{}` | {} | {} | {} | {} | {} | {} |",
                slice.slice_id,
                slice.gated.n,
                slice.gated.hits,
                pct(slice.permille),
                slice
                    .baseline
                    .map(pct)
                    .unwrap_or_else(|| "**unpinned**".to_string()),
                if slice.criterion_met {
                    "met"
                } else {
                    "NOT met"
                },
                if slice.regressed {
                    "**REGRESSION**"
                } else if slice.baseline.is_none() {
                    "**unpinned**"
                } else {
                    "held"
                }
            );
        }
        if !self.gate.unpinned.is_empty() {
            let _ = writeln!(
                w,
                "\n**{} gate-eligible slice(s) have no committed baseline**: {}. Until a baseline is \
                 recorded in `corpus/slices.toml`, a regression on them cannot be detected and the gate \
                 fails.",
                self.gate.unpinned.len(),
                self.gate
                    .unpinned
                    .iter()
                    .map(|id| format!("`{id}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let _ = writeln!(w);

        for m in &self.metrics {
            let _ = writeln!(w, "## `{}` — {}\n", m.slice_id, m.label);
            let _ = writeln!(w, "*{}*, {} rows.\n", m.kind, m.total.n);

            // Per source, always, and it is the result rather than the total above it.
            let _ = writeln!(w, "| source | rows | hits | rate |");
            let _ = writeln!(w, "|---|---:|---:|---:|");
            for (source, tally) in &m.by_source {
                let _ = writeln!(
                    w,
                    "| {source} | {} | {} | {} |",
                    tally.n,
                    tally.hits,
                    pct(tally.permille())
                );
            }
            if m.by_source.len() > 1 {
                let _ = writeln!(
                    w,
                    "\nNo aggregate is quoted for this slice. Its sources are not equally \
                     representative of anything, so a mean over them is a number without a referent \
                     (`corpus-analysis.md` Finding 1)."
                );
            }
            let _ = writeln!(w);

            for (title, map, note) in [
                (
                    "By delivery context",
                    &m.by_context,
                    "Where hostile text would actually arrive. The public corpus records none of this; \
                     these rows are hand-written or generated.",
                ),
                ("By difficulty", &m.by_difficulty, ""),
                (
                    "By labelled technique",
                    &m.by_technique,
                    "Honest only on the labelled subset.",
                ),
                (
                    "By insertion position",
                    &m.by_position,
                    "BIPIA's own ablation makes end-of-content the highest-ASR placement, so position \
                     sensitivity is a finding rather than a failure.",
                ),
                ("By carrier format", &m.by_carrier, ""),
                ("By language", &m.by_language, ""),
                (
                    "By payload",
                    &m.by_payload,
                    "`phrase-*` payloads carry the shapes the shipped rules match; `plain-*` payloads \
                     carry no lexical signal at all and are an attack only by virtue of being an \
                     instruction where data belongs. Read this table against the per-position one above: \
                     if this is bimodal and that one is flat, detection is a property of the words and \
                     not of the placement.",
                ),
                (
                    "Suppression by position",
                    &m.suppression_by_position,
                    "Rows where at least one finding was moved to the suppressed channel. A payload in a \
                     JSON string value or a table cell sits inside a quoting context, so this is a \
                     measurement of the false-negative channel `docs/limits.md` records as accepted and \
                     unquantified.",
                ),
            ] {
                if map.is_empty() || (map.len() == 1 && map.contains_key("")) {
                    continue;
                }
                let _ = writeln!(w, "### {title}\n");
                if !note.is_empty() {
                    let _ = writeln!(w, "{note}\n");
                }
                let _ = writeln!(w, "| stratum | rows | hits | rate |");
                let _ = writeln!(w, "|---|---:|---:|---:|");
                for (key, tally) in map {
                    let label = if key.is_empty() { "(unlabelled)" } else { key };
                    let _ = writeln!(
                        w,
                        "| {label} | {} | {} | {} |",
                        tally.n,
                        tally.hits,
                        pct(tally.permille())
                    );
                }
                let _ = writeln!(w);
            }

            if let Some(span) = m.span {
                let _ = writeln!(w, "### Span localisation\n");
                let _ = writeln!(
                    w,
                    "Of {} rows carrying span ground truth, **{} ({})** produced a finding whose span \
                     overlaps the injected payload.\n",
                    span.n,
                    span.hits,
                    pct(span.permille())
                );
                let _ = writeln!(
                    w,
                    "This is localisation by the **shipped detectors**. It is not M1 from \
                     `document-map.md`, which asks whether the injected segment is the top register \
                     outlier and needs `DocumentMap` in the core first.\n"
                );
                for (title, map) in [
                    ("Localisation by position", &m.span_by_position),
                    ("Localisation by carrier", &m.span_by_carrier),
                ] {
                    if map.is_empty() {
                        continue;
                    }
                    let _ = writeln!(w, "**{title}**\n");
                    let _ = writeln!(w, "| stratum | rows | localised | rate |");
                    let _ = writeln!(w, "|---|---:|---:|---:|");
                    for (key, tally) in map {
                        let _ = writeln!(
                            w,
                            "| {key} | {} | {} | {} |",
                            tally.n,
                            tally.hits,
                            pct(tally.permille())
                        );
                    }
                    let _ = writeln!(w);
                }
            }

            if m.total.hits > 0 {
                let _ = writeln!(
                    w,
                    "**Detection channel.** {} hits with a direct match, {} reached only through a \
                     decode chain.\n",
                    m.direct_hits, m.decode_only_hits
                );
            }
            if m.rows_with_suppression > 0 {
                let _ = writeln!(
                    w,
                    "**Quoting suppression** moved at least one finding to the suppressed channel on \
                     {} rows.\n",
                    m.rows_with_suppression
                );
            }
            if !m.incomplete.is_empty() {
                let _ = writeln!(
                    w,
                    "**Incomplete analysis** — reported, never scored as clean:\n"
                );
                for (cause, count) in &m.incomplete {
                    let _ = writeln!(w, "- `{cause}`: {count} rows");
                }
                let _ = writeln!(w);
            }
            for (source, (tally, reason)) in &m.excluded {
                let _ = writeln!(
                    w,
                    "**`{source}` is caveated** — {} of {} rows fired ({}), and the rate is an artifact \
                     of the source's serialisation rather than a measurement of its content. Reported, \
                     and excluded from any gate:\n\n{}\n",
                    tally.hits,
                    tally.n,
                    pct(tally.permille()),
                    reason.trim()
                );
            }
        }

        let gaps = self.known_gaps();
        if !gaps.is_empty() {
            let _ = writeln!(w, "## Known gaps\n");
            let _ = writeln!(
                w,
                "Derived from the rows counted above rather than written by hand, so a gap cannot drift \
                 from the metric beside it (Principle IV).\n"
            );
            for gap in gaps {
                let _ = writeln!(w, "- {gap}");
            }
            let _ = writeln!(w);
        }

        out
    }

    fn max_fp_permille_display(&self) -> u32 {
        self.gate.max_fp_permille
    }

    /// The same report as JSON, for anything that wants to re-cut the numbers.
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        let tally = |t: &Tally| json!({"n": t.n, "hits": t.hits, "permille": t.permille()});
        let map = |m: &BTreeMap<String, Tally>| {
            m.iter()
                .map(|(k, v)| (k.clone(), tally(v)))
                .collect::<serde_json::Map<_, _>>()
        };
        json!({
            "run": self.run,
            "ruleset": self.ruleset,
            "ruleset_digest": self.ruleset_digest,
            "floor": self.floor,
            "dataset": self.dataset,
            "gate": {
                "max_fp_permille": self.gate.max_fp_permille,
                "unpinned": self.gate.unpinned,
                "slices": self.gate.slices.iter().map(|s| json!({
                    "slice": s.slice_id,
                    "gated": tally(&s.gated),
                    "permille": s.permille,
                    "baseline_permille": s.baseline,
                    "regressed": s.regressed,
                    "criterion_met": s.criterion_met,
                })).collect::<Vec<_>>(),
            },
            "slices": self.metrics.iter().map(|m| json!({
                "slice": m.slice_id,
                "kind": m.kind,
                "label": m.label,
                "total": tally(&m.total),
                "by_source": map(&m.by_source),
                "by_context": map(&m.by_context),
                "by_difficulty": map(&m.by_difficulty),
                "by_technique": map(&m.by_technique),
                "by_position": map(&m.by_position),
                "by_carrier": map(&m.by_carrier),
                "by_language": map(&m.by_language),
                "by_payload": map(&m.by_payload),
                "suppression_by_position": map(&m.suppression_by_position),
                "direct_hits": m.direct_hits,
                "decode_only_hits": m.decode_only_hits,
                "rows_with_suppression": m.rows_with_suppression,
                "incomplete": m.incomplete,
                "span": m.span.as_ref().map(tally),
                "span_by_position": map(&m.span_by_position),
                "span_by_carrier": map(&m.span_by_carrier),
            })).collect::<Vec<_>>(),
            "known_gaps": self.known_gaps(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rate_is_integer_arithmetic_and_rounds_half_up() {
        assert_eq!(Tally { n: 0, hits: 0 }.permille(), 0);
        assert_eq!(Tally { n: 200, hits: 1 }.permille(), 5);
        assert_eq!(Tally { n: 3, hits: 1 }.permille(), 333);
        assert_eq!(Tally { n: 3, hits: 2 }.permille(), 667);
        assert_eq!(Tally { n: 38, hits: 12 }.permille(), 316);
        assert_eq!(pct(316), "31.6%");
        assert_eq!(pct(5), "0.5%");
        assert_eq!(pct(1000), "100.0%");
    }

    /// The gate must not pass because nobody pinned it. An unpinned slice has no floor to regress
    /// against, so it is a failure until somebody records what today's number is.
    #[test]
    fn an_unpinned_gate_slice_fails_by_default() {
        let gate = Gate {
            max_fp_permille: 10,
            slices: vec![],
            unpinned: vec!["neg_orbench".into()],
        };
        assert!(gate.failed(false, false));
        assert!(!gate.failed(false, true));
    }

    #[test]
    fn the_gate_fails_on_regression_but_not_on_an_unmet_criterion() {
        let gate = Gate {
            max_fp_permille: 10,
            slices: vec![GateSlice {
                slice_id: "repo_prose".into(),
                gated: Tally { n: 38, hits: 12 },
                permille: 316,
                baseline: Some(316),
                regressed: false,
                criterion_met: false,
            }],
            unpinned: vec![],
        };
        assert!(
            !gate.failed(false, false),
            "an unmet criterion at the pinned baseline is the recorded state, not new damage"
        );
        assert!(gate.failed(true, false), "--strict must enforce SC-003");

        let regressed = Gate {
            slices: vec![GateSlice {
                permille: 317,
                regressed: true,
                ..gate.slices[0].clone()
            }],
            ..gate
        };
        assert!(
            regressed.failed(false, false),
            "one more hit is a regression"
        );
    }
}
