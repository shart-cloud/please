//! What a scan saw, and what it did not get to look at.
//!
//! This module is one half of a seam. Detectors write into [`Evidence`] and can read nothing back;
//! finalization reads it and is the only thing that can. That asymmetry is not politeness about layering
//! — it is what makes two guarantees structural instead of remembered.
//!
//! **FR-124, aggregate before truncate.** 001 kept two collections in `Engine::scan`: `all_hits` fed
//! scoring and was never truncated, `reasons` was reported and was. The comment explaining why they must
//! not be confused was correct, and load-bearing, and exactly the kind of thing that survives until
//! someone edits the loop. With one accumulator and no way for a detector to hold a second view of it,
//! scoring over everything found is the only thing expressible. The bug class goes away rather than the
//! instance.
//!
//! **FR-122, one gap vocabulary.** 001 had four detector-specific shapes for "something went
//! unexamined": `Expansion::depth_exceeded`, `Expansion::fanout_exceeded`, `RuleMatches::saturated`, and
//! a bare `bool` returned from excerpt sanitisation. Each was a boolean that some *other* module had to
//! translate into a coverage judgement, and `engine.rs` was where all four translations lived. A boolean
//! carries no reason, so the translation had to reconstruct one — and the reconstruction was wrong at
//! least once: `depth_exceeded` originally meant "the decoder had more work queued", which for
//! unconditional transforms like ROT-13 is *always* true, so every scan reported inconclusive.
//!
//! The fix is that the code which hits a bound records the gap itself, in the shared vocabulary, at the
//! point it happens. Nobody translates anything.

use super::types::{DetectionClass, IncompleteCause, Incompleteness, Span, Transform};

/// One thing a detector saw. A detector's **only** output (FR-121).
///
/// This was `detect::Hit` in 001. Two changes came with the rename, and both are the point of it:
///
///  * it no longer knows how to become a [`Reason`](super::types::Reason). `Hit::into_reason` sanitised
///    the excerpt and filled in `suppressed_by`, which put the decision about what a finding *says* in
///    the module that found it. That transition now lives in finalization, at the single boundary that
///    owns it (FR-126);
///  * it carries exactly **one** class, and whoever emits it decides that class once. The 001 decode
///    path emitted an observation gated on its rule's class and then relabelled it `Encoding`, so a
///    finding had to satisfy two different class filters to be reported — which is the defect US2
///    closes (FR-133).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Stable rule identity. **Never a position** in the rule slice (FR-141).
    pub rule_id: String,
    pub class: DetectionClass,
    /// Span in the **original** input, even when the match came out of decoded content.
    pub span: Span,
    /// Content to show the reader, **raw**. Neutralised on the way into a reason, not here — one site,
    /// so it cannot be forgotten at a second one (FR-021, FR-126).
    pub matched: String,
    pub severity: u8,
    /// Why the rule exists, carried so a finding explains itself without a lookup.
    pub description: String,
    /// The transformations by which this arrived. Empty for a direct match.
    pub chain: Vec<Transform>,
}

/// Something the scan did not examine, in the one vocabulary everything uses (FR-122).
///
/// # Why this is not just [`Incompleteness`]
///
/// The two carry identical information and differ in exactly one respect: **who may construct one.**
///
///  * `CoverageGap` is constructible by any detector, because a detector is the only thing that knows it
///    hit a bound. The decoder knows its depth limit stopped it; the matcher knows which rule saturated.
///  * `Incompleteness` appears in a [`Verdict`](super::types::Verdict), and its constructors are visible
///    only inside `finalize` (T008). A detector that could build one directly could also hand it to a
///    verdict it assembled itself, which is the thing being prevented.
///
/// So the same fact is recorded with one set of rights and reported with another, and the conversion is
/// the seam. Collapsing them into a single type would mean either detectors can build what goes into a
/// verdict, or nothing outside finalization can report a gap at all — and the second is not true, since
/// hitting a bound is precisely a detector's observation to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageGap {
    cause: IncompleteCause,
    configured: Option<u64>,
    detail: Option<String>,
}

impl CoverageGap {
    /// A configured bound was reached, with the value that stopped analysis so a caller can raise it.
    ///
    /// `detail` is required rather than optional, unlike 001's `Incompleteness::bound`. A gap whose
    /// detail is absent tells the reader a limit was hit somewhere, which is very nearly no information
    /// at all — and every one of the five sites in 001 filled it in immediately afterwards via
    /// `with_detail`, so the optionality bought nothing but the chance to forget.
    pub fn bound(cause: IncompleteCause, configured: u64, detail: impl Into<String>) -> Self {
        debug_assert!(cause.is_bound(), "{cause:?} is not a bound");
        Self {
            cause,
            configured: Some(configured),
            detail: Some(detail.into()),
        }
    }

    /// Something in the environment failed, with an explanation of what.
    pub fn failure(cause: IncompleteCause, detail: impl Into<String>) -> Self {
        debug_assert!(!cause.is_bound(), "{cause:?} is a bound, not a failure");
        Self {
            cause,
            configured: None,
            detail: Some(detail.into()),
        }
    }

    pub fn cause(&self) -> IncompleteCause {
        self.cause
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl CoverageGap {
    /// The reportable form. Visible only inside `finalize`, so a gap reaches a verdict by exactly one
    /// route.
    pub(super) fn into_incompleteness(self) -> Incompleteness {
        Incompleteness {
            cause: self.cause,
            configured: self.configured,
            detail: self.detail,
        }
    }
}

/// The accumulated observations and coverage gaps of one scan.
///
/// # Write-only to detectors, read-only to finalization
///
/// Every recording method is `pub`. Every reading method is `pub(super)`, which inside
/// `crate::finalize::evidence` means visible throughout `crate::finalize` and nowhere else.
///
/// A detector therefore cannot ask what has been recorded so far, which sounds like a restriction and is
/// actually the guarantee: a stage that cannot read the accumulator cannot maintain its own copy of it,
/// so there is nothing for a second collection to disagree with. `Engine::scan` in 001 held
/// `all_hits`, `hits`, `decoded_hits`, `kept`, `reasons`, and `saturated_rules` simultaneously, and the
/// correctness of the score depended on the first of those staying in step with the last. It cannot be
/// out of step with something that does not exist.
///
/// This is deliberately *not* enforced by handing detectors a separate wrapper type. A wrapper is a
/// second thing to keep in sync; `pub(super)` on the read side is the same guarantee with no extra type,
/// and it is checked by the compiler either way (research P6).
#[derive(Debug, Default)]
pub struct Evidence {
    observations: Vec<Observation>,
    gaps: Vec<CoverageGap>,
}

impl Evidence {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Write side: public, for detectors ───────────────────────────────────────────────────────

    /// Record something seen.
    pub fn observe(&mut self, observation: Observation) {
        self.observations.push(observation);
    }

    /// Record something not examined, at the point it was not examined.
    pub fn record_gap(&mut self, gap: CoverageGap) {
        self.gaps.push(gap);
    }

    // ── Read side: `pub(super)`, for finalization only ──────────────────────────────────────────

    pub(super) fn into_parts(self) -> (Vec<Observation>, Vec<CoverageGap>) {
        (self.observations, self.gaps)
    }

    /// Read the recorded gaps. **Test builds only.**
    ///
    /// A detector that records a gap needs a unit test asserting it recorded the right one, and the whole
    /// design is that a detector cannot read this accumulator. `cfg(test)` is the narrow answer: the
    /// method does not exist in a shipped build, so the guarantee is not weakened by the thing that
    /// checks it. Integration tests do not need it — they assert on `Verdict::incomplete`, which is
    /// public, and asserting through the public surface is the better test anyway.
    #[cfg(test)]
    pub(crate) fn recorded_gaps(&self) -> &[CoverageGap] {
        &self.gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(rule_id: &str) -> Observation {
        Observation {
            rule_id: rule_id.to_string(),
            class: DetectionClass::Override,
            span: Span::new(0, 4),
            matched: "test".to_string(),
            severity: 50,
            description: "test rule".to_string(),
            chain: Vec::new(),
        }
    }

    #[test]
    fn an_empty_accumulator_has_nothing_to_report() {
        let (observations, gaps) = Evidence::new().into_parts();
        assert!(observations.is_empty());
        assert!(gaps.is_empty());
    }

    #[test]
    fn recording_preserves_order() {
        // Not an aesthetic preference. Byte-identical output (SC-011) requires that the same input
        // produce the same verdict, and finalization's total order over reasons uses the rule id only as
        // a tie-break — so anything upstream of it must be deterministic too.
        let mut evidence = Evidence::new();
        evidence.observe(observation("a"));
        evidence.observe(observation("b"));
        let (observations, _) = evidence.into_parts();
        let ids: Vec<&str> = observations.iter().map(|o| o.rule_id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);
    }

    #[test]
    fn a_gap_carries_its_configured_value_and_its_detail() {
        let gap = CoverageGap::bound(IncompleteCause::DecodeDepth, 3, "two more layers remained");
        assert_eq!(gap.cause(), IncompleteCause::DecodeDepth);
        assert_eq!(gap.detail(), Some("two more layers remained"));

        let reported = gap.into_incompleteness();
        assert_eq!(reported.configured, Some(3));
    }

    #[test]
    fn a_failure_carries_no_configured_value() {
        // The bound/failure split is what a caller *does about it*: raise a limit, or fix the
        // environment. A failure reporting a configured value would suggest a limit to raise that does
        // not exist.
        let gap = CoverageGap::failure(IncompleteCause::DecodeFailed, "too many regions");
        assert_eq!(gap.into_incompleteness().configured, None);
    }
}
