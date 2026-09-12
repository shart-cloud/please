//! Finalization owns retained analysis, scoring, and report projection.
//!
//! Detectors write observations and coverage gaps. Finalization retains bounded, neutralized evidence
//! in `Analysis`; optional tiers update that record and attach their reports. `Verdict` projects the
//! retained record with display limits. No optional tier reconstructs evidence from displayed reasons.
//! Scores and outcomes always derive from active retained findings and actual coverage gaps.

pub mod analysis;
pub mod evidence;
pub use analysis::Analysis;
pub mod ml_review;
pub mod plan;
pub mod review;
pub mod score;
pub mod types;

use crate::ruleset::Bands;
use crate::sanitize::sanitize_str;
use evidence::{CoverageGap, Evidence, Observation, Suppression};
use plan::Bounds;
use types::{
    IncompleteCause, JudgeReport, MlReport, Reason, RulesetId, SpanJudgement, SuppressedBy,
    TargetRef, Verdict,
};

/// Everything a verdict needs that is **not** evidence: who scanned, what with, and the band table.
///
/// A struct rather than three positional parameters, for the reason 001 gave for `VerdictParts` and which
/// still holds: adjacent same-typed fields are easy to transpose, and two `String`-shaped identities next to
/// each other are easy to swap silently.
///
/// This is not `VerdictParts` under a new name, and the difference is the whole of FR-120. The parts struct
/// carried the reasons and the coverage gaps — the evidence itself — so anyone able to build one was deciding
/// what the verdict said. This carries none of it. The evidence arrives separately, through an accumulator
/// the caller cannot read.
///
/// Nor is there a `score` field, and that absence is FR-127: a score is a function of the evidence, so
/// supplying one would mean the caller had already computed it from a collection of its own.
#[derive(Debug, Clone)]
pub struct Attribution {
    pub target: TargetRef,
    pub ruleset: RulesetId,
    /// Score-to-risk boundaries. Supplied rather than derived because they are **calibration** — data a
    /// deployment retunes without a rebuild — whereas the score is arithmetic over the evidence.
    pub bands: Bands,
}

/// Retain bounded evidence and derive a report. Display bounds are applied only by the projection.
pub fn finalize(evidence: Evidence, bounds: Bounds, attribution: Attribution) -> Verdict {
    let (observations, gaps, suppressions) = evidence.into_parts();
    let mut analysis = Analysis::new(bounds, attribution);
    analysis
        .incomplete
        .extend(gaps.into_iter().map(CoverageGap::into_incompleteness));
    for observation in observations {
        analysis.observe(observation, None);
    }
    for Suppression {
        observation,
        context,
    } in suppressions
    {
        analysis.observe(observation, Some(context));
    }
    analysis.finish()
}

/// Attach a bound advisory review using the original calibration.
///
/// This compatibility entry point checks the independently supplied band table and never grants
/// release authority. Use `rejudge_with_authority` for an explicit policy choice. Unbound reports,
/// changed evidence or policy, and duplicate decisions are refused atomically.
/// Capture a `review::ReviewScope` before obtaining the response and bind the report to that scope.
pub fn rejudge(verdict: Verdict, report: JudgeReport, bands: &Bands) -> Verdict {
    if verdict.bands() != bands {
        return refuse_to_judge(verdict, "review calibration does not match the scan");
    }
    rejudge_with_authority(verdict, report, review::ReviewAuthority::Advisory)
}

/// Apply a request-bound report under explicit caller authority, using the scan's own calibration.
pub fn rejudge_with_authority(
    verdict: Verdict,
    report: JudgeReport,
    authority: review::ReviewAuthority,
) -> Verdict {
    if !report
        .scope()
        .is_some_and(|scope| scope.valid_for(&verdict))
    {
        return refuse_to_judge(
            verdict,
            "review is unbound or does not match the input, evidence, or policy",
        );
    }

    // Indices are into the retained `analysis().reasons()` as the judge saw them. An index past the end is a report
    // about a different verdict, and applying part of it would demote whichever reason happened to sit at a
    // valid index — arbitrary, and arbitrary in the attacker's favour half the time.
    let count = verdict.analysis().reasons().len();
    if report
        .judgements()
        .iter()
        .any(|judgement| judgement.reason_index >= count)
    {
        return refuse_to_judge(
            verdict,
            "judgement names an observation this verdict does not contain",
        );
    }

    let demoted: Vec<bool> = {
        let mut flags = vec![false; count];
        let mut seen = vec![false; count];
        for judgement in report.judgements() {
            if seen[judgement.reason_index] {
                return refuse_to_judge(
                    verdict,
                    "review contains duplicate or contradictory decisions",
                );
            }
            seen[judgement.reason_index] = true;
            flags[judgement.reason_index] = judgement.judgement == SpanJudgement::Demoted;
        }
        flags
    };

    let report = report.with_authority(authority);
    if authority == review::ReviewAuthority::Advisory {
        return verdict.with_judge(report);
    }
    let mut state = verdict.into_analysis();
    let mut kept = Vec::new();
    for (index, mut reason) in state.reasons.into_iter().enumerate() {
        if demoted[index] {
            reason.demote_by_judge();
            state.suppressed.push(reason);
        } else {
            kept.push(reason);
        }
    }
    state.reasons = kept;
    order(&mut state.suppressed);
    state.judge = Some(report);
    state.finish()
}

/// Add ML evidence to the retained analysis. Display shortening never prevents composition.
/// Calibration and analysis limits must match the scan; supplied display limits select the projection.
pub fn with_ml(
    structural: Verdict,
    observations: Vec<Observation>,
    report: MlReport,
    bounds: Bounds,
    bands: &Bands,
) -> Verdict {
    if structural.bands() != bands {
        return refuse_ml(structural, "ML calibration does not match the scan");
    }
    if structural.analysis().bounds.max_observations != bounds.max_observations {
        return refuse_ml(structural, "ML analysis budget does not match the scan");
    }
    let mut state = structural.into_analysis();
    state.bounds.max_reasons = bounds.max_reasons;
    state.bounds.max_excerpt_bytes = bounds.max_excerpt_bytes;
    for observation in observations {
        state.observe_ml(observation, &report);
    }

    state.ml = Some(report);
    state.finish()
}

/// Record a failed ML attempt without attaching a new report. Any report from an earlier successful
/// attempt is retained along with its findings.
fn refuse_ml(verdict: Verdict, detail: &str) -> Verdict {
    add_gap(
        verdict,
        CoverageGap::failure(IncompleteCause::TierUnavailable, detail.to_string()),
    )
}

/// Record a coverage gap against an already-finalized verdict.
///
/// The seam an optional tier needs in order to fail closed. `please-judge` cannot build a `Verdict` and
/// cannot turn a [`CoverageGap`] into an [`Incompleteness`], so without this there would be no way for it
/// to say "I did not run" — and a tier that cannot say that would have to either succeed or be silent,
/// which is the fail-open the whole outcome model exists to prevent.
///
/// # Why this is safe to make public when `Verdict::new` is not
///
/// **Adding a gap is monotone in one direction.** It can turn `Clean` into `Inconclusive` and can change
/// nothing else: it cannot add a finding, cannot remove one, cannot alter a score, and cannot make any
/// verdict *more* reassuring than it was. The worst a caller can do with it is report less confidence than
/// the evidence warrants, which is the direction this project errs in anyway.
///
/// Contrast `Verdict::new`, which decides what a verdict *says*, and which is why it is `pub(super)`.
///
/// The judgement tier is the first caller, but nothing here is judge-specific — any downstream tier that
/// can fail needs exactly this.
pub fn add_gap(verdict: Verdict, gap: CoverageGap) -> Verdict {
    // The retained findings are unchanged, so the derived score and risk stay unchanged.
    let mut state = verdict.into_analysis();
    state.incomplete.push(gap.into_incompleteness());
    state.finish()
}

/// Record a failed judge attempt without applying it. Earlier successful tier reports are retained.
///
/// Every refusal path inside `rejudge` lands here, so there is one answer to "what happens when the judge
/// cannot be trusted with this verdict" rather than one per caller. The outcome degrades to `Inconclusive`
/// unless the verdict already found risk — which is the projection's ordering, unchanged: a scan that found a
/// real payload and then lost its second opinion has still found a real payload.
fn refuse_to_judge(verdict: Verdict, detail: &str) -> Verdict {
    add_gap(
        verdict,
        CoverageGap::failure(IncompleteCause::TierUnavailable, detail.to_string()),
    )
}

/// A verdict for an input too large to analyse (FR-017).
///
/// An oversized input is not analysed at all, so there is nothing to report except that fact — and
/// reporting it as clean would be the exact fail-open the whole outcome model exists to prevent.
pub fn oversized(limit: u64, actual: usize, target: TargetRef, ruleset: RulesetId) -> Verdict {
    let detail = if target.bytes_is_lower_bound {
        format!("input is at least {actual} bytes; reading stopped at the input limit")
    } else {
        format!("input is {actual} bytes")
    };
    gap_only(
        CoverageGap::bound(IncompleteCause::InputSize, limit, detail),
        target,
        ruleset,
    )
}

/// A reader stopped after observing more bytes than the input budget allows.
///
/// Preserve the effective policy without assigning a complete-input digest to a partial read.
/// `target.bytes` is the observed lower bound, including the byte that exceeded the cap.
pub fn acquisition_limit_exceeded(
    mut target: TargetRef,
    policy: &crate::policy::ScanPolicy,
    ruleset: RulesetId,
) -> Verdict {
    target.bytes_is_lower_bound = true;
    oversized(policy.max_input_bytes, target.bytes, target, ruleset)
        .with_scan_policy(policy.effective())
}

/// A verdict for a target that could not be read (FR-032a).
///
/// Lives in the core rather than the CLI because the core never opens a file, so the *caller* doing the
/// I/O has to produce this — and it must be trivial to produce correctly. Silently skipping the file
/// instead is the one thing that must not happen: a directory reported clean on the strength of files
/// nobody read is the fail-open one level up.
pub fn unreadable_target(
    target: TargetRef,
    detail: impl Into<String>,
    ruleset: RulesetId,
) -> Verdict {
    gap_only(
        CoverageGap::failure(IncompleteCause::TargetUnreadable, detail),
        target,
        ruleset,
    )
}

/// A verdict for a target that was read but is not decodable text.
///
/// Beside [`unreadable_target`] and [`not_traversed`], and for the same reason: the core takes bytes and
/// has no concept of a file, so the caller that owns the filesystem owns the decision about what is worth
/// handing over. Deciding it here would give the core an opinion about file formats, which is exactly what
/// keeps it out of a browser (Principle V).
///
/// Inconclusive, never clean, and never a finding.
pub fn not_text(target: TargetRef, detail: impl Into<String>, ruleset: RulesetId) -> Verdict {
    gap_only(
        CoverageGap::failure(IncompleteCause::TargetNotText, detail),
        target,
        ruleset,
    )
}

/// A verdict for a target a walk deliberately did not descend into.
///
/// A symbolic link to a directory, in practice: following one may be a cycle, and refusing is how a walk
/// stays bounded. Beside [`unreadable_target`] and for the same reason — the caller owns the filesystem —
/// but a *distinct* cause, because "we could not read this" and "we chose not to open this" send a reader
/// looking in two different places.
///
/// Inconclusive, never clean. Content behind a link nobody followed is content nobody examined.
pub fn not_traversed(target: TargetRef, detail: impl Into<String>, ruleset: RulesetId) -> Verdict {
    gap_only(
        CoverageGap::failure(IncompleteCause::TargetNotTraversed, detail),
        target,
        ruleset,
    )
}

/// A verdict recording one coverage gap and no findings.
///
/// Both short-circuit paths reduce to this, which is why neither of them needs to know how an outcome is
/// derived. In 001 each built its own `VerdictParts` and each therefore had to get `score: 0` and
/// `risk: None` right independently.
fn gap_only(gap: CoverageGap, target: TargetRef, ruleset: RulesetId) -> Verdict {
    let mut evidence = Evidence::new();
    evidence.record_gap(gap);
    finalize(
        evidence,
        plan::ScanPlan::resolve(&crate::ScanPolicy::default()).bounds(),
        Attribution {
            target,
            ruleset,
            bands: Bands::default(),
        },
    )
}

/// The total order over reasons. **The only definition** (FR-125).
///
/// Byte offset, then rule id as the tie-break. Deterministic output is a requirement rather than a nicety
/// (FR-030, SC-011): it is what lets a caller cache a verdict and diff it in CI.
///
/// 001 had this twice — once in `Verdict::assemble` and once in `Engine::scan` immediately before
/// truncating — with the second existing because truncation has to happen after ordering. Two identical
/// sorts is not a bug, it is a bug waiting for someone to improve one of them.
fn order(reasons: &mut [Reason]) {
    reasons.sort_by(|a, b| {
        a.span()
            .start
            .cmp(&b.span().start)
            .then_with(|| a.rule_id().cmp(b.rule_id()))
    });
}

/// Turn one observation into a reported reason, neutralising its excerpt (FR-021, FR-126).
///
/// This was `detect::Hit::into_reason`, which put the decision about what a finding *says* in the module
/// that found it. Sanitising at this boundary rather than at each display site is what makes FR-021 hold
/// for every consumer, including the ones that forget — and there is now exactly one boundary, so there
/// is nothing to forget at.
///
/// Retain display truncation on the reason. The producer must separately report any skipped analysis.
fn into_reason(observation: Observation, max_excerpt: usize) -> Reason {
    let (matched, truncated) = sanitize_str(&observation.matched, max_excerpt);
    Reason::new(
        observation.rule_id,
        observation.class,
        observation.span,
        matched,
        truncated || observation.excerpt_truncated,
        observation.severity,
        observation.chain,
        observation.description,
        // An observation can only ever have been quote-suppressed: detection is the only thing that
        // produces one, and detection has no judgement to apply. The widening in feature 004 happens
        // here, at the one boundary observations become reasons — `SuppressedBy::Judge` is written in
        // exactly one other place, `rejudge`, and nowhere a detector can reach.
        observation.suppressed_by.map(SuppressedBy::Quoting),
    )
}

/// Engine-only attribution after every scan path, including the size gate.
pub(crate) fn record_scan_policy(
    verdict: Verdict,
    policy: crate::policy::ScanPolicy,
    input: &[u8],
    bands: &Bands,
) -> Verdict {
    let verdict = if input.len() as u64 <= policy.max_input_bytes {
        verdict.with_input_digest(ml_review::input_digest(input))
    } else {
        verdict
    };
    verdict.with_scan_policy(policy).with_bands(*bands)
}
