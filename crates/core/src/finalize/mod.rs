//! Verdict finalization — the one place that decides what a verdict says (FR-120).
//!
//! Feature 001 built verdicts in three places in `engine.rs`: the size gate, the main path, and the
//! unreadable target, each assembling a `VerdictParts` by hand. Three producers means three chances to
//! forget the aggregate-before-truncate rule, three orderings of reasons that have to agree, and a class
//! of bug that code review either catches or does not. The parts struct is gone (T020) and so are the
//! other two producers; [`finalize`] is the only route to a [`Verdict`](types::Verdict).
//!
//! Detectors produce [`Evidence`](evidence::Evidence) and nothing else. That makes several disciplines
//! from 001 structural rather than remembered:
//!
//!   * reason ordering has one definition, because there is one producer (FR-125);
//!   * the observation-to-reason transition, including excerpt neutralisation, happens at one boundary,
//!     so FR-021 holds for every consumer including the ones that forget (FR-126);
//!   * a detector cannot construct a `Reason` at all, because the constructors are `pub(super)` and a
//!     detector is not a submodule of this one (FR-121, and see `tests/compile_fail/`).
//!
//! The verdict types live *inside* this module rather than beside it for exactly that last reason: Rust
//! cannot grant construction rights to a sibling, so a module that must be the sole producer has to be
//! the module the types are defined in (research P3, and [`types`] documents it at length).
//!
//! # What is still passed in rather than derived
//!
//! [`finalize`] takes `score` and `risk` as arguments. It should not: the evidence it already holds is
//! everything the score is computed from, and taking them as arguments means `engine.rs` keeps a parallel
//! collection of `(severity, class)` pairs alongside the accumulator, which is precisely the
//! two-collections shape FR-124 exists to remove. T058 and T060 close that in Phase 5, with the tests
//! that go red first. Phase 2 is behaviour-preserving and stops here on purpose.

pub mod evidence;
pub mod plan;
pub mod score;
pub mod types;

use crate::sanitize::sanitize_str;
use evidence::{CoverageGap, Evidence, Observation};
use plan::Bounds;
use types::{
    EngineId, IncompleteCause, Incompleteness, Outcome, Reason, RiskLevel, RulesetId, TargetRef,
    Verdict,
};

/// Everything a verdict needs that is not evidence: who scanned, what with, and how it scored.
///
/// A struct rather than six positional parameters, for the reason 001 gave for `VerdictParts` and which
/// still holds: adjacent same-typed fields are easy to transpose, and a transposed `score`/`severity`
/// pair is a silent scoring bug rather than a compile error.
///
/// This is **not** `VerdictParts` under a new name, and the difference is the whole of FR-120. The parts
/// struct carried the reasons and the coverage gaps — the evidence itself — so any caller who could build
/// one was deciding what the verdict said. This carries only attribution and the score, and the evidence
/// arrives separately through an accumulator the caller cannot read. `score` and `risk` are here for one
/// phase longer; see the module documentation.
#[derive(Debug, Clone)]
pub struct Attribution {
    pub score: u8,
    pub risk: RiskLevel,
    pub target: TargetRef,
    pub ruleset: RulesetId,
}

/// Turn evidence into a verdict. **The only producer** (FR-120).
///
/// The order of operations is the design, and each step is here rather than in a caller because a caller
/// doing it is a caller who can do it differently:
///
/// 1. every observation becomes a reason, neutralising its excerpt — and recording a gap if the excerpt
///    had to be truncated to fit (FR-122, FR-126);
/// 2. reasons are put into a total order (FR-125);
/// 3. the order is truncated to the reason bound, recording that as a gap;
/// 4. the outcome is derived from what is left plus every gap.
///
/// Step 3 after step 2 is not incidental. The order is by byte offset rather than by severity, so
/// truncating an unordered list would keep whichever reasons the rule iteration order happened to produce
/// (SC-011) — and truncating *before* aggregating the score would let a dropped high-severity finding
/// understate the score (FR-001b). The score is aggregated over the evidence, upstream of all of this.
pub fn finalize(evidence: Evidence, bounds: Bounds, attribution: Attribution) -> Verdict {
    let (observations, mut gaps) = evidence.into_parts();

    // ── Observations become reasons ─────────────────────────────────────────────────────────────
    let mut reasons: Vec<Reason> = Vec::with_capacity(observations.len());
    for observation in observations {
        let (reason, excerpt_truncated) =
            into_reason(observation, bounds.max_excerpt_bytes as usize);
        if excerpt_truncated {
            // Recorded here rather than by the sanitiser, which returns a boolean and has no idea whose
            // excerpt it shortened or what the bound was called (FR-122).
            gaps.push(CoverageGap::bound(
                IncompleteCause::ExcerptLength,
                bounds.max_excerpt_bytes as u64,
                format!("excerpt for `{}` truncated", reason.rule_id()),
            ));
        }
        reasons.push(reason);
    }

    // ── One ordering definition ─────────────────────────────────────────────────────────────────
    order(&mut reasons);

    // ── Truncate ────────────────────────────────────────────────────────────────────────────────
    let mut reasons_truncated = false;
    if reasons.len() > bounds.max_reasons as usize {
        reasons_truncated = true;
        gaps.push(CoverageGap::bound(
            IncompleteCause::MaxReasons,
            bounds.max_reasons as u64,
            format!("{} reasons found", reasons.len()),
        ));
        reasons.truncate(bounds.max_reasons as usize);
    }

    let incomplete: Vec<Incompleteness> = gaps
        .into_iter()
        .map(CoverageGap::into_incompleteness)
        .collect();

    assemble(reasons, reasons_truncated, incomplete, attribution)
}

/// A verdict for an input too large to analyse (FR-017).
///
/// An oversized input is not analysed at all, so there is nothing to report except that fact — and
/// reporting it as clean would be the exact fail-open the whole outcome model exists to prevent.
pub fn oversized(limit: u64, actual: usize, target: TargetRef, ruleset: RulesetId) -> Verdict {
    gap_only(
        CoverageGap::bound(
            IncompleteCause::InputSize,
            limit,
            format!("input is {actual} bytes"),
        ),
        target,
        ruleset,
    )
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

/// A verdict recording one coverage gap and no findings.
///
/// Both short-circuit paths reduce to this, which is why neither of them needs to know how an outcome is
/// derived. In 001 each built its own `VerdictParts` and each therefore had to get `score: 0` and
/// `risk: None` right independently.
fn gap_only(gap: CoverageGap, target: TargetRef, ruleset: RulesetId) -> Verdict {
    assemble(
        Vec::new(),
        false,
        vec![gap.into_incompleteness()],
        Attribution {
            score: 0,
            risk: RiskLevel::None,
            target,
            ruleset,
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
/// Returns whether the excerpt had to be shortened. The caller records that as a coverage gap; this
/// function does not, because a function that both transforms and records is two functions.
fn into_reason(observation: Observation, max_excerpt: usize) -> (Reason, bool) {
    let (matched, truncated) = sanitize_str(&observation.matched, max_excerpt);
    (
        Reason::new(
            observation.rule_id,
            observation.class,
            observation.span,
            matched,
            observation.severity,
            observation.chain,
            observation.description,
            // Populated by T068, once suppressions are retained rather than discarded (FR-128).
            None,
        ),
        truncated,
    )
}

/// Derive the outcome and build the verdict.
///
/// **The single point where the [`Outcome::Clean`] invariant is decided** (FR-004, FR-032b). The order of
/// the three branches is the design:
///
/// 1. Any reason at all makes this `RiskFound`, **even if coverage was also incomplete**. A scan that
///    found a real payload and then ran out of budget has still found a real payload; downgrading it to
///    inconclusive would discard a confirmed detection. The gap stays visible in the verdict so the
///    caller knows the finding may not be the only one.
/// 2. Otherwise, anything left unexamined makes this `Inconclusive`. "Found nothing" and "looked at
///    nothing" are indistinguishable from the outside, so they must not collapse into one outcome.
/// 3. Only with both empty is the verdict `Clean`.
fn assemble(
    reasons: Vec<Reason>,
    reasons_truncated: bool,
    incomplete: Vec<Incompleteness>,
    attribution: Attribution,
) -> Verdict {
    let Attribution {
        score,
        risk,
        target,
        ruleset,
    } = attribution;

    let outcome = if !reasons.is_empty() {
        Outcome::RiskFound
    } else if !incomplete.is_empty() {
        Outcome::Inconclusive
    } else {
        Outcome::Clean
    };

    // A verdict with no reasons has nothing for a score to summarise, so any score handed in is
    // discarded rather than reported. Trusting the caller here would let a scoring bug surface as a
    // confusing "clean, score 42" verdict instead of as a failing test. T060 removes the need for this
    // by deriving the score here instead of accepting one.
    let (score, risk) = match outcome {
        Outcome::Clean | Outcome::Inconclusive => (0, RiskLevel::None),
        Outcome::RiskFound => (score, risk),
    };

    Verdict::new(
        outcome,
        score,
        risk,
        reasons,
        reasons_truncated,
        incomplete,
        target,
        ruleset,
        EngineId::current(),
    )
}
