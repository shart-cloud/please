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
//! # The score is derived here, not accepted here (T058, T060)
//!
//! [`finalize`] takes no score. It aggregates one from the evidence it was handed, and bands it with the
//! table the caller supplied.
//!
//! Until T058 the score arrived as an argument, which meant the caller had to hold its own collection of
//! `(severity, class)` pairs alongside the accumulator in order to compute it. `Engine::scan` in 001 held six
//! overlapping collections and the score's correctness was the agreement between the first and the last,
//! maintained by a comment. With one accumulator and no way for a caller to read it, aggregating over
//! everything found is the only thing expressible — the bug class goes away rather than the instance
//! (FR-124).
//!
//! Note which of the two is still an input. The **band table** is data a deployment retunes without a
//! rebuild, so it is supplied. The **score** is a function of the evidence, so it is not. 001 accepted both
//! and then silently overwrote them for non-`RiskFound` outcomes, so a call site reading `score: 42` produced
//! a verdict saying 0 — the adjustment FR-127 objects to. There is now nothing to overwrite.

pub mod evidence;
pub mod plan;
pub mod score;
pub mod types;

use crate::ruleset::Bands;
use crate::sanitize::sanitize_str;
use evidence::{CoverageGap, Evidence, Observation, Suppression};
use plan::Bounds;
use score::aggregate;
use types::{
    DetectionClass, EngineId, IncompleteCause, Incompleteness, JudgeReport, Outcome, Reason,
    RiskLevel, RulesetId, SpanJudgement, SuppressedBy, TargetRef, Verdict,
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
/// understate the score (FR-001b). Which is why the score is taken in step 0, from the observations, before
/// anything here has had the chance to drop one.
pub fn finalize(evidence: Evidence, bounds: Bounds, attribution: Attribution) -> Verdict {
    let (observations, mut gaps, suppressions) = evidence.into_parts();

    // ── Score, before anything can be dropped ───────────────────────────────────────────────────
    //
    // First, deliberately. Aggregating here rather than after truncation is FR-001b, and doing it from the
    // observations rather than from a value handed in is FR-124: there is one collection, so there is nothing
    // for a second one to disagree with.
    let severities: Vec<(u8, DetectionClass)> = observations
        .iter()
        .map(|observation| (observation.severity, observation.class))
        .collect();
    let score = aggregate(&severities);
    let risk = attribution.bands.band(score);

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

    // ── Suppressions become annotated reasons ───────────────────────────────────────────────────
    //
    // Same conversion as a reported reason, deliberately: `--explain` prints these, so the excerpt has to be
    // neutralised by the same code that neutralises everything else (FR-021). An excerpt that is safe only
    // when it is reported is not safe.
    //
    // No coverage gap is recorded when a suppressed excerpt is truncated. The reader is not being shown the
    // whole excerpt of something they are not being shown at all, and a gap here would flip the verdict of
    // every document that quotes a payload to `Inconclusive`.
    let mut suppressed: Vec<Reason> = suppressions
        .into_iter()
        .map(
            |Suppression {
                 mut observation,
                 context,
             }| {
                observation.suppressed_by = Some(context);
                into_reason(observation, bounds.max_excerpt_bytes as usize).0
            },
        )
        .collect();

    // ── One ordering definition ─────────────────────────────────────────────────────────────────
    order(&mut reasons);
    order(&mut suppressed);

    let mut suppressions_truncated = false;
    if suppressed.len() > bounds.max_reasons as usize {
        // Bounded for the reason reasons are (FR-007): a document quoting ten thousand payloads must not
        // produce a ten-thousand-entry report. NOT recorded as incompleteness — see above.
        suppressions_truncated = true;
        suppressed.truncate(bounds.max_reasons as usize);
    }

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

    assemble(
        reasons,
        reasons_truncated,
        suppressed,
        suppressions_truncated,
        incomplete,
        score,
        risk,
        attribution,
    )
}

/// Apply a judgement to a finalized verdict (feature 004, FR-403).
///
/// **The judge supplies decisions; it does not assemble verdicts.** `Verdict::new` is `pub(super)` to this
/// module, so `please-judge` — a different crate entirely — cannot construct one. That is not an obstacle
/// worked around here, it is the guarantee 002 spent a phase establishing, preserved by giving the judgement
/// tier a seam instead of a constructor. `tests/seams.rs` still asserts exactly one `Verdict::new(` call
/// site, and this function routes through [`assemble`] like everything else.
///
/// # What it can do
///
/// Move an observation from `reasons` into `suppressed`, annotated [`SuppressedBy::Judge`]. That is all. It
/// cannot erase one, cannot raise a severity, and cannot introduce one — not because those are validated
/// against but because [`SpanJudgement`] has two variants and neither expresses them. For any report
/// whatsoever, including a maximally hostile one:
///
/// ```text
/// judged.reasons() ∪ judged.suppressed()  ==  structural.reasons() ∪ structural.suppressed()
/// max severity in judged                  ≤   max severity in structural
/// ```
///
/// # Why a truncated verdict is refused (plan D9, FR-421)
///
/// [`finalize`] aggregates the score **from the observations, before anything can be dropped** (FR-001b) —
/// it is step 0 up there, deliberately. By the time a `Verdict` exists, the reasons have been ordered and
/// truncated to `max_reasons`, and the severities of everything past the bound are gone.
///
/// So a `rejudge` that recomputed from the surviving reasons would silently *lower* the score on any
/// truncated verdict — not because a judgement demoted anything, but because the truncated contributions
/// were never there to begin with. That is a fail-open reachable by arithmetic alone, in a tier whose entire
/// premise is that degradation goes to `Inconclusive` and never to something cheerful.
///
/// The alternative was to have `Verdict` retain its pre-truncation severities. It is exact, it may become
/// necessary once there is a corpus, and it makes core carry state whose only consumer is an optional tier —
/// which is the one thing D1 says core does not do. Refusing costs a document that produced more than
/// `max_reasons` findings, and a document with more than sixty-four findings is not one whose *precision*
/// problem a second opinion was going to fix.
///
/// # Bands are supplied, not remembered
///
/// A `Verdict` records its score and its risk band but not the table that mapped one to the other, because
/// until now nothing needed to re-band. Demotion changes the score, so the table has to come back — from
/// [`crate::Engine::bands`], the same one the scan used. Passing it explicitly is what stops a re-band
/// against a different table than the original, which would produce a verdict quietly disagreeing with
/// itself.
pub fn rejudge(verdict: Verdict, report: JudgeReport, bands: &Bands) -> Verdict {
    if verdict.reasons_truncated() {
        return refuse_to_judge(
            verdict,
            "verdict truncated before judgement; the score cannot be recomputed exactly",
        );
    }

    // Indices are into the structural `reasons()` as the judge saw them. An index past the end is a report
    // about a different verdict, and applying part of it would demote whichever reason happened to sit at a
    // valid index — arbitrary, and arbitrary in the attacker's favour half the time.
    let count = verdict.reasons().len();
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
        for judgement in report.judgements() {
            // `|=` rather than `=`: two judgements naming the same index cannot un-demote each other.
            // Contradiction resolves toward the structural verdict, never away from it.
            flags[judgement.reason_index] |= judgement.judgement == SpanJudgement::Demoted;
        }
        flags
    };

    let (reasons, suppressed, score, risk, reasons_truncated, suppressions_truncated, attribution) =
        disassemble(verdict, bands, &demoted);

    assemble(
        reasons,
        reasons_truncated,
        suppressed,
        suppressions_truncated,
        // Judged successfully, so no gap is added. The gaps the structural verdict already carried are
        // preserved — a judgement resolves nothing about coverage.
        Vec::new(),
        score,
        risk,
        attribution,
    )
    .with_judge(report)
}

/// Rebuild a verdict with the demoted reasons moved, without ever calling `Verdict::new`.
///
/// Returns the pieces `assemble` wants. Separate from [`rejudge`] because the destructuring is noisy and
/// the decision it implements — which list each reason belongs in — is one line that should be readable.
#[allow(clippy::type_complexity)]
fn disassemble(
    verdict: Verdict,
    bands: &Bands,
    demoted: &[bool],
) -> (
    Vec<Reason>,
    Vec<Reason>,
    u8,
    RiskLevel,
    bool,
    bool,
    Attribution,
) {
    let attribution = Attribution {
        target: verdict.target().clone(),
        ruleset: verdict.ruleset().clone(),
        bands: *bands,
    };
    let reasons_truncated = verdict.reasons_truncated();
    let suppressions_truncated = verdict.suppressions_truncated();
    let mut suppressed: Vec<Reason> = verdict.suppressed().to_vec();

    let mut kept: Vec<Reason> = Vec::new();
    for (index, reason) in verdict.reasons().iter().enumerate() {
        let mut reason = reason.clone();
        if demoted[index] {
            reason.demote_by_judge();
            suppressed.push(reason);
        } else {
            kept.push(reason);
        }
    }

    // Re-aggregate over what is still reported. Exact here in a way it would not be on a truncated verdict:
    // every reason the score was originally computed from is present, so removing the demoted ones removes
    // exactly their contribution (plan D9).
    let severities: Vec<(u8, DetectionClass)> = kept
        .iter()
        .map(|reason| (reason.severity(), reason.class()))
        .collect();
    let score = aggregate(&severities);
    let risk = bands.band(score);

    // Suppressed reasons arrive from two places now — quoting suppression during the scan, and demotion
    // just above — and must still be in one order (FR-125). Note that this is the ONLY place the two lists
    // interact, and it moves reasons between them without creating or dropping any: the union is preserved
    // by construction rather than by check, which is what SC-406 is a test of.
    order(&mut suppressed);

    (
        kept,
        suppressed,
        score,
        risk,
        reasons_truncated,
        suppressions_truncated,
        attribution,
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
    let attribution = Attribution {
        target: verdict.target().clone(),
        ruleset: verdict.ruleset().clone(),
        // Never consulted. Score and risk are carried through unchanged: nothing was demoted, so there is
        // nothing to re-band, and `assemble` zeroes both for a non-`RiskFound` outcome anyway.
        bands: Bands::default(),
    };
    let mut incomplete: Vec<Incompleteness> = verdict.incomplete().to_vec();
    incomplete.push(gap.into_incompleteness());

    assemble(
        verdict.reasons().to_vec(),
        verdict.reasons_truncated(),
        verdict.suppressed().to_vec(),
        verdict.suppressions_truncated(),
        incomplete,
        verdict.score(),
        verdict.risk(),
        attribution,
    )
}

/// Return the structural verdict with a `TierUnavailable` gap and **no judgement applied**.
///
/// Every refusal path inside `rejudge` lands here, so there is one answer to "what happens when the judge
/// cannot be trusted with this verdict" rather than one per caller. The outcome degrades to `Inconclusive`
/// unless the verdict already found risk — which is [`assemble`]'s ordering, unchanged: a scan that found a
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
    assemble(
        Vec::new(),
        false,
        Vec::new(),
        false,
        vec![gap.into_incompleteness()],
        // No findings, so nothing for a score to summarise. Passed explicitly rather than defaulted so this
        // reads as a fact about the verdict rather than as a field nobody filled in.
        0,
        RiskLevel::None,
        Attribution {
            target,
            ruleset,
            // Never consulted: banding zero under any ascending table gives `None`. Supplied because the
            // struct requires it, and `Bands::default()` is the honest choice — a scan that examined nothing
            // has no deployment-specific calibration to report.
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
            // An observation can only ever have been quote-suppressed: detection is the only thing that
            // produces one, and detection has no judgement to apply. The widening in feature 004 happens
            // here, at the one boundary observations become reasons — `SuppressedBy::Judge` is written in
            // exactly one other place, `rejudge`, and nowhere a detector can reach.
            observation.suppressed_by.map(SuppressedBy::Quoting),
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
#[allow(clippy::too_many_arguments)]
fn assemble(
    reasons: Vec<Reason>,
    reasons_truncated: bool,
    suppressed: Vec<Reason>,
    suppressions_truncated: bool,
    incomplete: Vec<Incompleteness>,
    score: u8,
    risk: RiskLevel,
    attribution: Attribution,
) -> Verdict {
    let Attribution {
        target,
        ruleset,
        bands: _,
    } = attribution;

    let outcome = if !reasons.is_empty() {
        Outcome::RiskFound
    } else if !incomplete.is_empty() {
        Outcome::Inconclusive
    } else {
        Outcome::Clean
    };

    // A verdict with no reasons has nothing for a score to summarise.
    //
    // Note that this is no longer a *correction*. The score was aggregated from the observations, and a
    // verdict with no reasons is a verdict whose observations were empty or were all dropped by the class
    // filter — either way `aggregate` over nothing is 0 already. Kept as an explicit branch because the
    // second case is real: an `Inconclusive` verdict can carry observations that the class filter removed,
    // and reporting a score for findings nobody is being shown would be incoherent.
    //
    // 001 wrote this same match over a score the CALLER supplied, which made it a silent adjustment: the
    // call site said 42 and the verdict said 0 (FR-127).
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
        suppressed,
        suppressions_truncated,
        incomplete,
        target,
        ruleset,
        EngineId::current(),
    )
}
