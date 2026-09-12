//! Display bounds must not become analysis gaps during structural → ML → judge composition.
use please_core::finalize::{
    self,
    evidence::{CoverageGap, Evidence, Observation},
    plan::Bounds,
    Attribution,
};
use please_core::ruleset::Bands;
use please_core::verdict::{
    AddressedTo, DetectionClass, Features, Framing, ImperativeSource, IncompleteCause, JudgeReport,
    MlMode, MlReport, MlSegmentResult, Outcome, RulesetId, Span, SpanJudgement, SpanRelation,
    SpanRole, SpanVerdict, StatedPurposeExplainsContent, TargetRef, Verdict,
};

fn bounds() -> Bounds {
    Bounds {
        max_input_bytes: 4096,
        max_decode_depth: 3,
        max_matches_per_rule: 16,
        max_observations: 4096,
        max_reasons: 64,
        max_excerpt_bytes: 8,
    }
}

fn observation() -> Observation {
    Observation {
        rule_id: "test.long".into(),
        class: DetectionClass::AgentDirected,
        span: Span::new(0, 1024),
        matched: "x".repeat(1024),
        severity: 75,
        chain: vec![],
        description: "A completely examined document".into(),
        excerpt_truncated: false,
        suppressed_by: None,
    }
}

fn build(ml: bool, gap: Option<CoverageGap>) -> Verdict {
    let mut evidence = Evidence::new();
    if let Some(gap) = gap {
        evidence.record_gap(gap);
    }
    if !ml {
        evidence.observe(observation());
    }
    let structural = finalize::finalize(
        evidence,
        bounds(),
        Attribution {
            target: TargetRef::buffer("examined", 1024),
            ruleset: RulesetId {
                name: "test".into(),
                version: "0".into(),
                digest: "test".into(),
            },
            bands: Bands::default(),
        },
    );
    if !ml {
        return structural;
    }
    finalize::with_ml(
        structural,
        vec![observation()],
        MlReport::new(
            "test-classifier",
            "test-revision",
            "test-digest",
            700,
            vec![MlSegmentResult::new(
                Span::new(0, 1024),
                MlMode::Classify,
                Some(1000),
                None,
            )],
        ),
        bounds(),
        &Bands::default(),
    )
}

fn demote(verdict: Verdict) -> Verdict {
    let judgements = (0..verdict.reasons().len())
        .map(|reason_index| SpanVerdict {
            reason_index,
            role: SpanRole::DescriptionOfAnInstruction,
            relation: SpanRelation::IsWhatTheDocumentShows,
            judgement: SpanJudgement::Demoted,
        })
        .collect();
    apply_authorized(
        verdict,
        JudgeReport::new(
            "offline-test",
            "fixture",
            Features {
                addressed_to: AddressedTo::DocumentRecipient,
                imperative_source: ImperativeSource::QuotedThirdParty,
                framing: Framing::PresentedAsExample,
                stated_purpose_explains_content: StatedPurposeExplainsContent::Yes,
            },
            judgements,
            None,
        ),
        &Bands::default(),
    )
}

#[test]
fn shortened_excerpt_does_not_leave_review_after_demotion() {
    for ml in [false, true] {
        let before = build(ml, None);
        assert_eq!(before.score(), 75);
        assert_eq!(before.reasons()[0].matched().len(), 8);
        assert!(before.reasons()[0].excerpt_truncated());
        let span = before.reasons()[0].span();
        let after = demote(before);
        assert!(after.reasons().is_empty());
        assert_eq!(after.suppressed().len(), 1);
        assert!(after.suppressed()[0].excerpt_truncated());
        assert_eq!(after.suppressed()[0].span(), span);
        assert_eq!(
            after.outcome(),
            Outcome::Clean,
            "display truncation is not incomplete analysis; ml={ml}"
        );
        assert_eq!(after.score(), 0);
        assert!(after.incomplete().is_empty());
        assert_eq!(after.ml().is_some(), ml);
    }
}

#[test]
fn producer_shortening_and_sanitization_expansion_keep_metadata_when_quote_suppressed() {
    use please_core::verdict::QuotingContext;
    for (matched, already_shortened, expected) in [
        ("short", false, false),
        ("short", true, true),
        ("\u{202e}\u{202e}", false, true),
    ] {
        let mut obs = observation();
        obs.matched = matched.into();
        obs.excerpt_truncated = already_shortened;
        let mut evidence = Evidence::new();
        evidence.suppress(obs, QuotingContext::FencedCode);
        let v = finalize::finalize(
            evidence,
            bounds(),
            Attribution {
                target: TargetRef::buffer("quoted", 1024),
                ruleset: RulesetId {
                    name: "test".into(),
                    version: "0".into(),
                    digest: "test".into(),
                },
                bands: Bands::default(),
            },
        );
        assert_eq!(v.outcome(), Outcome::Clean);
        assert!(v.incomplete().is_empty());
        assert_eq!(v.suppressed()[0].excerpt_truncated(), expected);
        assert!(!v.suppressed()[0].matched().contains('\u{202e}'));
    }
}

#[test]
fn real_analysis_gaps_survive_demotion_alongside_shortened_excerpts() {
    for cause in [
        IncompleteCause::InputSize,
        IncompleteCause::DecodeDepth,
        IncompleteCause::MaxMatchesPerRule,
        IncompleteCause::MaxReasons,
        // Historical/caller-supplied gaps are not silently discarded by the new representation.
        IncompleteCause::ExcerptLength,
        IncompleteCause::TargetUnreadable,
        IncompleteCause::TargetNotTraversed,
        IncompleteCause::TargetNotText,
        IncompleteCause::DecodeFailed,
        IncompleteCause::RulesetUnavailable,
        IncompleteCause::TierUnavailable,
    ] {
        for ml in [false, true] {
            let gap = if cause.is_bound() {
                CoverageGap::bound(cause, 1, "analysis stopped")
            } else {
                CoverageGap::failure(cause, "analysis failed")
            };
            let before = build(ml, Some(gap));
            let original_gap = before
                .incomplete()
                .iter()
                .find(|g| g.cause() == cause)
                .unwrap()
                .clone();
            let after = demote(before);
            assert_eq!(after.outcome(), Outcome::Inconclusive, "{cause:?}; ml={ml}");
            assert!(after.incomplete().contains(&original_gap));
        }
    }
}

fn apply_authorized(
    verdict: please_core::Verdict,
    report: please_core::JudgeReport,
    bands: &please_core::ruleset::Bands,
) -> please_core::Verdict {
    use please_core::finalize::review::{ReviewAuthority, ReviewScope};
    assert_eq!(verdict.bands(), bands);
    let report = ReviewScope::capture(&verdict).bind(report);
    please_core::finalize::rejudge_with_authority(verdict, report, ReviewAuthority::MayRelease)
}
