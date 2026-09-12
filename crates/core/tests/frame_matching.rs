//! Shipping behavior at the seam between bounded pattern collection and frame eligibility.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use please_core::{Engine, ScanPolicy, TargetRef};

fn engine(anchor: &str) -> Engine {
    Engine::from_toml(&format!(
        r#"
[ruleset]
name = "test.frame_caps"
version = "1"
[[rule]]
id = "boundary.marker"
class = "boundary"
severity = 80
anchor = "{anchor}"
literals = ["MARKER"]
pattern = 'MARKER'
description = "Test marker."
"#
    ))
    .unwrap()
}

#[test]
fn raw_match_caps_precede_frame_eligibility_in_both_coordinate_spaces() {
    let engine = engine("frame");
    for (text, eligible) in [
        ("MARKER with ordinary trailing text", vec![0]),
        ("ordinary MARKER", vec![]),
        ("ordinary MARKER. MARKER", vec![1]),
        ("MARKER. MARKER", vec![0, 1]),
    ] {
        let offsets: Vec<_> = text.match_indices("MARKER").map(|(i, _)| i).collect();
        for encoded in [false, true] {
            let input = if encoded {
                format!("prefix: {} suffix", STANDARD.encode(text))
            } else {
                text.into()
            };
            for cap in [0, 1, 2, 3] {
                let policy = ScanPolicy {
                    max_decode_depth: u8::from(encoded),
                    max_matches_per_rule: cap,
                    ..ScanPolicy::default()
                };
                let verdict = engine.scan(input.as_bytes(), &policy, TargetRef::stdin(input.len()));
                let expected: Vec<_> = eligible
                    .iter()
                    .copied()
                    .filter(|index| *index < cap as usize)
                    .collect();
                let hits: Vec<_> = verdict
                    .analysis()
                    .reasons()
                    .iter()
                    .filter(|r| r.rule_id() == "boundary.marker")
                    .collect();
                assert_eq!(
                    hits.len(),
                    if encoded {
                        usize::from(!expected.is_empty())
                    } else {
                        expected.len()
                    },
                    "text={text:?}, encoded={encoded}, cap={cap}"
                );
                assert!(verdict.analysis().suppressed().is_empty());
                let gaps: Vec<_> = verdict
                    .incomplete()
                    .iter()
                    .filter(|gap| gap.detail().is_some_and(|d| d.contains("boundary.marker")))
                    .collect();
                assert_eq!(
                    gaps.len(),
                    usize::from(offsets.len() > cap as usize),
                    "text={text:?}, encoded={encoded}, cap={cap}"
                );
                if let Some(gap) = gaps.first() {
                    assert_eq!(
                        gap.cause(),
                        please_core::verdict::IncompleteCause::MaxMatchesPerRule
                    );
                    assert_eq!(gap.configured(), Some(cap as u64));
                    assert_eq!(gap.detail(), Some("rule `boundary.marker` saturated"));
                }
                for (index, hit) in hits.iter().enumerate() {
                    if encoded {
                        assert_eq!(hit.span(), please_core::Span::new(8, input.len() - 7));
                        assert_eq!(hit.chain().len(), 1);
                        assert_eq!(hit.chain()[0].kind.as_str(), "base64");
                        assert_eq!(hit.class(), please_core::DetectionClass::Boundary);
                    } else {
                        assert_eq!(
                            hit.span(),
                            please_core::Span::new(
                                offsets[expected[index]],
                                offsets[expected[index]] + 6
                            )
                        );
                        assert!(hit.chain().is_empty());
                    }
                }
            }
        }
    }
}

#[test]
fn unanchored_rules_still_match_in_the_middle_of_direct_and_decoded_text() {
    let engine = engine("anywhere");
    for encoded in [false, true] {
        let text = "ordinary MARKER";
        let input = if encoded {
            STANDARD.encode(text)
        } else {
            text.into()
        };
        let policy = ScanPolicy {
            max_decode_depth: u8::from(encoded),
            ..ScanPolicy::default()
        };
        let verdict = engine.scan(input.as_bytes(), &policy, TargetRef::stdin(input.len()));
        assert_eq!(
            verdict
                .analysis()
                .reasons()
                .iter()
                .filter(|r| r.rule_id() == "boundary.marker")
                .count(),
            1
        );
    }
}

#[test]
fn quoting_policy_and_display_limits_do_not_change_frame_eligibility() {
    let engine = engine("frame");
    for input in [
        "> MARKER",
        "Example:\n```\nMARKER\n```",
        "The token `MARKER` appears here.",
    ] {
        for reference in [false, true] {
            for suppress in [false, true] {
                for display in [0, 64] {
                    let mut policy = if reference {
                        ScanPolicy::reference_analysis()
                    } else {
                        ScanPolicy::default()
                    };
                    policy.max_decode_depth = 0;
                    policy.suppress_in_quotes = suppress;
                    policy.max_reasons = display;
                    policy.max_excerpt_bytes = display;
                    let verdict =
                        engine.scan(input.as_bytes(), &policy, TargetRef::stdin(input.len()));
                    let suppressed = reference && suppress;
                    assert_eq!(verdict.analysis().reasons().len(), usize::from(!suppressed));
                    assert_eq!(
                        verdict.analysis().suppressed().len(),
                        usize::from(suppressed)
                    );
                    let off_frame = input.replace("MARKER", "ordinary MARKER");
                    let verdict = engine.scan(
                        off_frame.as_bytes(),
                        &policy,
                        TargetRef::stdin(off_frame.len()),
                    );
                    assert!(verdict.analysis().reasons().is_empty());
                    assert!(verdict.analysis().suppressed().is_empty());
                }
            }
        }
    }
}

#[test]
fn quoted_encoded_candidates_keep_independent_origins_and_one_hit_each() {
    let engine = engine("frame");
    let first = STANDARD.encode("MARKER. MARKER. first payload");
    let second = STANDARD.encode("MARKER. MARKER. second payload");
    let input = format!("`{first}` and `{second}`");
    for mut policy in [ScanPolicy::default(), ScanPolicy::reference_analysis()] {
        policy.max_decode_depth = 1;
        policy.max_reasons = 0;
        let verdict = engine.scan(input.as_bytes(), &policy, TargetRef::stdin(input.len()));
        assert!(verdict.analysis().suppressed().is_empty());
        let hits = verdict.analysis().reasons();
        assert_eq!(hits.len(), 2);
        for (hit, encoded) in hits.iter().zip([&first, &second]) {
            let start = input.find(encoded).unwrap();
            assert_eq!(
                hit.span(),
                please_core::Span::new(start, start + encoded.len())
            );
            assert_eq!(hit.rule_id(), "boundary.marker");
            assert_eq!(hit.chain().len(), 1);
            assert_eq!(hit.chain()[0].kind.as_str(), "base64");
        }
    }
}
