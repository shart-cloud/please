//! The built-in rule set measured against the labelled fixture corpus (SC-002, SC-003, SC-001, SC-008).
//!
//! This is the only accuracy evidence Feature 001 has. Corpus-scale, per-source stratified metrics arrive
//! with `please-eval`, and until then no accuracy claim about this tool may be published — see
//! `docs/limits.md`. What these tests establish is narrower and still worth having: the mechanisms work,
//! and regressions are caught.
//!
//! The reporting here is deliberately per-context and per-difficulty rather than one blended number.
//! `context` records where hostile text would actually arrive — an email body, a tool result, a skill file,
//! an MCP tool description — and a strong result on one vector must not be able to conceal a weak one on
//! another.

mod support;

use please_core::policy::ScanPolicy;
use please_core::verdict::{Outcome, RiskLevel, TargetRef};
use please_core::Engine;
use support::{load_all_cases, Case, Expected};

fn engine() -> Engine {
    Engine::builtin().expect("the built-in rule set must load")
}

fn scan(engine: &Engine, case: &Case) -> please_core::Verdict {
    engine.scan(
        case.text.as_bytes(),
        &ScanPolicy::default(),
        TargetRef::buffer(&case.id, case.text.len()),
    )
}

/// A finding at or above this band counts as a detection.
///
/// `Low` rather than the default `High`, because these tests measure whether the *mechanism* fires, not
/// whether the provisional band boundaries happen to be tuned. Band calibration is the evaluation
/// harness's job; conflating the two would make every future recalibration look like a detection
/// regression.
const DETECTION_FLOOR: RiskLevel = RiskLevel::Low;

fn detected(verdict: &please_core::Verdict) -> bool {
    verdict.outcome() == Outcome::RiskFound && verdict.is_at_or_above(DETECTION_FLOOR)
}

// ── SC-002: every detection class fires on its positives ───────────────────────────────────────

#[test]
fn every_positive_case_is_detected() {
    let engine = engine();
    let mut missed: Vec<&Case> = Vec::new();
    let cases = load_all_cases();

    for case in cases.iter().filter(|c| c.expected == Expected::Injection) {
        if !detected(&scan(&engine, case)) {
            missed.push(case);
        }
    }

    if !missed.is_empty() {
        eprintln!("\n{} undetected positive case(s):", missed.len());
        for case in &missed {
            eprintln!(
                "  {:<32} [{:<20} {:<6}] {}",
                case.id, case.context, case.difficulty, case.subcategory
            );
        }
        eprintln!();
    }

    let total = cases
        .iter()
        .filter(|c| c.expected == Expected::Injection)
        .count();
    assert!(
        missed.is_empty(),
        "{}/{} positives detected; {} missed (listed above)",
        total - missed.len(),
        total,
        missed.len()
    );
}

#[test]
fn every_declared_expected_class_actually_fires() {
    // A case carrying `expected_classes` asserts *which* mechanism should catch it, not merely that
    // something did. Without this, a case could pass because an unrelated rule happened to match — which
    // is how a detection class silently stops working while the suite stays green.
    let engine = engine();
    let mut wrong: Vec<String> = Vec::new();

    for case in load_all_cases()
        .iter()
        .filter(|c| !c.expected_classes.is_empty())
    {
        let verdict = scan(&engine, case);
        let fired: Vec<String> = verdict
            .reasons()
            .iter()
            .map(|r| r.class.as_str().to_string())
            .collect();
        for expected in &case.expected_classes {
            if !fired.contains(expected) {
                wrong.push(format!(
                    "{}: expected class `{expected}`, fired {fired:?}",
                    case.id
                ));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "class expectations unmet:\n  {}",
        wrong.join("\n  ")
    );
}

// ── SC-003: the false-positive gate ────────────────────────────────────────────────────────────

#[test]
fn the_false_positive_rate_is_within_budget() {
    // The criterion that decides whether anyone adopts this. A firewall with a bad false-positive rate
    // gets switched off, and then it protects nothing.
    const MAX_RATE: f64 = 0.01;
    const REQUIRED_NEGATIVES: usize = 200;

    let engine = engine();
    let cases = load_all_cases();
    let negatives: Vec<&Case> = cases.iter().filter(|c| c.is_benign()).collect();

    let mut false_positives: Vec<&Case> = Vec::new();
    for case in &negatives {
        if detected(&scan(&engine, case)) {
            false_positives.push(case);
        }
    }

    if !false_positives.is_empty() {
        eprintln!("\n{} false positive(s):", false_positives.len());
        for case in &false_positives {
            let verdict = scan(&engine, case);
            eprintln!(
                "  {:<34} score {:<4} {:?}",
                case.id,
                verdict.score(),
                verdict
                    .reasons()
                    .iter()
                    .map(|r| r.rule_id.as_str())
                    .collect::<Vec<_>>()
            );
            eprintln!("      why benign: {}", case.notes);
        }
        eprintln!();
    }

    let rate = false_positives.len() as f64 / negatives.len().max(1) as f64;

    // The size minimum is part of the criterion, not a suggestion: a 1% rate over 20 cases silently means
    // zero, which is a materially stricter bar than the one intended and cannot be met honestly. Until the
    // corpus reaches 200 this reports rather than gates, because failing on a corpus we have not written
    // yet would just be a red suite nobody can act on.
    if negatives.len() < REQUIRED_NEGATIVES {
        eprintln!(
            "note: {}/{REQUIRED_NEGATIVES} benign cases. The SC-003 gate is not yet meaningful; \
             current false-positive rate {:.1}% over {} cases is informational only.",
            negatives.len(),
            rate * 100.0,
            negatives.len()
        );
        assert!(
            false_positives.is_empty(),
            "with a corpus this small, any false positive is worth failing on"
        );
        return;
    }

    assert!(
        rate <= MAX_RATE,
        "false-positive rate {:.2}% exceeds {:.2}% over {} negatives",
        rate * 100.0,
        MAX_RATE * 100.0,
        negatives.len()
    );
}

// ── SC-001 and SC-008: findings must be actionable ─────────────────────────────────────────────

#[test]
fn every_finding_is_actionable() {
    // SC-001's mechanical half: a reader must be able to say what was found and where, from the output
    // alone. Every field below is one a reader needs; a finding missing any of them is an assertion rather
    // than evidence.
    let engine = engine();
    let mut defects: Vec<String> = Vec::new();

    for case in load_all_cases() {
        let verdict = scan(&engine, &case);
        for reason in verdict.reasons() {
            if reason.rule_id.is_empty() {
                defects.push(format!("{}: reason with no rule id", case.id));
            }
            if reason.span.end <= reason.span.start {
                defects.push(format!(
                    "{}: reason `{}` has an empty span",
                    case.id, reason.rule_id
                ));
            }
            if reason.description.trim().is_empty() {
                defects.push(format!(
                    "{}: reason `{}` has no description",
                    case.id, reason.rule_id
                ));
            }
            if reason.matched.is_empty() {
                defects.push(format!(
                    "{}: reason `{}` has no excerpt",
                    case.id, reason.rule_id
                ));
            }
        }
    }

    assert!(
        defects.is_empty(),
        "unactionable findings:\n  {}",
        defects.join("\n  ")
    );
}

#[test]
fn no_excerpt_leaks_a_raw_control_or_invisible_character() {
    // FR-021 over the whole corpus. The concealment fixtures are the interesting ones here: their content
    // is precisely the characters that must not survive into a report.
    let engine = engine();
    for case in load_all_cases() {
        let verdict = scan(&engine, &case);
        for reason in verdict.reasons() {
            for ch in reason.matched.chars() {
                let code = ch as u32;
                let dangerous = matches!(code, 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F..=0x9F)
                    || matches!(code, 0x200B..=0x200F | 0x202A..=0x202E | 0xE0000..=0xE007F);
                assert!(
                    !dangerous,
                    "{}: excerpt for `{}` leaked U+{code:04X}",
                    case.id, reason.rule_id
                );
            }
        }
    }
}

// ── Reporting, not gating ──────────────────────────────────────────────────────────────────────

#[test]
fn report_detection_by_context_and_difficulty() {
    // Printed rather than asserted. A single blended detection rate hides exactly what matters: whether
    // the tool is weak on a whole attack vector. Run with `--nocapture` to read it.
    let engine = engine();
    let cases = load_all_cases();

    let mut contexts: Vec<String> = cases.iter().map(|c| c.context.clone()).collect();
    contexts.sort();
    contexts.dedup();

    eprintln!("\ndetection by context (positives only):");
    for context in &contexts {
        let group: Vec<&Case> = cases
            .iter()
            .filter(|c| c.context == *context && c.expected == Expected::Injection)
            .collect();
        if group.is_empty() {
            continue;
        }
        let hit = group.iter().filter(|c| detected(&scan(&engine, c))).count();
        eprintln!("  {:<24} {hit}/{}", context, group.len());
    }

    eprintln!("\ndetection by difficulty (positives only):");
    for difficulty in ["easy", "medium", "hard"] {
        let group: Vec<&Case> = cases
            .iter()
            .filter(|c| c.difficulty == difficulty && c.expected == Expected::Injection)
            .collect();
        if group.is_empty() {
            continue;
        }
        let hit = group.iter().filter(|c| detected(&scan(&engine, c))).count();
        eprintln!("  {:<24} {hit}/{}", difficulty, group.len());
    }

    let negatives = cases.iter().filter(|c| c.is_benign()).count();
    eprintln!("\nbenign corpus: {negatives}/200 toward the SC-003 minimum\n");
}
