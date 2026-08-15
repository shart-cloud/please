//! Human-readable output (FR-027).
//!
//! Written to answer SC-001: a reader states what was found and where, from this output alone. Every field
//! shown is one a reader needs to act — rule identity, byte span, excerpt, description — and the excerpt is
//! already neutralised before it reaches here, so a payload cannot forge this report's own structure.
//!
//! The ordering matters and is the same discipline throughout: **sanitise the payload, then style it.**
//! Never the reverse.

use please_core::verdict::{Outcome, RiskLevel, Verdict};

/// Render one verdict.
pub fn verdict(out: &mut String, v: &Verdict, explain: bool) {
    let name = v
        .target()
        .name
        .clone()
        .unwrap_or_else(|| "<stdin>".to_string());

    match v.outcome() {
        Outcome::Clean => {
            out.push_str(&format!("{name} — clean\n"));
            return;
        }
        Outcome::Inconclusive => {
            out.push_str(&format!("{name} — INCONCLUSIVE\n"));
        }
        Outcome::RiskFound => {
            out.push_str(&format!(
                "{name} — RISK FOUND ({}, score {})\n",
                band(v.risk()),
                v.score()
            ));
        }
    }

    for reason in v.reasons() {
        out.push_str(&format!(
            "\n  {:<6} {:<34} bytes {}–{}\n",
            severity_label(reason.severity()),
            reason.rule_id(),
            reason.span().start,
            reason.span().end
        ));
        out.push_str(&format!("         {:?}\n", reason.matched()));
        if explain {
            out.push_str(&format!("         {}\n", reason.description()));
            if !reason.chain().is_empty() {
                let steps: Vec<String> = reason
                    .chain()
                    .iter()
                    .map(|t| format!("{:?} (depth {})", t.kind, t.depth))
                    .collect();
                out.push_str(&format!("         via: {}\n", steps.join(" → ")));
            }
        }
    }

    if v.reasons_truncated() {
        out.push_str("\n  (more reasons were found than the limit reports)\n");
    }

    // Coverage gaps are printed for every non-clean verdict, not only inconclusive ones. A risk-found
    // verdict that also hit a bound may not have found everything, and the reader needs to know that the
    // list above might be partial.
    out.push_str("\n  unexamined: ");
    if v.incomplete().is_empty() {
        out.push_str("none");
    } else {
        let gaps: Vec<String> = v
            .incomplete()
            .iter()
            .map(|i| match i.detail() {
                Some(d) => format!("{} ({d})", i.cause().as_str()),
                None => i.cause().as_str().to_string(),
            })
            .collect();
        out.push_str(&gaps.join("; "));
    }

    out.push_str(&format!(
        "\n  rules: {} v{} ({})\n",
        v.ruleset().name,
        v.ruleset().version,
        v.ruleset().digest
    ));
}

/// Summary line for a multi-target run.
pub fn summary(out: &mut String, verdicts: &[Verdict]) {
    if verdicts.len() < 2 {
        return;
    }
    let risk = verdicts
        .iter()
        .filter(|v| v.outcome() == Outcome::RiskFound)
        .count();
    let inconclusive = verdicts
        .iter()
        .filter(|v| v.outcome() == Outcome::Inconclusive)
        .count();
    let clean = verdicts.len() - risk - inconclusive;
    out.push_str(&format!(
        "\n{} target(s): {clean} clean, {risk} with findings, {inconclusive} inconclusive\n",
        verdicts.len()
    ));
}

fn band(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::None => "none",
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

/// Short severity label, so a reader can scan a column rather than compare numbers.
fn severity_label(severity: u8) -> &'static str {
    match severity {
        0..=19 => "info",
        20..=44 => "low",
        45..=69 => "med",
        70..=89 => "high",
        _ => "crit",
    }
}
