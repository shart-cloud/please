//! Human-readable output (FR-027).
//!
//! Written to answer SC-001: a reader states what was found and where, from this output alone. Every field
//! shown is one a reader needs to act — rule identity, byte span, excerpt, description — and the excerpt is
//! already neutralised before it reaches here, so a payload cannot forge this report's own structure.
//!
//! The ordering matters and is the same discipline throughout: **sanitise the payload, then style it.**
//! Never the reverse.

use please_core::verdict::{Outcome, QuotingContext, RiskLevel, SuppressedBy, Verdict};

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
            // Not an unconditional return. A clean verdict is exactly where the suppressed list matters
            // most: security prose whose every payload was correctly hidden reports clean, and "what did the
            // heuristic do here?" is precisely the question its author is asking (SC-110). Returning early
            // would make the answer unavailable in the one case it is wanted.
            if explain {
                suppressed(out, v);
            }
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
            // Acceptance scenario 3: reported *because* suppression is off, and annotated with what would
            // otherwise have hidden it. This is how a reader tells which findings the heuristic disagrees
            // with them about without running the scan twice.
            if let Some(context) = reason.suppressed_by() {
                out.push_str(&format!(
                    "         would be suppressed: {}\n",
                    context_label(Some(context))
                ));
            }
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

    if explain {
        suppressed(out, v);
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

/// What quoting suppression hid, under `--explain` (T069, SC-110).
///
/// Behind `--explain` rather than always shown, because the default output is what a hook prints on a denial
/// and a list of things that were deliberately *not* acted on would bury the finding that was. Under
/// `--explain` the reader has asked why, and this is most of the answer.
///
/// Excerpts here were neutralised by finalization on the way in, like every other excerpt — the same
/// discipline as the rest of this module: sanitise the payload, then style it.
fn suppressed(out: &mut String, v: &Verdict) {
    if v.suppressed().is_empty() {
        return;
    }

    out.push_str(&format!(
        "\n  suppressed by quoting ({} not reported):\n",
        v.suppressed().len()
    ));
    for reason in v.suppressed() {
        out.push_str(&format!(
            "    {:<34} bytes {}–{}  [{}]\n",
            reason.rule_id(),
            reason.span().start,
            reason.span().end,
            context_label(reason.suppressed_by()),
        ));
        out.push_str(&format!("         {:?}\n", reason.matched()));
    }
    if v.suppressions_truncated() {
        out.push_str("    (more were suppressed than the limit reports)\n");
    }
    out.push_str(
        "    Re-run with --no-suppress-in-quotes to report these. Suppressed content WAS examined; \
         this is a reporting choice, not a gap in coverage.\n",
    );
}

/// Why an observation was suppressed, in the words a reader would use.
///
/// `Debug` on the enum would print `FencedCode`, which is a Rust identifier rather than an explanation. This
/// is output a person reads while deciding whether the tool is wrong.
fn context_label(context: Option<SuppressedBy>) -> &'static str {
    match context {
        Some(SuppressedBy::Quoting(QuotingContext::FencedCode)) => "inside a fenced code block",
        Some(SuppressedBy::Quoting(QuotingContext::InlineCode)) => "inside inline code",
        Some(SuppressedBy::Quoting(QuotingContext::BlockQuote)) => "inside a block quote",
        Some(SuppressedBy::Quoting(QuotingContext::QuotedString)) => "inside a quoted string",
        Some(SuppressedBy::Quoting(QuotingContext::AttributiveMarker)) => {
            "after a phrase introducing an example"
        }
        // Feature 004. Deliberately says who rather than where: a judge suppression is not a property of
        // the document, it is an external opinion about it, and a reader deciding whether to trust it needs
        // to know which of the two they are looking at. `--explain` prints the feature answers underneath.
        Some(SuppressedBy::Judge) => "judged to describe an instruction rather than issue one",
        // Both enums are `non_exhaustive`, so a variant added later lands here rather than failing to
        // compile. Naming it honestly beats guessing.
        Some(_) => "inside a quoting context",
        None => "unknown context",
    }
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
