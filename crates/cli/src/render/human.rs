//! Human-readable output (FR-027).
//!
//! Moved from `render.rs` to `render/human.rs` at 001 T070, when `--format json` gave it a sibling. The
//! contents are unchanged apart from two duplications this move let go of: a private `band()` that
//! respelled `RiskLevel`, and hardcoded `"confirmed"`/`"demoted"` strings. Both now call the `as_str()`
//! the core type carries, so the two renderers cannot disagree about what a value is called.
//!
//! Written to answer SC-001: a reader states what was found and where, from this output alone. Every field
//! shown is one a reader needs to act — rule identity, byte span, excerpt, description — and the excerpt is
//! already neutralised before it reaches here, so a payload cannot forge this report's own structure.
//!
//! The ordering matters and is the same discipline throughout: **sanitise the payload, then style it.**
//! Never the reverse.

use please_core::verdict::{Outcome, QuotingContext, SuppressedBy, Verdict};

/// Render one verdict.
fn verdict(out: &mut String, v: &Verdict, explain: bool) {
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
                judgement(out, v);
            }
            // A clean verdict still has attribution to report when a judge produced it — this is the
            // benign-tool-001 case, and "clean because a model said so" is exactly the claim a reader
            // needs to be able to attribute.
            judge_attribution(out, v);
            return;
        }
        Outcome::Inconclusive => {
            out.push_str(&format!("{name} — INCONCLUSIVE\n"));
        }
        Outcome::RiskFound => {
            out.push_str(&format!(
                "{name} — RISK FOUND ({}, score {})\n",
                v.risk().as_str(),
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
        judgement(out, v);
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
    judge_attribution(out, v);
}

/// The judgement tier's identity, beside the rule set's (FR-416, T041).
///
/// Always shown when a judge ran, not only under `--explain`. The rule-set digest is on every verdict for
/// the same reason: a verdict is evidence, and evidence that cannot say what produced it is worth less
/// later than it seems now (001 SC-012). A model id and a prompt version are the same claim one level up —
/// **a verdict judged by one model is not evidence about another.**
fn judge_attribution(out: &mut String, v: &Verdict) {
    let Some(report) = v.judge() else {
        return;
    };
    out.push_str(&format!(
        "  judge: {} (prompt {})\n",
        report.model(),
        report.prompt_version()
    ));
}

/// What the judge answered, and which answer drove each judgement (US5, T040).
///
/// Under `--explain` only, and the reason is the same one that puts the suppressed list there: default
/// output is what a hook prints on a denial, and a table of feature answers would bury the finding.
///
/// **002 removed a two-run diff from the false-positive workflow. This must not put one back.** An engineer
/// disagreeing with a judged outcome should be able to see which observation the judge acted on and what it
/// said, from one verdict — not by rerunning with `--no-judge` and diffing. That command exists to settle
/// disputes about whether the judge is *right*, not to discover what it *did*.
fn judgement(out: &mut String, v: &Verdict) {
    let Some(report) = v.judge() else {
        return;
    };

    let features = report.features();
    out.push_str("\n  judged:\n");
    out.push_str(&format!(
        "    document   addressed to {}, imperatives {}, framing {}, purpose explains content {}\n",
        features.addressed_to.as_str(),
        features.imperative_source.as_str(),
        features.framing.as_str(),
        features.stated_purpose_explains_content.as_str(),
    ));

    for span in report.judgements() {
        // `relation` first, because it is the field the decision usually turns on (plan D4a) and a reader
        // scanning this column wants the deciding answer where their eye lands.
        out.push_str(&format!(
            "    span {:<3}   {:<10}  relation {:<38} role {}\n",
            span.reason_index,
            span.judgement.as_str(),
            span.relation.as_str(),
            span.role.as_str(),
        ));
    }
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

    // Feature 004: the heading and the advice below both used to say "quoting" unconditionally, which was
    // true while quoting was the only thing that could suppress. It now reads wrong on exactly the case the
    // judgement tier exists for — benign-tool-001 renders four judge demotions under a heading claiming
    // they were quoted, and the remedy it offers does not work on them.
    let by_judge = v
        .suppressed()
        .iter()
        .filter(|r| r.suppressed_by() == Some(SuppressedBy::Judge))
        .count();
    let by_quoting = v.suppressed().len() - by_judge;
    let cause = match (by_quoting, by_judge) {
        (0, _) => "suppressed by the judge",
        (_, 0) => "suppressed by quoting",
        _ => "suppressed",
    };
    out.push_str(&format!(
        "\n  {cause} ({} not reported):\n",
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
    // Name the flag that actually reverses what happened here. Offering `--no-suppress-in-quotes` for a
    // judge demotion sends the reader to a flag that will change nothing, and the second run they do after
    // that is the two-run diff 002 spent a phase removing.
    let remedy = match (by_quoting, by_judge) {
        (0, _) => "--no-judge",
        (_, 0) => "--no-suppress-in-quotes",
        _ => "--no-suppress-in-quotes and/or --no-judge",
    };
    out.push_str(&format!(
        "    Re-run with {remedy} to report these. Suppressed content WAS examined; this is a \
         reporting choice, not a gap in coverage.\n",
    ));
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
///
/// Takes counts rather than the verdicts, because nothing keeps the verdicts any more: they are rendered
/// and dropped one at a time so peak memory tracks the largest single target rather than the corpus. Three
/// running integers are the whole of what this line ever needed from them.
fn summary(out: &mut String, clean: usize, risk: usize, inconclusive: usize) {
    let total = clean + risk + inconclusive;
    if total < 2 {
        return;
    }
    out.push_str(&format!(
        "\n{total} target(s): {clean} clean, {risk} with findings, {inconclusive} inconclusive\n",
    ));
}

/// Human output, one verdict at a time.
///
/// The counts are the only state carried across targets, and `scratch` is one reused allocation rather
/// than one per verdict — [`verdict`] still writes into a `String`, so this is where that string lives
/// now instead of growing without bound in `main`.
pub struct Emitter {
    explain: bool,
    scratch: String,
    clean: usize,
    risk: usize,
    inconclusive: usize,
}

impl Emitter {
    pub fn new(explain: bool) -> Self {
        Self {
            explain,
            scratch: String::new(),
            clean: 0,
            risk: 0,
            inconclusive: 0,
        }
    }

    pub fn verdict<W: std::io::Write>(&mut self, w: &mut W, v: &Verdict) -> std::io::Result<()> {
        match v.outcome() {
            Outcome::Clean => self.clean += 1,
            Outcome::RiskFound => self.risk += 1,
            Outcome::Inconclusive => self.inconclusive += 1,
        }
        self.scratch.clear();
        verdict(&mut self.scratch, v, self.explain);
        w.write_all(self.scratch.as_bytes())
    }

    pub fn finish<W: std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.scratch.clear();
        summary(&mut self.scratch, self.clean, self.risk, self.inconclusive);
        w.write_all(self.scratch.as_bytes())
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
