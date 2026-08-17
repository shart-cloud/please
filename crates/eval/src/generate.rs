//! The carrier x payload x position generator, with span-level ground truth.
//!
//! `docs/research/indirect-structure.md` §5 states the bottleneck this exists to remove, and it is not
//! sample size: *"Every hypothesis in §2 is a **span** hypothesis. Every public corpus gives a
//! **document** label. That mismatch, not the size of the corpus, is what makes structural iteration
//! slow: you cannot measure 'did the detector localise the injected span' against data that only says
//! 'this document contains one somewhere'."*
//!
//! Inserting the payload ourselves fixes that, and three properties follow that nothing downloadable
//! provides: ground truth at a known byte offset, independent ablation of position against carrier, and
//! a matched negative per positive. Generated text is also ours, so unlike the 41 upstream sources it
//! can be committed.
//!
//! # Determinism
//!
//! No RNG, no clock, no hash-derived ordering. The cross-product is enumerated in the order the corpus
//! files declare, ids are `carrier:payload:position`, and re-running with unchanged inputs produces a
//! byte-identical `corpus/generated.jsonl` — which `--check` asserts and CI enforces. That is what makes
//! a committed derived artifact safe: a diff in the file means somebody changed an input, never that the
//! generator wandered.
//!
//! # What it deliberately does not do
//!
//! It does not vary the payload text per insertion, does not paraphrase, and does not attempt to make
//! the seam invisible. `document-map.md` §5.1 names the risk that *"the generator's seams are our
//! seams"* — we would be generating the discontinuities we already believe in — and the mitigation is
//! measurement against held-out hand-written fixtures, not a cleverer generator. A generator tuned until
//! its output fooled our own detectors would be optimising the wrong direction.

use serde::Deserialize;
use std::collections::BTreeSet;

use crate::rows::Row;
use crate::Result;

/// The anchor marker a carrier uses to declare an insertion point.
const ANCHOR_OPEN: &str = "@@ANCHOR:";
const ANCHOR_CLOSE: &str = "@@";

#[derive(Debug, Deserialize)]
struct Carriers {
    #[serde(rename = "carrier")]
    carriers: Vec<Carrier>,
}

#[derive(Debug, Deserialize)]
struct Carrier {
    id: String,
    file: String,
    context: String,
    split: String,
    #[allow(dead_code)]
    // Review material: read by a human deciding whether the corpus is balanced.
    notes: String,
}

#[derive(Debug, Deserialize)]
struct Payloads {
    #[serde(rename = "payload")]
    payloads: Vec<Payload>,
}

#[derive(Debug, Deserialize)]
struct Payload {
    id: String,
    intent: String,
    text: String,
    #[allow(dead_code)]
    notes: String,
}

#[derive(Debug, Deserialize)]
struct Positions {
    #[serde(rename = "position")]
    positions: Vec<Position>,
}

#[derive(Debug, Deserialize)]
struct Position {
    id: String,
    template: String,
    escape: Escape,
    #[allow(dead_code)]
    notes: String,
}

/// What the syntax around an insertion point will tolerate.
///
/// A property of the position, not of the payload. The same payload text has to be able to appear in a
/// table cell and in a JSON field without either document becoming malformed — and a malformed carrier
/// is a carrier the scanner reads differently, which would confound every comparison across positions.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Escape {
    None,
    SingleLine,
    TableCell,
    JsonString,
}

impl Escape {
    fn apply(self, text: &str) -> String {
        match self {
            Escape::None => text.to_string(),
            Escape::SingleLine => text.replace(['\n', '\r'], " "),
            Escape::TableCell => text.replace(['\n', '\r'], " ").replace('|', "/"),
            Escape::JsonString => {
                // serde_json quotes and escapes; the surrounding carrier already supplies the quotes.
                let quoted = serde_json::to_string(text).unwrap_or_else(|_| format!("{text:?}"));
                quoted.trim_matches('"').to_string()
            }
        }
    }
}

/// One anchor found in a carrier.
#[derive(Debug, Clone)]
struct Anchor {
    position: String,
    default: String,
    /// Byte range of the whole `@@ANCHOR:…@@` marker in the carrier source.
    start: usize,
    end: usize,
}

/// What a generation run produced, including what it could not.
pub struct Generated {
    pub rows: Vec<Row>,
    pub positives: usize,
    pub negatives: usize,
    /// `(carrier, position)` pairs a carrier does not declare an anchor for.
    ///
    /// Reported rather than silently absent. Positions are not universal — a table-cell insertion needs
    /// a table and a json-field insertion needs JSON — so the cross-product is over applicable pairs
    /// only, and the real row count is below `document-map.md` §3's 2,160 upper bound. A silently
    /// smaller corpus reads as full coverage, which is the failure mode this list exists to prevent.
    pub skipped: Vec<(String, String)>,
}

/// Build every row from the committed corpus inputs.
pub fn build() -> Result<Generated> {
    let carriers: Carriers = read_toml("corpus/carriers.toml")?;
    let payloads: Payloads = read_toml("corpus/payloads.toml")?;
    let positions: Positions = read_toml("corpus/positions.toml")?;

    let known: BTreeSet<&str> = positions.positions.iter().map(|p| p.id.as_str()).collect();
    let mut rows = Vec::new();
    let mut skipped = Vec::new();
    let (mut positives, mut negatives) = (0usize, 0usize);

    for carrier in &carriers.carriers {
        // Carrier paths in `carriers.toml` are relative to `corpus/`, where they read as what they are.
        let path = crate::crate_path("corpus").join(&carrier.file);
        let source = std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "carrier `{}`: cannot read {}: {e}",
                carrier.id,
                path.display()
            )
        })?;
        let anchors = parse_anchors(&carrier.id, &source)?;

        for anchor in &anchors {
            if !known.contains(anchor.position.as_str()) {
                return Err(format!(
                    "carrier `{}` declares anchor `{}`, which is not a position in \
                     corpus/positions.toml. An anchor nobody can target is a silently unused insertion \
                     point",
                    carrier.id, anchor.position
                )
                .into());
            }
        }

        // The matched negative: every anchor replaced by its default. Emitted first so a reader of the
        // JSONL meets the carrier before its variants.
        let (clean_text, _) = render(&source, &anchors, None);
        let mut negative = Row::new(
            format!("{}:none", carrier.id),
            carrier.id.clone(),
            clean_text,
        );
        negative.context = Some(carrier.context.clone());
        negative.split = Some(carrier.split.clone());
        negative.carrier_id = Some(carrier.id.clone());
        negative.difficulty = Some("matched".to_string());
        rows.push(negative);
        negatives += 1;

        for position in &positions.positions {
            let Some(anchor) = anchors.iter().find(|a| a.position == position.id) else {
                skipped.push((carrier.id.clone(), position.id.clone()));
                continue;
            };
            for payload in &payloads.payloads {
                let rendered = position
                    .template
                    .replace("{payload}", &position.escape.apply(&payload.text));
                let (text, span) = render(&source, &anchors, Some((anchor, &rendered)));
                let span = span.ok_or_else(|| {
                    format!(
                        "carrier `{}`, position `{}`: the payload was not placed. This is a generator \
                         defect, not a corpus one",
                        carrier.id, position.id
                    )
                })?;

                // The span covers the RENDERED payload including whatever the template added, because
                // the template's newlines and list bullet are part of what was injected. A metric asking
                // "did a finding overlap the injection" must count a finding on the bullet.
                let mut row = Row::new(
                    format!("{}:{}:{}", carrier.id, payload.id, position.id),
                    carrier.id.clone(),
                    text,
                );
                row.context = Some(carrier.context.clone());
                row.split = Some(carrier.split.clone());
                row.carrier_id = Some(carrier.id.clone());
                row.payload_id = Some(payload.id.clone());
                row.position = Some(position.id.clone());
                row.injected_span = Some(span);
                // `intent` rides in `technique` so it reaches the per-stratum tables without a second
                // field on `Row` that only this corpus would populate. The report's technique table is
                // keyed on whatever is in there, and for generated rows the useful key is the intent.
                row.technique = Some(payload.intent.clone());
                rows.push(row);
                positives += 1;
            }
        }
    }

    Ok(Generated {
        rows,
        positives,
        negatives,
        skipped,
    })
}

fn read_toml<T: for<'de> Deserialize<'de>>(relative: &str) -> Result<T> {
    let path = crate::crate_path(relative);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()).into())
}

/// Find every `@@ANCHOR:position@@` or `@@ANCHOR:position|default@@` in a carrier.
fn parse_anchors(carrier_id: &str, source: &str) -> Result<Vec<Anchor>> {
    let mut anchors = Vec::new();
    let mut cursor = 0usize;
    while let Some(offset) = source[cursor..].find(ANCHOR_OPEN) {
        let start = cursor + offset;
        let body_start = start + ANCHOR_OPEN.len();
        let end_offset = source[body_start..].find(ANCHOR_CLOSE).ok_or_else(|| {
            format!(
                "carrier `{carrier_id}`: an anchor opened at byte {start} is never closed with `{ANCHOR_CLOSE}`"
            )
        })?;
        let body = &source[body_start..body_start + end_offset];
        let (position, default) = match body.split_once('|') {
            Some((position, default)) => (position.to_string(), default.to_string()),
            None => (body.to_string(), String::new()),
        };
        if position.trim().is_empty() {
            return Err(format!(
                "carrier `{carrier_id}`: an anchor at byte {start} names no position"
            )
            .into());
        }
        anchors.push(Anchor {
            position,
            default,
            start,
            end: body_start + end_offset + ANCHOR_CLOSE.len(),
        });
        cursor = body_start + end_offset + ANCHOR_CLOSE.len();
    }

    let mut seen = BTreeSet::new();
    for anchor in &anchors {
        if !seen.insert(anchor.position.as_str()) {
            return Err(format!(
                "carrier `{carrier_id}`: position `{}` is anchored twice. Which one a payload would go \
                 in is then a property of iteration order, and the span label would be about the other",
                anchor.position
            )
            .into());
        }
    }
    Ok(anchors)
}

/// Resolve every anchor, optionally placing a payload at one of them.
///
/// Returns the document and, when a payload was placed, its byte span in that document. Offsets are
/// computed while building the output rather than mapped back afterwards, which is the only way the span
/// stays correct: replacing a marker with text of a different length moves everything after it, and every
/// other anchor in the file is also being replaced by something of a different length again.
fn render(
    source: &str,
    anchors: &[Anchor],
    target: Option<(&Anchor, &str)>,
) -> (String, Option<(usize, usize)>) {
    let mut out = String::with_capacity(source.len() + 256);
    let mut span = None;
    let mut cursor = 0usize;

    for anchor in anchors {
        out.push_str(&source[cursor..anchor.start]);
        let is_target = target.is_some_and(|(t, _)| t.start == anchor.start);
        let replacement = if is_target {
            target.expect("checked").1.to_string()
        } else {
            anchor.default.clone()
        };

        if replacement.is_empty() {
            // An empty replacement on a line that held nothing else would leave a blank line the
            // carrier's author did not write. Blank lines are not cosmetic here: `document-map.md` §1.1
            // makes a run of them a segment in its own right, so a stray one would be a structural
            // feature invented by the generator. Drop the line's trailing newline with it.
            if line_holds_only_this_anchor(source, anchor) {
                trim_trailing_line_start(&mut out);
                cursor = skip_to_next_line(source, anchor.end);
                continue;
            }
            // An inline anchor at the end of a line leaves the space that preceded it. Trailing
            // whitespace is a real difference between the matched negative and its positives, and
            // `mean_line_len` in `document-map.md` §1.2 is measured in bytes — so a stray space is a
            // measurable artifact of the generator rather than of the document. Remove it.
            if source[anchor.end..].starts_with('\n') {
                while out.ends_with(' ') || out.ends_with('\t') {
                    out.pop();
                }
            }
        } else if is_target {
            let start = out.len();
            out.push_str(&replacement);
            span = Some((start, out.len()));
            cursor = anchor.end;
            continue;
        }

        out.push_str(&replacement);
        cursor = anchor.end;
    }
    out.push_str(&source[cursor..]);
    (out, span)
}

/// Whether the carrier line containing this anchor contains nothing else but whitespace.
fn line_holds_only_this_anchor(source: &str, anchor: &Anchor) -> bool {
    let line_start = source[..anchor.start]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let line_end = source[anchor.end..]
        .find('\n')
        .map(|i| anchor.end + i)
        .unwrap_or(source.len());
    source[line_start..anchor.start].trim().is_empty()
        && source[anchor.end..line_end].trim().is_empty()
}

/// Remove the partial line just written, back to the last newline.
fn trim_trailing_line_start(out: &mut String) {
    let keep = out.rfind('\n').map(|i| i + 1).unwrap_or(0);
    out.truncate(keep);
}

/// Advance past the rest of the line, including its newline.
fn skip_to_next_line(source: &str, from: usize) -> usize {
    match source[from..].find('\n') {
        Some(offset) => from + offset + 1,
        None => source.len(),
    }
}

/// Path to the committed output.
pub fn output_path() -> std::path::PathBuf {
    crate::crate_path("corpus/generated.jsonl")
}

/// Serialise rows to the committed JSONL form.
pub fn serialise(rows: &[Row]) -> Result<String> {
    let mut out = String::new();
    for row in rows {
        out.push_str(&serde_json::to_string(row)?);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_byte_identical_across_runs() {
        let first =
            serialise(&build().expect("the corpus must generate").rows).expect("serialises");
        let second =
            serialise(&build().expect("the corpus must generate").rows).expect("serialises");
        assert_eq!(
            first, second,
            "generation is not deterministic, so a committed corpus could not be trusted"
        );
    }

    /// The span label is the whole point of the corpus. If it does not name the payload's actual bytes,
    /// every localisation metric computed from this file is measuring nothing.
    #[test]
    fn every_span_label_names_the_payload_it_claims() {
        let generated = build().expect("the corpus must generate");
        let payloads: Payloads = read_toml("corpus/payloads.toml").expect("payloads load");

        let mut checked = 0usize;
        for row in &generated.rows {
            let Some((start, end)) = row.injected_span else {
                continue;
            };
            assert!(
                end <= row.text.len(),
                "{}: span {start}..{end} is outside a {}-byte document",
                row.id,
                row.text.len()
            );
            let excerpt = &row.text[start..end];
            let payload_id = row
                .payload_id
                .as_deref()
                .expect("a positive names its payload");
            let payload = payloads
                .payloads
                .iter()
                .find(|p| p.id == payload_id)
                .expect("the payload must exist");

            // Compared on the first line only: a single-line escape collapses newlines and the
            // json-string escape rewrites quotes, so the rendered form is legitimately not the source
            // form. What must hold is that the span covers the payload and not its neighbours.
            let first_line = payload.text.lines().next().unwrap_or_default();
            let needle: String = first_line.chars().take(24).collect();
            assert!(
                excerpt.contains(needle.trim()) || excerpt.contains(&escape_probe(&needle)),
                "{}: span excerpt {excerpt:?} does not contain the payload {needle:?}",
                row.id
            );
            checked += 1;
        }
        assert!(checked > 500, "only {checked} positives generated");
    }

    fn escape_probe(text: &str) -> String {
        serde_json::to_string(text)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string()
    }

    /// A matched negative must contain no trace of the marker syntax, or the "identical except the
    /// payload" claim is false and the negative is measuring the generator.
    #[test]
    fn no_row_leaks_the_anchor_syntax() {
        let generated = build().expect("the corpus must generate");
        for row in &generated.rows {
            assert!(
                !row.text.contains(ANCHOR_OPEN),
                "{}: an unresolved anchor survived into the corpus",
                row.id
            );
        }
    }

    #[test]
    fn every_carrier_yields_exactly_one_matched_negative() {
        let generated = build().expect("the corpus must generate");
        let carriers: Carriers = read_toml("corpus/carriers.toml").expect("carriers load");
        assert_eq!(
            generated.negatives,
            carriers.carriers.len(),
            "one matched negative per carrier, no more and no fewer"
        );
        for carrier in &carriers.carriers {
            assert!(
                generated
                    .rows
                    .iter()
                    .any(|r| r.id == format!("{}:none", carrier.id)),
                "carrier `{}` produced no matched negative",
                carrier.id
            );
        }
    }

    /// Both splits must carry several formats. A split where all the email lives on one side would make
    /// the held-out comparison a comparison of formats rather than of splits.
    #[test]
    fn both_splits_cover_several_formats() {
        let carriers: Carriers = read_toml("corpus/carriers.toml").expect("carriers load");
        for split in ["calibration", "report"] {
            let contexts: BTreeSet<&str> = carriers
                .carriers
                .iter()
                .filter(|c| c.split == split)
                .map(|c| c.context.as_str())
                .collect();
            assert!(
                contexts.len() >= 3,
                "split `{split}` covers only {} context(s); a threshold chosen on it would be a \
                 threshold about those formats",
                contexts.len()
            );
        }
    }

    #[test]
    fn all_nine_positions_are_reachable_somewhere() {
        let generated = build().expect("the corpus must generate");
        let positions: Positions = read_toml("corpus/positions.toml").expect("positions load");
        for position in &positions.positions {
            assert!(
                generated
                    .rows
                    .iter()
                    .any(|r| r.position.as_deref() == Some(position.id.as_str())),
                "no carrier anchors position `{}`, so it is defined and never measured",
                position.id
            );
        }
    }
}
