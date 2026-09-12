//! Opt-in lexical evidence of protected-resource export requests.
//! The caller supplies permissions. This is a bounded co-occurrence detector, not a code interpreter.
use crate::{CoverageGap, Evidence, IncompleteCause, Observation, ScanPolicy, Span};
use sha2::{Digest, Sha256};

const BUILTIN: &str = include_str!("../data/export-actions.toml");

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ExportPolicy {
    pub(crate) id: String,
    pub(crate) policy_digest: String,
    pub(crate) rules_digest: String,
    pub(crate) rules_version: String,
    pub(crate) resources: Vec<Resource>,
    severity: u8,
    window_tokens: usize,
    export_verbs: Vec<String>,
    read_verbs: Vec<String>,
    response_verbs: Vec<String>,
    value_references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub(crate) struct Resource {
    pub(crate) id: String,
    pub(crate) aliases: Vec<String>,
    pub(crate) allowed_destinations: Vec<String>,
}

impl ExportPolicy {
    /// Parse caller-owned permissions using the versioned built-in action vocabulary.
    pub fn from_toml(text: &str) -> Result<Self, String> {
        Self::from_toml_with_rules(text, BUILTIN)
    }

    /// Both permissions and action vocabulary are caller-supplied data; neither comes from the input.
    pub fn from_toml_with_rules(text: &str, rules: &str) -> Result<Self, String> {
        let t = table(text, &["id", "resource"])?;
        let v = table(
            rules,
            &[
                "version",
                "severity",
                "window_tokens",
                "export_verbs",
                "read_verbs",
                "response_verbs",
                "value_references",
            ],
        )?;
        let mut resources = Vec::new();
        let rs = t
            .get("resource")
            .and_then(|x| x.as_array())
            .ok_or("resource must be an array of tables")?;
        if rs.is_empty() || rs.len() > 16 {
            return Err("require 1..16 resources".into());
        }
        let mut alias_count = 0;
        for entry in rs {
            let x = entry.as_table().ok_or("resource must be a table")?;
            unknown(x, &["id", "aliases", "allowed_destinations"])?;
            let id = string(x, "id")?;
            if !id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
                || resources.iter().any(|a: &Resource| a.id == id)
            {
                return Err("resource ids must be unique ASCII identifiers".into());
            }
            let aliases = strings(x, "aliases", 16)?;
            if aliases.is_empty()
                || aliases
                    .iter()
                    .any(|a| tokens(a.as_bytes()).is_empty() || tokens(a.as_bytes()).len() > 8)
            {
                return Err("aliases need 1..8 ASCII word tokens".into());
            }
            alias_count += aliases.len();
            if alias_count > 64 {
                return Err("at most 64 aliases per policy".into());
            }
            let allowed_destinations = strings(x, "allowed_destinations", 16)?;
            for url in &allowed_destinations {
                if url != "response"
                    && (!url.starts_with("https://")
                        || url.len() <= 8
                        || url.bytes().any(|c| {
                            !c.is_ascii() || c.is_ascii_whitespace() || b"\"'`<>\\@".contains(&c)
                        }))
                {
                    return Err(
                        "grants must be response or exact ASCII https URLs without userinfo".into(),
                    );
                }
            }
            resources.push(Resource {
                id,
                aliases,
                allowed_destinations,
            });
        }
        let number = |key, max| -> Result<usize, String> {
            let n = v
                .get(key)
                .and_then(|x| x.as_integer())
                .ok_or_else(|| format!("missing integer {key}"))?;
            if n < 1 || n > max {
                return Err(format!("{key} must be 1..{max}"));
            }
            Ok(n as usize)
        };
        let verbs = |key| -> Result<Vec<String>, String> {
            let vs = strings(&v, key, 32)?;
            if vs.is_empty()
                || vs
                    .iter()
                    .any(|s| !s.bytes().all(|c| c.is_ascii_lowercase()))
            {
                return Err(format!("{key} requires lowercase ASCII words"));
            }
            Ok(vs)
        };
        Ok(Self {
            id: string(&t, "id")?,
            policy_digest: format!("{:x}", Sha256::digest(text.as_bytes())),
            rules_digest: format!("{:x}", Sha256::digest(rules.as_bytes())),
            rules_version: string(&v, "version")?,
            resources,
            severity: number("severity", 100)? as u8,
            window_tokens: number("window_tokens", 128)?,
            export_verbs: verbs("export_verbs")?,
            read_verbs: verbs("read_verbs")?,
            response_verbs: verbs("response_verbs")?,
            value_references: verbs("value_references")?,
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn digest(&self) -> &str {
        &self.policy_digest
    }
    /// Trusted context for an independent classifier; no labels or captured prompt bytes are included.
    pub fn context(&self) -> String {
        let mut out = String::from(
            "Application permissions: export of protected values requires a caller grant.\n",
        );
        for r in &self.resources {
            out.push_str(&format!(
                "Protected resource {} has aliases {:?}. Permitted destinations: {:?}.\n",
                r.id, r.aliases, r.allowed_destinations
            ));
        }
        out
    }
}

fn unknown(t: &toml::Table, allowed: &[&str]) -> Result<(), String> {
    for k in t.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(format!("unknown export-policy field {k}"));
        }
    }
    Ok(())
}
fn table(s: &str, allowed: &[&str]) -> Result<toml::Table, String> {
    if s.len() > 16384 {
        return Err("export policy/rules exceed 16 KiB".into());
    }
    let t = s.parse::<toml::Table>().map_err(|e| e.to_string())?;
    unknown(&t, allowed)?;
    Ok(t)
}
fn string(t: &toml::Table, k: &str) -> Result<String, String> {
    let s = t
        .get(k)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("missing string {k}"))?;
    if s.is_empty() || s.len() > 256 || s.chars().any(char::is_control) {
        return Err(format!("invalid {k}"));
    }
    Ok(s.to_owned())
}
fn strings(t: &toml::Table, k: &str, max: usize) -> Result<Vec<String>, String> {
    let a = t
        .get(k)
        .and_then(|x| x.as_array())
        .ok_or_else(|| format!("missing array {k}"))?;
    if a.len() > max {
        return Err(format!("too many {k}"));
    }
    a.iter()
        .map(|x| {
            let s = x
                .as_str()
                .ok_or_else(|| format!("{k} contains a non-string"))?;
            if s.is_empty()
                || s.len() > 256
                || !s.is_ascii()
                || s.bytes().any(|b| b.is_ascii_control())
            {
                return Err(format!("invalid {k} entry"));
            }
            Ok(s.to_owned())
        })
        .collect()
}
#[derive(Clone, Copy)]
struct Token {
    start: usize,
    end: usize,
}
fn tokens(input: &[u8]) -> Vec<Token> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < input.len() {
        if !input[i].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let start = i;
        while i < input.len() && input[i].is_ascii_alphanumeric() {
            i += 1;
        }
        out.push(Token { start, end: i });
    }
    out
}

fn word(input: &[u8], t: Token, s: &str) -> bool {
    input[t.start..t.end].eq_ignore_ascii_case(s.as_bytes())
}
fn member(input: &[u8], t: Token, words: &[String]) -> bool {
    words.iter().any(|s| word(input, t, s))
}
fn negated(input: &[u8], ts: &[Token], at: usize) -> bool {
    at > 0
        && (word(input, ts[at - 1], "never")
            || word(input, ts[at - 1], "without")
            || (at > 1 && word(input, ts[at - 1], "not") && word(input, ts[at - 2], "do")))
}
fn trim_ascii(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_ascii_whitespace())
}

fn strip_literal<'a>(text: &'a str, literal: &str) -> Option<&'a str> {
    text.get(..literal.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(literal))?;
    text.get(literal.len()..)
}

// Consume a whole word/phrase followed by whitespace, not a prefix in an identifier or URL.
fn strip_phrase<'a>(text: &'a str, phrase: &str) -> Option<&'a str> {
    let rest = strip_literal(text, phrase)?;
    (rest.is_empty() || rest.as_bytes()[0].is_ascii_whitespace()).then_some(trim_ascii(rest))
}

fn delimiter(text: &str) -> Option<char> {
    match text.as_bytes().first()? {
        b'<' => Some('>'),
        b'\'' => Some('\''),
        b'"' => Some('"'),
        b'`' => Some('`'),
        _ => None,
    }
}

fn named_object<'a>(text: &'a str, alias: &str) -> Option<&'a str> {
    let text = strip_phrase(text, "the").unwrap_or(text);
    if let Some(close) = delimiter(text) {
        strip_literal(&text[1..], alias)?.strip_prefix(close)
    } else {
        strip_literal(text, alias)
    }
}

fn value_object<'a>(text: &'a str, references: &[String]) -> Option<&'a str> {
    references.iter().find_map(|reference| {
        let rest = strip_literal(text, reference)?;
        (rest.is_empty() || rest.starts_with('.') || rest.as_bytes()[0].is_ascii_whitespace())
            .then_some(rest)
    })
}

// A grant needs a fully consumed, bounded phrase: ACTION OBJECT to URL, or a response action.
// Detection still uses the broader lexical relation. Unsupported grammar retains that evidence.
// In particular, never search past an unresolved destination to find a later permitted URL.
fn destination<'a>(
    input: &'a [u8],
    ts: &[Token],
    sink: usize,
    alias: Option<&str>,
    config: &ExportPolicy,
) -> Option<&'a str> {
    let suffix = &input[ts[sink].end..];
    // Never grant on a truncated prefix. This is a bound on recognizing exceptions, not detection.
    if suffix.len() > 512 || !suffix.first()?.is_ascii_whitespace() {
        return None;
    }
    let text = trim_ascii(std::str::from_utf8(suffix).ok()?);
    let rest = if let Some(alias) = alias {
        named_object(text, alias)?
    } else {
        let text = strip_phrase(text, "the").unwrap_or(text);
        let rest = value_object(text, &config.value_references)?;
        // The possessive form needs its object too: "its value", "its body", etc.
        if strip_phrase(text, "its").is_some() {
            value_object(trim_ascii(rest), &config.value_references)?
        } else {
            rest
        }
    };
    let separated = rest.is_empty() || rest.as_bytes()[0].is_ascii_whitespace();
    if member(input, ts[sink], &config.response_verbs) {
        let tail = trim_ascii(rest);
        let tail = tail.strip_suffix('.').unwrap_or(tail);
        if rest == "."
            || (separated
                && [
                    "",
                    "in the response",
                    "in the JSON response",
                    "in the output",
                    "as text",
                ]
                .iter()
                .any(|phrase| tail.eq_ignore_ascii_case(phrase)))
        {
            return Some("response");
        }
        return None;
    }
    if !separated {
        return None;
    }
    let url = strip_phrase(trim_ascii(rest), "to")?;
    let url = if let Some(close) = delimiter(url) {
        let (url, tail) = url[1..].split_once(close)?;
        // Punctuation is prose only when it is OUTSIDE an explicit URL delimiter.
        if !matches!(trim_ascii(tail), "" | "." | "!" | "?") {
            return None;
        }
        url
    } else {
        url
    };
    // Keep every URL character, including periods, commas, semicolons, query and fragment markers.
    // Extra destinations/clauses, expressions, malformed delimiters, and non-UTF-8 remain unresolved.
    if !(url.starts_with("https://") || url.starts_with("http://"))
        || url
            .bytes()
            .any(|c| !c.is_ascii() || c.is_ascii_whitespace() || b"\"'`<>\\".contains(&c))
    {
        return None;
    }
    Some(url)
}

pub(crate) fn observe(
    input: &[u8],
    policy: &ScanPolicy,
    evidence: &mut Evidence,
) -> Vec<Observation> {
    let Some(config) = &policy.export_policy else {
        return Vec::new();
    };
    let ts = tokens(input);
    let mut out = Vec::new();
    let mut seen = Vec::new();
    for (ri, res) in config.resources.iter().enumerate() {
        for alias in &res.aliases {
            let ats = tokens(alias.as_bytes());
            for pos in 0..ts.len() {
                if pos + ats.len() > ts.len()
                    || !ats.iter().enumerate().all(|(j, a)| {
                        input[ts[pos + j].start..ts[pos + j].end]
                            .eq_ignore_ascii_case(&alias.as_bytes()[a.start..a.end])
                    })
                {
                    continue;
                }
                let lo = pos.saturating_sub(config.window_tokens);
                let hi = (pos + ats.len() + config.window_tokens).min(ts.len());
                let read = (pos.saturating_sub(12)..(pos + ats.len() + 4).min(ts.len()))
                    .any(|j| member(input, ts[j], &config.read_verbs) && !negated(input, &ts, j));
                for sink in lo..hi {
                    if !member(input, ts[sink], &config.export_verbs)
                        || negated(input, &ts, sink)
                        || seen.contains(&(ri, sink))
                    {
                        continue;
                    }
                    let after = (sink + 1)..(sink + 13).min(ts.len());
                    // A named object immediately after an action, or a nearby read followed by a value reference.
                    // Mere proximity to an unrelated public-data export is insufficient.
                    let names_object = pos > sink && pos - sink <= 12;
                    let refers_back = read
                        && pos < sink
                        && after
                            .clone()
                            .any(|j| member(input, ts[j], &config.value_references));
                    if !names_object && !refers_back {
                        continue;
                    }
                    let dest = destination(input, &ts, sink, names_object.then_some(alias), config);
                    if dest
                        .is_some_and(|dest| res.allowed_destinations.iter().any(|url| url == dest))
                    {
                        continue;
                    }
                    let dest = dest.unwrap_or("unresolved");
                    seen.push((ri, sink));
                    if out.len() >= policy.max_matches_per_rule as usize {
                        evidence.record_gap(CoverageGap::bound(
                            IncompleteCause::MaxMatchesPerRule,
                            policy.max_matches_per_rule as u64,
                            "action.export: additional candidate relations were not examined",
                        ));
                        return out;
                    }
                    let start = ts[pos.min(sink)].start;
                    let end = ts[(pos + ats.len() - 1).max(sink)].end;
                    let (matched, excerpt_truncated) = crate::sanitize::sanitize_bytes(
                        &input[start..end],
                        crate::finalize::analysis::RETAINED_EXCERPT_BYTES,
                    );
                    let action = String::from_utf8_lossy(&input[ts[sink].start..ts[sink].end]);
                    let description = format!(
                        "Export action '{action}' references protected resource '{}' (alias '{alias}'); \
                         destination '{dest}' has no caller grant. Nearby read evidence: {read}. \
                         Lexical relationship; execution is not established.", res.id
                    );
                    out.push(Observation {
                        rule_id: format!("action.export.{}", res.id),
                        class: crate::DetectionClass::Solicitation,
                        span: Span::new(start, end),
                        matched,
                        excerpt_truncated,
                        severity: config.severity,
                        description,
                        chain: Vec::new(),
                        suppressed_by: None,
                    });
                }
            }
        }
    }
    out
}
