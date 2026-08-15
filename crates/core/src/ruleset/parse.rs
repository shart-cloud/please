//! TOML → raw rule structures.
//!
//! Parsing walks the [`toml::Value`] tree by hand rather than deriving `Deserialize`. Three reasons,
//! and they all point the same way:
//!
//! * **Unknown fields must be rejected with the offending name.** A derive can reject unknown fields
//!   but the message it produces is not ours to shape, and this diagnostic is read by someone who has
//!   just mistyped `severty` and needs to be told so.
//! * **The `serde` feature is optional on this crate.** Rule loading is not optional, so it cannot
//!   depend on a feature that a wasm or embedded caller may have switched off.
//! * **Every error names its rule.** Walking the tree keeps the current rule id in hand, which a
//!   derive-based error does not have.

use super::{Bands, RulesetError};

type Table = toml::map::Map<String, toml::Value>;

/// A rule as it appears in TOML, before validation.
///
/// Separate from [`super::Rule`] because parsing establishes *shape* and validation establishes
/// *legality*. Keeping severity as `i64` here is deliberate: an out-of-range value must survive parsing
/// so validation can report the number the author actually wrote.
pub(super) struct RawRule {
    pub id: String,
    pub class: String,
    pub severity: i64,
    pub literals: Vec<String>,
    pub pattern: String,
    pub fires_in_quotes: bool,
    pub enabled: bool,
    pub description: String,
}

pub(super) struct RawRuleset {
    pub name: String,
    pub version: String,
    pub bands: Bands,
    pub rules: Vec<RawRule>,
}

const RULESET_FIELDS: &[&str] = &["name", "version"];
const BANDS_FIELDS: &[&str] = &["low", "medium", "high", "critical"];
const RULE_FIELDS: &[&str] = &[
    "id",
    "class",
    "severity",
    "literals",
    "pattern",
    "fires_in_quotes",
    "enabled",
    "description",
];
const TOP_FIELDS: &[&str] = &["ruleset", "bands", "rule"];

pub(super) fn parse(source: &str) -> Result<RawRuleset, RulesetError> {
    // `toml::Table` rather than `toml::Value`: `Value`'s `FromStr` parses a single TOML *value*
    // expression and rejects a document outright ("unexpected content, expected nothing"). `Table` is
    // the document-level entry point.
    let table: toml::Table = source
        .parse()
        .map_err(|e: toml::de::Error| RulesetError::Toml {
            detail: e.to_string(),
        })?;

    reject_unknown(table.keys().map(String::as_str), TOP_FIELDS, &None)?;

    // ── [ruleset] ───────────────────────────────────────────────────────────────────────────────
    let meta = table
        .get("ruleset")
        .ok_or_else(|| RulesetError::MissingField {
            rule: None,
            field: "ruleset".to_string(),
        })?
        .as_table()
        .ok_or_else(|| RulesetError::WrongType {
            rule: None,
            field: "ruleset".to_string(),
            expected: "a table",
        })?;
    reject_unknown(meta.keys().map(String::as_str), RULESET_FIELDS, &None)?;
    let name = required_string(meta, "name", &None)?;
    let version = required_string(meta, "version", &None)?;

    // ── [bands] ─────────────────────────────────────────────────────────────────────────────────
    let bands = match table.get("bands") {
        None => Bands::default(),
        Some(value) => {
            let t = value.as_table().ok_or_else(|| RulesetError::WrongType {
                rule: None,
                field: "bands".to_string(),
                expected: "a table",
            })?;
            reject_unknown(t.keys().map(String::as_str), BANDS_FIELDS, &None)?;
            let default = Bands::default();
            Bands {
                low: band_value(t, "low", default.low)?,
                medium: band_value(t, "medium", default.medium)?,
                high: band_value(t, "high", default.high)?,
                critical: band_value(t, "critical", default.critical)?,
            }
        }
    };

    // ── [[rule]] ────────────────────────────────────────────────────────────────────────────────
    let mut rules = Vec::new();
    if let Some(value) = table.get("rule") {
        let array = value.as_array().ok_or_else(|| RulesetError::WrongType {
            rule: None,
            field: "rule".to_string(),
            expected: "an array of tables",
        })?;
        for entry in array {
            let t = entry.as_table().ok_or_else(|| RulesetError::WrongType {
                rule: None,
                field: "rule".to_string(),
                expected: "an array of tables",
            })?;

            // Read the id first so every subsequent diagnostic can name the rule it came from.
            let id = required_string(t, "id", &None)?;
            let at = Some(id.clone());

            reject_unknown(t.keys().map(String::as_str), RULE_FIELDS, &at)?;

            rules.push(RawRule {
                class: required_string(t, "class", &at)?,
                severity: required_integer(t, "severity", &at)?,
                literals: optional_string_array(t, "literals", &at)?,
                pattern: required_string(t, "pattern", &at)?,
                fires_in_quotes: optional_bool(t, "fires_in_quotes", false, &at)?,
                enabled: optional_bool(t, "enabled", true, &at)?,
                description: required_string(t, "description", &at)?,
                id,
            });
        }
    }

    Ok(RawRuleset {
        name,
        version,
        bands,
        rules,
    })
}

fn reject_unknown<'a>(
    present: impl Iterator<Item = &'a str>,
    allowed: &[&str],
    rule: &Option<String>,
) -> Result<(), RulesetError> {
    for key in present {
        if !allowed.contains(&key) {
            return Err(RulesetError::UnknownField {
                rule: rule.clone(),
                field: key.to_string(),
            });
        }
    }
    Ok(())
}

fn required_string(
    table: &Table,
    field: &str,
    rule: &Option<String>,
) -> Result<String, RulesetError> {
    match table.get(field) {
        None => Err(RulesetError::MissingField {
            rule: rule.clone(),
            field: field.to_string(),
        }),
        Some(value) => value
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| RulesetError::WrongType {
                rule: rule.clone(),
                field: field.to_string(),
                expected: "a string",
            }),
    }
}

fn required_integer(
    table: &Table,
    field: &str,
    rule: &Option<String>,
) -> Result<i64, RulesetError> {
    match table.get(field) {
        None => Err(RulesetError::MissingField {
            rule: rule.clone(),
            field: field.to_string(),
        }),
        Some(value) => value.as_integer().ok_or_else(|| RulesetError::WrongType {
            rule: rule.clone(),
            field: field.to_string(),
            expected: "an integer",
        }),
    }
}

fn optional_bool(
    table: &Table,
    field: &str,
    default: bool,
    rule: &Option<String>,
) -> Result<bool, RulesetError> {
    match table.get(field) {
        None => Ok(default),
        Some(value) => value.as_bool().ok_or_else(|| RulesetError::WrongType {
            rule: rule.clone(),
            field: field.to_string(),
            expected: "a boolean",
        }),
    }
}

fn optional_string_array(
    table: &Table,
    field: &str,
    rule: &Option<String>,
) -> Result<Vec<String>, RulesetError> {
    match table.get(field) {
        None => Ok(Vec::new()),
        Some(value) => {
            let array = value.as_array().ok_or_else(|| RulesetError::WrongType {
                rule: rule.clone(),
                field: field.to_string(),
                expected: "an array of strings",
            })?;
            array
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| RulesetError::WrongType {
                            rule: rule.clone(),
                            field: field.to_string(),
                            expected: "an array of strings",
                        })
                })
                .collect()
        }
    }
}

fn band_value(table: &Table, field: &str, default: u8) -> Result<u8, RulesetError> {
    match table.get(field) {
        None => Ok(default),
        Some(value) => {
            let raw = value.as_integer().ok_or_else(|| RulesetError::WrongType {
                rule: None,
                field: format!("bands.{field}"),
                expected: "an integer",
            })?;
            u8::try_from(raw).ok().filter(|v| *v <= 100).ok_or_else(|| {
                RulesetError::BandsNotAscending {
                    detail: format!("bands.{field} = {raw} is outside 0..=100"),
                }
            })
        }
    }
}
