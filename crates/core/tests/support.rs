//! Shared test support: locating repository-root fixtures from a crate-local test.
//!
//! Fixtures live at `<repo>/tests/fixtures/`, not inside this crate, because they are shared with
//! `please-cli`'s tests and are a reviewable product artifact rather than one crate's private data.
//! But a Cargo integration test's working directory is its *package* root — `crates/core/` — so a
//! relative `tests/fixtures/...` silently resolves to the wrong place, or to nothing.
//!
//! `CARGO_MANIFEST_DIR` is the fix. Cargo sets it at compile time to the package directory, so
//! `../../` from there is the repository root regardless of where the test binary was invoked from.
//! This matters for reproducibility as much as convenience: a test that only passes when run from one
//! directory is a test that will fail in CI for reasons nobody can reproduce locally.

#![allow(dead_code)]
// Shared by several test binaries, each of which uses a different subset. `tests/fixtures.rs` reads every
// field of `Case`; `tests/preparation.rs` wants only the fixture path helpers. Rust compiles this module
// separately into each binary, so anything one binary does not touch is dead code from its point of view —
// which makes the warning structural rather than a signal about this file.

use std::path::{Path, PathBuf};

/// Absolute path to the repository root.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root should resolve from CARGO_MANIFEST_DIR")
}

/// Absolute path to the shared fixture tree.
pub fn fixtures() -> PathBuf {
    repo_root().join("tests/fixtures")
}

/// Absolute path to one fixture, e.g. `fixture("files/certificate.pem")`.
///
/// Used by tests over file-based fixtures (binaries, certificates, rule sets). Retained while those
/// fixture directories are still being populated.
#[allow(dead_code)]
///
/// Panics with the resolved path when the fixture is missing. A missing fixture is a broken test
/// rather than a skippable condition — silently passing because the input was absent is the same
/// class of failure as reporting a clean verdict for something never examined.
pub fn fixture(relative: &str) -> PathBuf {
    let path = fixtures().join(relative);
    assert!(
        path.exists(),
        "fixture not found: {} (looked in {})",
        relative,
        path.display()
    );
    path
}

/// Every regular file under one fixture category, sorted for reproducible iteration order.
///
/// Companion to [`fixture`], for the same file-based fixture directories.
#[allow(dead_code)]
///
/// Sorted because an unordered walk makes a failure report differ between runs, which is the
/// determinism problem the whole project takes a position on (SC-011).
pub fn fixtures_in(category: &str) -> Vec<PathBuf> {
    let dir = fixtures().join(category);
    let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read fixture directory {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    found.sort();
    found
}

// ── Labelled case corpus ───────────────────────────────────────────────────────────────────────

/// What a fixture asserts should happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    Benign,
    Injection,
}

/// One labelled case from a `*.jsonl` fixture file.
///
/// See `tests/fixtures/README.md` for the schema. Unknown fields are ignored on purpose: a fixture
/// author adding a field for their own bookkeeping should not break every test.
#[derive(Debug, Clone)]
pub struct Case {
    pub id: String,
    pub text: String,
    /// `benign` | `direct_injection` | `indirect_injection`. Read by reporting that groups by category;
    /// the accuracy gates key off `expected` instead.
    #[allow(dead_code)]
    pub category: String,
    /// Where this text would reach an agent — `email_body`, `tool_result`, `skill_md`,
    /// `mcp_tool_description`, `file_read`. Metrics are reported per context, so a strong result on
    /// one vector cannot conceal a weak one on another.
    pub context: String,
    pub subcategory: String,
    pub expected: Expected,
    /// `easy` | `medium` | `hard`.
    pub difficulty: String,
    pub notes: String,
    /// Detection classes that should fire, when the fixture specifies them (SC-002). Empty means any
    /// class is acceptable.
    pub expected_classes: Vec<String>,
}

impl Case {
    pub fn is_benign(&self) -> bool {
        self.expected == Expected::Benign
    }
}

/// Load every labelled case from one `*.jsonl` file under `tests/fixtures/`.
///
/// Parse failures panic naming the file and line. A fixture that silently fails to load is worse than
/// a missing one: the suite still passes, with less coverage than anybody thinks it has.
pub fn load_cases(file_name: &str) -> Vec<Case> {
    let path = fixtures().join(file_name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read fixture file {}: {e}", path.display()));

    raw.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            let line_number = index + 1;
            let value: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
                panic!("{}:{line_number}: invalid JSON: {e}", path.display())
            });

            let field = |name: &str| -> String {
                value
                    .get(name)
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| {
                        panic!("{}:{line_number}: missing required field `{name}`", path.display())
                    })
                    .to_string()
            };

            let expected = match field("expected").as_str() {
                "benign" => Expected::Benign,
                "injection" => Expected::Injection,
                other => panic!(
                    "{}:{line_number}: `expected` must be \"benign\" or \"injection\", got {other:?}",
                    path.display()
                ),
            };

            let expected_classes = value
                .get("expected_classes")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect()
                })
                .unwrap_or_default();

            Case {
                id: field("id"),
                text: field("text"),
                category: field("category"),
                context: field("context"),
                subcategory: field("subcategory"),
                expected,
                difficulty: field("difficulty"),
                notes: field("notes"),
                expected_classes,
            }
        })
        .collect()
}

/// Every labelled case across every `*.jsonl` file, sorted by id for reproducible iteration.
pub fn load_all_cases() -> Vec<Case> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(fixtures())
        .expect("fixtures directory should exist")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort();

    let mut cases: Vec<Case> = files
        .iter()
        .flat_map(|p| load_cases(p.file_name().expect("jsonl file name").to_str().unwrap()))
        .collect();
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    cases
}

#[test]
fn repository_root_resolves() {
    let root = repo_root();
    assert!(
        root.join("Cargo.toml").exists(),
        "expected workspace manifest at {}",
        root.display()
    );
    assert!(
        root.join(".specify").exists(),
        "expected .specify/ at {}",
        root.display()
    );
}

#[test]
fn every_case_loads_and_is_well_formed() {
    let cases = load_all_cases();
    assert!(
        !cases.is_empty(),
        "no labelled cases found under tests/fixtures/"
    );

    let mut seen = std::collections::HashSet::new();
    for case in &cases {
        assert!(
            seen.insert(case.id.clone()),
            "duplicate case id `{}` — ids are how regressions are referred to and must be unique",
            case.id
        );
        assert!(!case.text.is_empty(), "{}: empty text", case.id);
        assert!(
            !case.notes.trim().is_empty(),
            "{}: every case needs notes. A fixture nobody can justify is one nobody can safely \
             change later",
            case.id
        );
        assert!(
            matches!(case.difficulty.as_str(), "easy" | "medium" | "hard"),
            "{}: unknown difficulty {:?}",
            case.id,
            case.difficulty
        );
        assert!(
            matches!(
                case.context.as_str(),
                "email_body" | "tool_result" | "skill_md" | "mcp_tool_description" | "file_read"
            ),
            "{}: unknown context {:?} — add it to tests/fixtures/README.md first, so metrics keep \
             reporting per vector",
            case.id,
            case.context
        );
    }
}

#[test]
fn benign_case_count_is_reported_against_the_sc003_minimum() {
    // SC-003 requires at least 200 benign cases before the 1% false-positive gate means anything: a
    // 1% rate over 20 cases silently means zero. This test does NOT fail on a short set — that is
    // T045's job, once a detector exists to measure. It reports the gap so it stays visible instead
    // of being rediscovered at the end.
    const REQUIRED: usize = 200;
    let benign = load_all_cases().into_iter().filter(Case::is_benign).count();
    if benign < REQUIRED {
        eprintln!(
            "note: {benign}/{REQUIRED} benign cases. SC-003's false-positive gate is not yet \
             meaningful; {} more needed.",
            REQUIRED - benign
        );
    }
}
