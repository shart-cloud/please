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

/// Absolute path to one fixture, e.g. `fixture("override/ignore_previous.md")`.
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
