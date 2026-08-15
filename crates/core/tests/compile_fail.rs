//! Tests that assert code **does not compile** (SC-108, FR-104, FR-121).
//!
//! Feature 002 makes two claims no ordinary test can check, because the claim in each case is that a
//! program is not writable:
//!
//!   * a detector cannot construct a `Reason`, an `Incompleteness`, or a `Verdict` — only finalization
//!     can (SC-108, FR-121). Feature 001 achieved this by convention and code review; the whole point
//!     of moving the verdict types behind `pub(super)` constructors is to make it structural instead;
//!   * a caller cannot mint built-in provenance for a rule they supplied (FR-104). If they could, the
//!     delta validation in T039 would become a way to skip validation entirely rather than a way to
//!     avoid repeating it.
//!
//! A test that compiles can only ever check the *positive* half of each: that finalization can build a
//! verdict, that preparation can mint `Builtin`. The negative half is what carries the guarantee, and
//! `trybuild` is how it is expressed — each case in `tests/compile_fail/` is a small program that must
//! be rejected by the compiler, with its expected diagnostic recorded alongside it in a `.stderr` file.
//!
//! **On the `.stderr` files.** They pin the compiler's message, not just the fact of failure, which is
//! deliberate: a case that fails for the wrong reason — a typo, a missing import, a renamed type —
//! would otherwise pass and assert nothing. That does mean a compiler upgrade can require regenerating
//! them (`TRYBUILD=overwrite cargo test -p please-core --test compile_fail`). Review the diff when it
//! happens; a change in *which* error fires is a change in the guarantee.
//!
//! **On the order of work.** Every case here is written before the sealing that makes it pass (T010 and
//! T032 precede T063), so during the middle of this feature these cases *fail* — the code they forbid
//! still compiles. That is the intended red phase, and T063 is the commit that turns it green.

use std::path::{Path, PathBuf};

/// Where the cases live, relative to this crate's manifest.
const CASE_DIR: &str = "tests/compile_fail";

#[test]
fn code_that_must_not_compile_does_not_compile() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(CASE_DIR);
    let cases = cases_in(&dir);

    if cases.is_empty() {
        // The harness lands (T004) before the first case does (T010). An empty directory is a real
        // state of this feature rather than a mistake, so say so plainly instead of failing — but do
        // not pretend a guarantee was checked.
        eprintln!(
            "note: no compile-fail cases in {}/ yet. SC-108 and FR-104 are UNCHECKED. \
             T010 and T032 add the cases; T063 makes them pass.",
            CASE_DIR
        );
        return;
    }

    let t = trybuild::TestCases::new();
    for case in cases {
        t.compile_fail(&case);
    }
}

/// The `.rs` files in `dir`, sorted, so a failure names the same case on every machine.
///
/// `trybuild` accepts a glob directly, but globbing a directory that does not exist yet is an error
/// rather than an empty set, and this feature spends several commits in exactly that state.
fn cases_in(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut cases: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    cases.sort();
    cases
}
