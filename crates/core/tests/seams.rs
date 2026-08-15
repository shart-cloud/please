//! Structural claims about the source, asserted by reading it (SC-107, SC-111).
//!
//! Some guarantees are about **how many places** a decision is made, and no runtime test can see that. A
//! test can check that finalization produces the right verdict; it cannot check that finalization is the
//! only thing that produces one, or that there is exactly one definition of how reasons are ordered. Those
//! are properties of the source text.
//!
//! # Why not rely on visibility alone
//!
//! `Verdict::new` is `pub(super)`, so nothing outside `crate::finalize` can call it — and
//! `tests/compile_fail/only_finalization_produces_a_verdict.rs` proves that. What visibility does *not*
//! prevent is a second call site appearing **inside** `finalize`, which is where the three producers in 001
//! would have lived had the module existed. Two producers inside one module is the same bug as two producers
//! in two modules; it is just harder to notice.
//!
//! Likewise a second reason-ordering `sort_by`. 001 had two — one in `Verdict::assemble` and one in
//! `Engine::scan` immediately before truncating — and neither was wrong. Two identical sorts is not a bug,
//! it is a bug waiting for someone to improve one of them.
//!
//! # These tests are grep, and they know it
//!
//! Reading source with string matching is crude, and the failure mode to guard against is a test that
//! silently stops finding anything and reports success. So each assertion is two-sided: it pins the expected
//! count **and** fails if the count is zero. A test asserting "at most one" would pass on a typo in its own
//! search pattern.

use std::path::{Path, PathBuf};

/// Every `.rs` file under the shipping crates, excluding tests and benches.
///
/// Test code legitimately does things production code must not — `tests/finalization.rs` calls
/// `finalize::finalize` in fifteen places — so scanning it would make these counts meaningless.
fn source_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf();

    let mut files = Vec::new();
    for crate_dir in ["core", "cli"] {
        collect(&root.join(crate_dir).join("src"), &mut files);
    }
    files.sort();
    assert!(
        files.len() > 10,
        "found only {} source files; the walk is broken and every count below would be a false pass",
        files.len()
    );
    files
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Occurrences of `needle` across the shipping source, as `(file, line number, line)`.
///
/// Comment lines are skipped. Every one of these guarantees is discussed at length in comments — the
/// paragraph above this function names `Verdict::new` twice — and counting prose would make the assertions
/// depend on how thoroughly the code is documented, which is precisely backwards.
fn occurrences(needle: &str) -> Vec<(String, usize, String)> {
    let mut found = Vec::new();
    for path in source_files() {
        let text = std::fs::read_to_string(&path).expect("source must be readable");
        let name = path
            .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
            .unwrap_or(&path)
            .display()
            .to_string();
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }
            if line.contains(needle) {
                found.push((name.clone(), index + 1, line.trim().to_string()));
            }
        }
    }
    found
}

fn report(label: &str, found: &[(String, usize, String)]) -> String {
    let mut out = format!("{} site(s) of {label}:\n", found.len());
    for (file, line, text) in found {
        out.push_str(&format!("  {file}:{line}  {text}\n"));
    }
    out
}

// ── SC-107: one producer, one ordering ─────────────────────────────────────────────────────────

#[test]
fn exactly_one_place_constructs_a_verdict() {
    // FR-120. 001 had three, all in `engine.rs`, each assembling a `VerdictParts` by hand — so the
    // FR-004 clean-means-examined invariant was decided in three places that had to agree.
    let found = occurrences("Verdict::new(");
    assert_eq!(
        found.len(),
        1,
        "{}",
        report("`Verdict::new(`", &found)
            + "\nExactly one construction site is the guarantee. Visibility stops a caller OUTSIDE \
               `finalize` from adding one; only this test stops a second appearing inside it."
    );
    assert!(
        found[0].0.ends_with("finalize/mod.rs"),
        "the one producer must be in finalize/mod.rs, found in {}",
        found[0].0
    );
}

#[test]
fn exactly_one_definition_of_how_reasons_are_ordered() {
    // FR-125. The ordering is byte offset, then rule id as the tie-break — so the tie-break comparison is
    // the signature of a definition of the order, and there must be one.
    let found = occurrences("rule_id().cmp(");
    assert_eq!(
        found.len(),
        1,
        "{}",
        report("the reason-ordering tie-break", &found)
            + "\n001 had two identical sorts, one in `Verdict::assemble` and one in `Engine::scan` before \
               truncating. Neither was wrong. Two identical sorts is a bug waiting for someone to improve \
               one of them."
    );
    assert!(
        found[0].0.ends_with("finalize/mod.rs"),
        "the ordering must be defined in finalize/mod.rs, found in {}",
        found[0].0
    );
}

#[test]
fn nothing_outside_finalization_aggregates_a_score() {
    // FR-124 and FR-127. The score is derived from the evidence accumulator, inside finalization. A caller
    // that computed its own would be maintaining a second view of the observations — which is the shape
    // this feature removes rather than the instance.
    //
    // 001, and this crate up to T058, called `aggregate` from `Engine::scan` over a parallel collection of
    // `(severity, class)` pairs assembled alongside the reasons. Their agreement was the score's
    // correctness, and it was maintained by a comment.
    let found = occurrences("aggregate(");
    let outside: Vec<_> = found
        .iter()
        .filter(|(file, _, _)| !file.contains("finalize/"))
        .cloned()
        .collect();
    assert!(
        outside.is_empty(),
        "{}",
        report("`aggregate(` outside finalize/", &outside)
            + "\nDeriving the score anywhere else means holding a second collection of observations."
    );
    assert!(
        !found.is_empty(),
        "no call to `aggregate` found anywhere; the search pattern is broken"
    );
}

#[test]
fn the_class_filter_is_applied_at_exactly_one_site() {
    // FR-133. Not the *resolution* of the active set, which is `ScanPlan::resolve`, but its application.
    // 001 applied it in four places and changed an observation's class between two of them, which is the
    // US2 defect.
    let found = occurrences(".admits(");
    let applications: Vec<_> = found
        .iter()
        .filter(|(file, _, _)| !file.contains("finalize/plan.rs"))
        .cloned()
        .collect();
    assert_eq!(
        applications.len(),
        1,
        "{}",
        report("`.admits(` outside its own definition", &applications)
            + "\nOne application site cannot disagree with itself. Four can, and did."
    );
}

// ── The gap vocabulary has one shape ───────────────────────────────────────────────────────────

#[test]
fn only_finalization_turns_a_coverage_gap_into_a_reported_one() {
    // FR-122. Detectors record `CoverageGap`; finalization converts. If a second conversion site existed,
    // a gap could reach a verdict without passing through the accumulator finalization reads.
    let found = occurrences("into_incompleteness()");
    let outside: Vec<_> = found
        .iter()
        .filter(|(file, _, _)| !file.contains("finalize/"))
        .cloned()
        .collect();
    assert!(
        outside.is_empty(),
        "{}",
        report("`into_incompleteness()` outside finalize/", &outside)
    );
    assert!(
        !found.is_empty(),
        "no conversion found at all; the search pattern is broken"
    );
}
