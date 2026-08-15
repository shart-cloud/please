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

// ── SC-111, FR-140: the rule position space does not leave the matcher ─────────────────────────

#[test]
fn no_component_outside_the_matcher_indexes_the_rule_slice() {
    // SC-111. 001 identified a rule by its POSITION in the resolved slice, and that position crossed three
    // seams: the prefilter returned candidate indices, the pattern store keyed compiled patterns by index,
    // and the engine indexed back into the slice to read a rule's metadata. Three components agreeing on an
    // ordering is a coupling no type checks — insert a rule, or resolve an override differently, and every
    // index means something else while everything still compiles.
    //
    // Positions are a fine way to key a cache and a terrible thing to put in an interface. The matcher owns
    // all three together, so the index space is real but unobservable.
    // Two locations may index a rule slice, and the difference between them is the whole requirement.
    //
    //   matcher/       — owns the slice, the prefilter, and the compiled slots, so an index here is an
    //                    internal address that nothing outside can observe.
    //   ruleset/mod.rs — `Ruleset::resolve` replaces a rule by `position()` and then `rules[index] = rule`.
    //                    The index is created and consumed inside one function, over a `Vec` that function
    //                    owns, and never reaches a caller. That is not a seam; it is a local variable.
    //
    // FR-140 forbids EXCHANGING a position between components, not computing one. A test that forbade both
    // would be asking for `retain`-and-rebuild in `resolve` for no benefit to anyone.
    const MAY_INDEX: &[&str] = &["matcher/", "ruleset/mod.rs"];

    let found = occurrences("rules[");
    let outside: Vec<_> = found
        .iter()
        .filter(|(file, _, _)| !MAY_INDEX.iter().any(|allowed| file.contains(allowed)))
        .cloned()
        .collect();
    assert!(
        outside.is_empty(),
        "{}",
        report("indexing into the rule slice, outside the two places that may", &outside)
            + "\nA rule is identified by its id. A position is the matcher's private business, and any \
               new entry in this test's allow-list needs the same argument the two existing ones have."
    );
    assert!(
        !found.is_empty(),
        "no rule-slice indexing found anywhere; the search pattern is broken and this test is vacuous"
    );
}

#[test]
fn the_prefilters_candidate_indices_do_not_leave_the_matcher() {
    // The first of the three seams. `Prefilter::candidates` returns positions, which is the right thing for
    // it to do and the wrong thing for anyone else to see.
    let found = occurrences(".candidates(");
    let outside: Vec<_> = found
        .iter()
        .filter(|(file, _, _)| !file.contains("matcher/"))
        .cloned()
        .collect();
    assert!(
        outside.is_empty(),
        "{}",
        report("`.candidates(` outside matcher/", &outside)
    );
    assert!(!found.is_empty(), "search pattern is broken");
}

#[test]
fn the_matchers_public_interface_exchanges_no_position() {
    // The interface itself, read rather than inferred. Every `pub fn` in the matcher's own module must be
    // free of `usize` — no index in, no index out. `Span` carries `usize` fields, but it is a location in the
    // INPUT, which is a coordinate the caller already has and can act on; a rule position is a coordinate
    // only the matcher can interpret.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/matcher/mod.rs");
    let text = std::fs::read_to_string(&dir).expect("matcher/mod.rs must exist");

    let offenders: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("pub fn") || l.starts_with("pub const fn"))
        .filter(|l| l.contains("usize"))
        .collect();

    assert!(
        offenders.is_empty(),
        "the matcher's public interface mentions `usize`, which is how a position escapes:\n  {}",
        offenders.join("\n  ")
    );
    assert!(
        text.contains("pub fn"),
        "no public interface found at all; this test would pass vacuously"
    );
}

// ── FR-141: an observation carries an identity, and identity does not move ─────────────────────

/// A rule set containing `extra` filler rules that all sort BEFORE `z.target`.
///
/// Sorting matters: resolution orders rules by id, so adding rules whose ids precede `z.target` shifts its
/// position in the resolved slice. If any part of the pipeline identified it positionally, the reported
/// identity would move with it.
fn ruleset_with_filler(extra: usize) -> String {
    let mut source = String::from("[ruleset]\nname = \"test.identity\"\nversion = \"1.0.0\"\n");
    for i in 0..extra {
        source.push_str(&format!(
            "\n[[rule]]\nid = \"a.filler_{i}\"\nclass = \"boundary\"\nseverity = 10\n\
             literals = [\"zzzz_no_match_{i}\"]\npattern = 'zzzz_no_match_{i}'\n\
             description = \"Filler that sorts before the target and never matches.\"\n"
        ));
    }
    source.push_str(
        "\n[[rule]]\nid = \"z.target\"\nclass = \"override\"\nseverity = 85\n\
         literals = [\"needle\"]\npattern = 'needle'\ndescription = \"The rule under test.\"\n",
    );
    source
}

#[test]
fn a_reported_identity_does_not_move_when_a_rules_position_does() {
    // FR-141 behaviourally rather than by grep. Three rule sets in which `z.target` sits at position 0, 5,
    // and 20 of the resolved slice. Every scan must report the same id, the same span, and the same class.
    //
    // **This test passes on the day it is written, and that is correct.** 001 already reported identity as a
    // string — `Hit` carried `rule_id: String` — so the *reported* half of FR-141 was never broken. What was
    // broken is FR-140: positions were exchanged BETWEEN components, which the three grep tests above catch
    // and which were red before T072–T076. This one exists to hold the reported half still while the
    // components underneath it are rearranged, which is what a regression test is for.
    use please_core::policy::ScanPolicy;
    use please_core::verdict::TargetRef;
    use please_core::{DetectionClass, Engine};

    let input = "please find the needle here";
    let mut seen = Vec::new();

    for extra in [0usize, 5, 20] {
        let engine = Engine::from_toml(&ruleset_with_filler(extra))
            .unwrap_or_else(|e| panic!("rule set with {extra} filler rules must prepare: {e}"));

        // The target really does move: filler ids sort before `z.target`.
        assert_eq!(
            engine
                .ruleset()
                .all_rules()
                .iter()
                .position(|r| r.id == "z.target"),
            Some(extra),
            "the fixture must actually shift the position, or this test proves nothing"
        );

        let verdict = engine.scan(
            input.as_bytes(),
            &ScanPolicy::default(),
            TargetRef::buffer("t", input.len()),
        );
        assert_eq!(verdict.reasons().len(), 1, "one rule matches");
        let reason = &verdict.reasons()[0];
        seen.push((
            reason.rule_id().to_string(),
            reason.span().start,
            reason.span().end,
            reason.class(),
            verdict.score(),
        ));
    }

    let first = &seen[0];
    assert_eq!(first.0, "z.target", "reported by id, not by position");
    assert_eq!(first.3, DetectionClass::Override);
    for other in &seen[1..] {
        assert_eq!(
            first, other,
            "the same rule at a different position must produce an identical finding: {seen:?}"
        );
    }
}
