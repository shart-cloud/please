//! Preparation cost: is it proportional to the caller's rules, or to the resolved set? (SC-105)
//!
//! The reason this is measured rather than asserted-and-forgotten. Compiled validation costs ~44 ms for 80
//! rules against a ~25 ms cold-start budget for a process a pre-tool hook launches once per tool call
//! (research D17). Two designs are available:
//!
//!  * **validate the union.** Simple, obviously correct, and it means `--rules one-extra-rule.toml` costs
//!    what validating eighty-one rules costs. That is the difference between a flag people use and a flag
//!    people pass once, watch the latency, and never pass again.
//!  * **validate the delta.** The built-in half is already proven, in CI, at default limits — so prove the
//!    caller's rules and leave the rest. Cost tracks what the caller asked for.
//!
//! The second only works because provenance survives resolution per rule (FR-105). Without that, after
//! layering you can say "this set contains caller rules" but not *which*, and the delta collapses back into
//! the union.
//!
//! # What the numbers should show
//!
//! `builtin` should be flat and cheap regardless of the rule count — it compiles nothing. `layered/N`
//! should scale with N, the caller's rule count, and should **not** shift when the built-in set grows.
//! `from_source_whole_set` is the comparison: a caller replacing the built-in set entirely owns every rule
//! and pays for all of them, which is correct rather than a regression.
//!
//! # Measured, on the machine this was written on
//!
//! ```text
//! prepare/builtin                    489 µs      compiles nothing
//! prepare/builtin_revalidated       5.75 ms      compiles all 80, because limits were tightened
//! prepare/layered/1                 1.72 ms
//! prepare/layered/4                 6.84 ms
//! prepare/layered/16                25.2 ms
//! ```
//!
//! `builtin` against `builtin_revalidated` is the value of the CI record: ~5.3 ms of cold start that the
//! fast path does not spend. And `layered/1` at 1.72 ms is the delta working — validating the union would
//! make it ~7 ms, since it would pay `builtin_revalidated` plus the caller's one rule every time.
//!
//! Absolute numbers will differ per machine and are recorded for shape, not as a threshold. The
//! relationships are what matter: `builtin` flat and cheap, `layered/N` tracking N, and `layered/1` nowhere
//! near `builtin_revalidated`.
//!
//! # Why the assertion is not here
//!
//! The mechanical check lives in `tests/preparation.rs`, as a count of patterns compiled rather than a
//! wall-clock measurement. A timing assertion would be flaky on shared CI runners, and the count is the
//! thing the design actually constrains — time is a consequence. This bench exists to keep the consequence
//! honest: if `layered/1` ever approached `builtin_revalidated`, the delta would have stopped working in a
//! way the count assertion could still miss.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use please_core::prepare;
use please_core::ruleset::{Ruleset, RulesetLimits};

/// A rule set of `count` distinct, legitimate rules.
///
/// Distinct patterns rather than `count` copies of one: the compiler's own caching is not something this
/// benchmark should be measuring.
fn rules(count: usize) -> String {
    let mut source = String::from("[ruleset]\nname = \"bench.caller\"\nversion = \"1.0.0\"\n");
    for i in 0..count {
        source.push_str(&format!(
            r#"
[[rule]]
id = "bench.rule_{i}"
class = "override"
severity = 50
literals = ["marker{i}"]
pattern = '(?i)\bmarker{i}\s+\w+{{1,{}}}'
description = "Bench rule {i}."
"#,
            i % 7 + 3
        ));
    }
    source
}

fn preparation(c: &mut Criterion) {
    let mut group = c.benchmark_group("prepare");

    // The fast path. Compiles nothing, so this is parse plus resolve plus digest — the ~4 ms half of the
    // cold-start budget, and it must not grow when the delta machinery is added around it.
    group.bench_function("builtin", |b| {
        b.iter(|| prepare::builtin().expect("the built-in set must prepare"));
    });

    for count in [1usize, 4, 16] {
        let source = rules(count);

        // The path SC-105 is about: the caller's rules layered onto the built-in eighty. Cost must track
        // `count`, not 80 + count.
        group.bench_with_input(BenchmarkId::new("layered", count), &source, |b, source| {
            b.iter(|| {
                let addition = Ruleset::from_toml(source).expect("must parse");
                prepare::layered(None, vec![addition], &[], RulesetLimits::default())
                    .expect("must prepare")
            });
        });

        // The comparison. Replacing the built-in set means owning every rule, so this is the honest cost of
        // validating exactly what the caller supplied and nothing else.
        group.bench_with_input(
            BenchmarkId::new("from_source_whole_set", count),
            &source,
            |b, source| {
                b.iter(|| {
                    prepare::from_source(source, RulesetLimits::default()).expect("must prepare")
                });
            },
        );
    }

    // Tightened limits invalidate the CI record, so every built-in rule is revalidated (FR-108). This is
    // the expensive path, benched so its cost is known rather than discovered by a user who tightened a
    // limit and wondered why start-up got slower.
    group.bench_function("builtin_revalidated", |b| {
        b.iter(|| {
            prepare::builtin_with_limits(RulesetLimits {
                max_compiled_bytes: 512 * 1024,
                ..RulesetLimits::default()
            })
            .expect("the built-in set must validate at half the default budget")
        });
    });

    group.finish();
}

criterion_group!(benches, preparation);
criterion_main!(benches);
