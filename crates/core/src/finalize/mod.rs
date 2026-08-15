//! Verdict finalization — the one place that decides what a verdict says (FR-120).
//!
//! **Skeleton (T005).** The contents arrive in Phase 2: `types` (T007–T009), `evidence` (T011–T013),
//! `plan` (T014), `score` (T015), and the assembly itself (T016, T017).
//!
//! Feature 001 built verdicts in three places in `engine.rs` — the size gate, the main path, and the
//! unreadable target — each assembling `VerdictParts` by hand. Three producers means three chances to
//! forget the aggregate-before-truncate rule, three orderings of reasons that must agree, and a class
//! of bug that code review catches or does not.
//!
//! The design here is that detectors produce [`Evidence`] and nothing else, and finalization consumes
//! evidence and produces the only `Verdict` anyone can obtain. That makes several disciplines from 001
//! structural rather than remembered:
//!
//!   * the score is derived from the evidence accumulator, so it cannot be computed over a truncated
//!     report — there is no second collection to truncate (FR-124);
//!   * reason ordering has one definition, because there is one producer (FR-125);
//!   * a detector cannot construct a `Reason` at all, because the constructors are `pub(super)` and a
//!     detector is not a submodule of this one (FR-121, and see `tests/compile_fail/`).
//!
//! The verdict types live *inside* this module rather than beside it for exactly that last reason: Rust
//! cannot grant construction rights to a sibling, so a module that must be the sole producer has to be
//! the module the types are defined in (research P3).
