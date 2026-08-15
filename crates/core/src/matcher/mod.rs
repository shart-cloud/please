//! The matcher — rules, the literal prefilter, and the compiled-pattern slots, behind one interface.
//!
//! **Skeleton (T005).** The contents arrive in Phase 7: `prefilter` moves here at T072, `patterns` at
//! T073, and the interface that hides them at T074.
//!
//! What this module is for is hiding a number. Feature 001 identifies a rule by its *position* in the
//! resolved rule slice, and that position is exchanged across three seams: the prefilter returns
//! candidate indices, the pattern cache keys compiled patterns by index, and the engine indexes back
//! into the slice to read a rule's metadata. Three components agreeing on an ordering is a coupling
//! that no type checks — insert a rule, or resolve an override differently, and every index means
//! something else while everything still compiles.
//!
//! Positions are a fine way to key a cache and a terrible thing to put in an interface. So the matcher
//! owns the slice, the prefilter, and the slots together, and what it hands out are observations
//! carrying a rule *identity* (FR-140, FR-141). The index space stops existing outside this module.
//!
//! It also accepts pre-filled compiled patterns from preparation (T075): validation has already paid
//! to compile every caller-supplied pattern, and compiling it a second time on first match is waste
//! this crate can simply not do (FR-109, SC-106).
