//! FR-104: a caller cannot mint built-in provenance.
//!
//! Built-in rules get treatment nothing else gets: preparation skips compiled validation for them at
//! default limits, on the grounds that CI has already established they compile. That shortcut is the whole
//! reason cold start is ~25 ms instead of ~70 ms, and it is sound only while `Builtin` is unforgeable. A
//! caller who could stamp their own rules `Builtin` would not be bypassing a formality — they would be
//! turning delta validation from "do not repeat work already done" into "skip validation entirely", which
//! is a way to load the resource bomb that `tests/fixtures/rules/bomb.toml` exists to reject.
//!
//! Note what is *not* forbidden: reading provenance, and minting `Supplied`. Both are public, because a
//! caller writing a rule loader has every right to say where their rules came from. It is the trusted
//! variant that is unavailable.
//!
//! # Why a public enum could not do this
//!
//! In Rust a public enum's variants are publicly constructible, and there is no way to make one variant
//! private — `pub enum Provenance { Builtin, Supplied }` hands `Provenance::Builtin` to everyone. So
//! `Provenance` is a public struct wrapping a private discriminant, with `Supplied` reachable through a
//! public constructor and `Builtin` reachable only from inside `crate::prepare` (research P1).
//!
//! Naming is the other route worth closing, and it is closed by construction rather than by a check: a
//! caller calling their rule set `please.builtin` gains nothing, because provenance is not derived from
//! content and a name is content. `preparation.rs::naming_a_rule_set_after_the_builtin_earns_nothing`
//! asserts that from the outside.

use please_core::prepare::Provenance;

fn main() {
    // Reading is public. This must keep compiling — the error below has to be about minting, not about
    // the type being unusable.
    let mine = Provenance::supplied();
    let _ = mine.is_builtin();

    // Minting the trusted variant is not.
    let _forged = Provenance::builtin();
}
