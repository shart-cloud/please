//! Where a rule came from, as a value rather than a claim (FR-104).
//!
//! Built-in rules get treatment nothing else gets: preparation skips compiled validation for them at
//! default limits, because a CI check has already established that they compile. That shortcut is what
//! keeps cold start near 25 ms rather than 70 ms, and it is sound only while [`Provenance::Builtin`] —
//! spelled [`Provenance::builtin`] here — is unobtainable outside this module tree.
//!
//! # Why this is a struct wrapping a private enum
//!
//! The obvious spelling does not work:
//!
//! ```ignore
//! pub enum Provenance { Builtin, Supplied }
//! ```
//!
//! In Rust a public enum's variants are publicly constructible and there is no way to make one variant
//! private. That declaration hands `Provenance::Builtin` to every caller, and the guarantee becomes a
//! request. `#[non_exhaustive]` does not help either: it stops downstream crates from *matching*
//! exhaustively and from constructing with a struct literal, but a unit variant stays constructible, and
//! it does nothing at all inside this crate — where the detectors live.
//!
//! So: a public newtype over a private discriminant. Reading is public, minting `Supplied` is public, and
//! minting `Builtin` is `pub(super)` — visible in `crate::prepare` and nowhere else (research P1).
//! `tests/compile_fail/provenance_cannot_be_forged.rs` asserts it.
//!
//! # Provenance is not derived from content
//!
//! A caller naming their rule set `please.builtin` gains nothing, because the name is content and this is
//! not read from content. It is stamped by whoever loaded the bytes, and only preparation loads the
//! embedded ones.

/// The trust origin of a rule.
///
/// `Copy`, because it is one bit of information and threading a reference to it through resolution would
/// be all cost and no benefit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Provenance(Origin);

/// The discriminant. **Private, and that is the entire mechanism** — see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Origin {
    Builtin,
    Supplied,
}

impl Provenance {
    /// Shipped inside the binary, with validity established in continuous integration.
    ///
    /// `pub(super)`: reachable from `crate::prepare` and nowhere else. This is the only privileged value
    /// in the crate, and preparation is the only thing that can produce it.
    pub(super) fn builtin() -> Self {
        Self(Origin::Builtin)
    }

    /// Provided by a caller at run time. Public: anyone loading rules may say so, and saying so is what
    /// gets those rules validated.
    pub fn supplied() -> Self {
        Self(Origin::Supplied)
    }

    /// True for rules shipped inside the binary.
    ///
    /// The one question anything asks of this type, and the reason it exists: it is what lets delta
    /// validation validate the caller's half of a resolved set and leave the other half alone (FR-105).
    pub fn is_builtin(&self) -> bool {
        matches!(self.0, Origin::Builtin)
    }

    /// Stable name, for the identity digest and for diagnostics.
    ///
    /// Part of what a prepared rule set's digest covers, so two sets with identical rules and different
    /// trust origins are distinguishable (FR-111).
    pub fn as_str(&self) -> &'static str {
        match self.0 {
            Origin::Builtin => "builtin",
            Origin::Supplied => "supplied",
        }
    }
}

impl Default for Provenance {
    /// `Supplied`.
    ///
    /// Deliberately the untrusted value. A default that granted trust would mean any future code path
    /// that forgot to set provenance would silently skip validation — the failure would be invisible and
    /// in the unsafe direction. Defaulting to `Supplied` makes the same mistake cost an unnecessary
    /// compile, which is a performance bug rather than a security one.
    fn default() -> Self {
        Self::supplied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_origins_are_distinguishable() {
        assert!(Provenance::builtin().is_builtin());
        assert!(!Provenance::supplied().is_builtin());
        assert_ne!(Provenance::builtin(), Provenance::supplied());
    }

    #[test]
    fn the_default_is_untrusted() {
        // If this ever flips, every code path that forgets to set provenance starts skipping validation.
        assert_eq!(Provenance::default(), Provenance::supplied());
    }

    #[test]
    fn wire_names_are_stable() {
        // These reach the identity digest, so changing one re-identifies every rule set ever prepared.
        assert_eq!(Provenance::builtin().as_str(), "builtin");
        assert_eq!(Provenance::supplied().as_str(), "supplied");
    }
}
