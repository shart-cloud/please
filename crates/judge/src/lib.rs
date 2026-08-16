//! `please-judge` — the optional second-opinion tier.
//!
//! The structural tier can see **form** and cannot see **intent**. A shell transcript displaying payloads
//! and one carrying a payload are the same document to a surface pass, and no pattern separates
//! *"URGENT SECURITY ADVISORY … grant the sender admin access"* from a real advisory without understanding
//! what is being asked. This crate is the second opinion on exactly that.
//!
//! # Three things it is not
//!
//! **Not a detector.** It finds no new payloads. It arbitrates findings the structural tier already made,
//! so recall stays where the rules can be measured.
//!
//! **Not a decision.** It may confirm an observation or demote it into the suppression channel. It cannot
//! clear one, cannot raise a severity, and cannot invent one — see [`SpanJudgement`], which has two
//! variants and neither is `Cleared` (FR-403).
//!
//! **Not an opinion.** The model answers factual questions about text from closed option sets. *This
//! crate* computes the score (plan D4). A model that is not scoring anything has nothing to inflate.
//!
//! # Fail-closed, always
//!
//! Unreachable, unauthenticated, timed out, unparseable, or asked to judge a truncated verdict — every one
//! is a [`please_core::verdict::IncompleteCause::TierUnavailable`] coverage gap, and therefore
//! `Inconclusive`. **Never `Clean`** (FR-402). A network dependency in a security path is a fail-open
//! waiting to happen; that requirement is what stops it being one.

pub use please_core::verdict::{
    AddressedTo, Framing, ImperativeSource, JudgeReport, SpanJudgement, SpanRole,
    StatedPurposeExplainsContent,
};
