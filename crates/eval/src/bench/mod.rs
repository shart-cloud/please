//! Versioned prompt-injection test-bench contracts and runner.
//!
//! This module remains in the excluded evaluator. It treats case content as hostile data, preserves
//! native outputs, and never changes the shipping detector's configuration or dependency graph.

pub mod adapter;
pub mod exposure;
pub mod identity;
pub mod jev;
pub mod model;
pub mod normalize;
pub mod pack;
pub mod please;
pub mod presentation;
pub mod process;
pub mod protocol;
pub mod report;
pub mod runner;
pub mod system;
