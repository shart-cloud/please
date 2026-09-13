use std::time::Duration;

use crate::bench::model::{CoverageState, NativeResponse};

#[derive(Debug)]
pub struct NativeExecution {
    pub coverage: CoverageState,
    pub native: Option<NativeResponse>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<i32>,
    pub transport: &'static str,
    pub elapsed: Duration,
    pub runner_overhead: Duration,
    pub diagnostics: Vec<String>,
}

impl NativeExecution {
    pub fn unsupported() -> Self {
        Self {
            coverage: CoverageState::Unsupported,
            native: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: None,
            transport: "not_invoked",
            elapsed: Duration::ZERO,
            runner_overhead: Duration::ZERO,
            diagnostics: vec!["system does not declare this surface".into()],
        }
    }

    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            coverage: CoverageState::Unavailable,
            native: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: None,
            transport: "not_invoked",
            elapsed: Duration::ZERO,
            runner_overhead: Duration::ZERO,
            diagnostics: vec![detail.into()],
        }
    }
}
