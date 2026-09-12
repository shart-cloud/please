//! Consumers can move or project retained analysis but cannot construct an arbitrary verdict.
use please_core::{Engine, ScanPolicy, TargetRef, Verdict};

fn main() {
    let analysis = Engine::builtin().unwrap()
        .scan(b"", &ScanPolicy::default(), TargetRef::buffer("test", 0))
        .into_analysis();
    let _ = Verdict::new(analysis);
}
