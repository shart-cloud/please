#![cfg(not(feature = "judge"))]
#[test]
fn jev_is_absent_without_judge_feature() {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_plz"))
        .args(["jev", "--check"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(64));
}
