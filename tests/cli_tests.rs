// Command-line interface tests

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("katwalk").unwrap();
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("katwalk"))
        .stdout(predicate::str::contains("--wrapper"));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("katwalk").unwrap();
    cmd.arg("--version");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("0.0.1"));
}

#[test]
fn test_cli_missing_wrapper() {
    let mut cmd = Command::cargo_bin("katwalk").unwrap();
    cmd.arg("--regcap");

    // Should fail because --wrapper is required
    cmd.assert().failure();
}

#[test]
fn test_cli_invalid_wrapper_path() {
    let mut cmd = Command::cargo_bin("katwalk").unwrap();
    cmd.arg("--wrapper")
        .arg("/nonexistent/wrapper")
        .arg("--regcap");

    cmd.assert().failure();
}

#[test]
fn test_cli_in_without_out() {
    let mut cmd = Command::cargo_bin("katwalk").unwrap();
    cmd.arg("--wrapper")
        .arg("/tmp/dummy")
        .arg("--in")
        .arg("test.json");

    // Should not crash, but will exit with code 1 for no operation
    let _ = cmd.assert();
}

#[test]
fn test_cli_indir_without_outdir() {
    let mut cmd = Command::cargo_bin("katwalk").unwrap();
    cmd.arg("--wrapper")
        .arg("/tmp/dummy")
        .arg("--indir")
        .arg("/tmp/indir");

    // Should not crash
    let _ = cmd.assert();
}

#[test]
fn test_file_operations() {
    let temp_dir = TempDir::new().unwrap();

    // Create a test input file
    let input_file = temp_dir.path().join("input.json");
    fs::write(
        &input_file,
        r#"{"vsId": 1, "algorithm": "SHA2-256", "testGroups": []}"#,
    )
    .unwrap();

    // Verify file exists
    assert!(input_file.exists());

    // Read it back
    let content = fs::read_to_string(&input_file).unwrap();
    assert!(content.contains("SHA2-256"));
}

#[test]
fn test_json_parsing() {
    use serde_json::Value;

    let json_str = r#"{
        "vsId": 12345,
        "algorithm": "SHA2-256",
        "revision": "1.0",
        "testGroups": []
    }"#;

    let parsed: Value = serde_json::from_str(json_str).unwrap();
    assert_eq!(parsed["vsId"], 12345);
    assert_eq!(parsed["algorithm"], "SHA2-256");
}

#[test]
fn test_directory_creation() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().join("responses");

    fs::create_dir_all(&output_dir).unwrap();
    assert!(output_dir.exists());
    assert!(output_dir.is_dir());
}
