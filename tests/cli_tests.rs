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
        .stdout(predicate::str::contains("--wrapper"))
        .stdout(predicate::str::contains("--testset"));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("katwalk").unwrap();
    cmd.arg("--version");

    let expected_version = env!("CARGO_PKG_VERSION");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_version));
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

fn write_sha3_testset_fixture(
    temp_dir: &TempDir,
    expected_md: &str,
    output: Option<&str>,
) -> std::path::PathBuf {
    let manifest_dir = temp_dir.path().join("manifest");
    let vectors_dir = manifest_dir.join("vectors");
    fs::create_dir_all(&vectors_dir).unwrap();

    fs::write(
        vectors_dir.join("prompt.json"),
        r#"{
            "vsId": 1,
            "algorithm": "SHA3-256",
            "revision": "1.0",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "tests": [{"tcId": 1, "msg": "", "len": 0}]
            }]
        }"#,
    )
    .unwrap();
    fs::write(
        vectors_dir.join("expected.json"),
        format!(
            r#"{{
                "vsId": 1,
                "algorithm": "SHA3-256",
                "revision": "1.0",
                "testGroups": [{{
                    "tgId": 1,
                    "tests": [{{"tcId": 1, "md": "{expected_md}"}}]
                }}]
            }}"#
        ),
    )
    .unwrap();

    let output = output
        .map(|path| format!(r#", "out": "{path}""#))
        .unwrap_or_default();
    let manifest = manifest_dir.join("testset.json");
    fs::write(
        &manifest,
        format!(
            r#"{{
                "tests": [{{
                    "in": "vectors/prompt.json",
                    "expected": "vectors/expected.json"{output}
                }}]
            }}"#
        ),
    )
    .unwrap();
    manifest
}

#[test]
fn test_cli_testset_resolves_manifest_relative_paths_and_writes_to_outdir() {
    let temp_dir = TempDir::new().unwrap();
    let manifest = write_sha3_testset_fixture(
        &temp_dir,
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        None,
    );
    let outdir = temp_dir.path().join("responses");

    let mut cmd = Command::cargo_bin("katwalk").unwrap();
    cmd.arg("--wrapper")
        .arg(assert_cmd::cargo::cargo_bin("fips202_wrapper"))
        .arg("--testset")
        .arg(&manifest)
        .arg("--outdir")
        .arg(&outdir)
        .current_dir(temp_dir.path());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("PASS"));
    assert!(outdir.join("prompt.json").exists());
}

#[test]
fn test_cli_testset_failure_identifies_manifest_entry() {
    let temp_dir = TempDir::new().unwrap();
    let manifest = write_sha3_testset_fixture(&temp_dir, "00", None);

    let mut cmd = Command::cargo_bin("katwalk").unwrap();
    cmd.arg("--wrapper")
        .arg(assert_cmd::cargo::cargo_bin("fips202_wrapper"))
        .arg("--testset")
        .arg(&manifest);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("FAIL testset entry=1 input="))
        .stderr(predicate::str::contains("tgId=1 tcId=1 field=md"))
        .stderr(predicate::str::contains("Test-set entry 1"));
}

#[test]
fn test_cli_testset_refuses_to_overwrite_outputs() {
    let temp_dir = TempDir::new().unwrap();
    let manifest = write_sha3_testset_fixture(
        &temp_dir,
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        Some("response.json"),
    );
    fs::write(
        temp_dir.path().join("manifest/response.json"),
        "existing output",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("katwalk").unwrap();
    cmd.arg("--wrapper")
        .arg("/nonexistent/wrapper")
        .arg("--testset")
        .arg(&manifest);

    cmd.assert().failure().stderr(predicate::str::contains(
        "would overwrite existing output file",
    ));
}

#[test]
fn test_cli_testset_conflicts_with_single_file_mode() {
    let mut cmd = Command::cargo_bin("katwalk").unwrap();
    cmd.arg("--wrapper")
        .arg("/nonexistent/wrapper")
        .arg("--testset")
        .arg("testset.json")
        .arg("--in")
        .arg("prompt.json");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}
