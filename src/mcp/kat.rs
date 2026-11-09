//! Runs a vector-set JSON file through a wrapper binary over the ACVP
//! modulewrapper protocol and, optionally, diffs the responses against an
//! expected-results file. Backs the `run_kat` MCP tool.

use super::RunKatRequest;
use crate::subprocess::Subprocess;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Caps how many mismatching fields are listed in the tool's text summary;
/// the full responses are always written to a file for closer inspection.
const MAX_MISMATCHES: usize = 20;

fn read_json(path: &Path) -> Result<Value> {
    let data = if path.extension().and_then(|e| e.to_str()) == Some("zip") {
        crate::utils::read_vectors_from_zip(path)?
    } else {
        std::fs::read_to_string(path).with_context(|| format!("failed to read {path:?}"))?
    };
    serde_json::from_str(&data).with_context(|| format!("failed to parse JSON in {path:?}"))
}

struct Comparison {
    run: usize,
    passed: usize,
    failed: usize,
    unsupported: usize,
    mismatches: Vec<String>,
}

fn groups<'a>(value: &'a Value, label: &str) -> Result<&'a Vec<Value>> {
    value["testGroups"]
        .as_array()
        .with_context(|| format!("{label} response is missing testGroups"))
}

/// Mirrors the semantics of the `--expected` comparison used by the CLI
/// path, but returns a bounded, structured summary instead of printing to
/// stdout/stderr -- MCP tool output is read by a model, not a terminal.
fn compare(actual: &Value, expected: &Value) -> Result<Comparison> {
    let actuals = match actual {
        Value::Array(a) => a.clone(),
        other => vec![other.clone()],
    };
    let expecteds = match expected {
        Value::Array(a) => a.clone(),
        other => vec![other.clone()],
    };

    let mut tested = 0usize;
    let mut failed_tests = 0usize;
    let mut unsupported = 0usize;
    let mut mismatches = Vec::new();

    for (act, exp) in actuals.iter().zip(expecteds.iter()) {
        let act_groups = groups(act, "actual")?;
        let exp_groups = groups(exp, "expected")?;

        for exp_group in exp_groups {
            let tg_id = exp_group["tgId"]
                .as_u64()
                .context("expected group missing tgId")?;
            let act_group = act_groups
                .iter()
                .find(|g| g["tgId"].as_u64() == Some(tg_id))
                .with_context(|| format!("actual response missing tgId {tg_id}"))?;

            let exp_tests = exp_group["tests"]
                .as_array()
                .with_context(|| format!("expected group {tg_id} missing tests"))?;
            let act_tests = act_group["tests"]
                .as_array()
                .with_context(|| format!("actual group {tg_id} missing tests"))?;

            for exp_test in exp_tests {
                let tc_id = exp_test["tcId"]
                    .as_u64()
                    .with_context(|| format!("expected test in group {tg_id} missing tcId"))?;

                let Some(act_test) = act_tests.iter().find(|t| t["tcId"].as_u64() == Some(tc_id))
                else {
                    unsupported += 1;
                    continue;
                };

                tested += 1;
                let mut test_failed = false;
                if let Some(fields) = exp_test.as_object() {
                    for (key, exp_val) in fields {
                        if key == "tcId" {
                            continue;
                        }
                        let act_val = &act_test[key];
                        let matches = match (exp_val, act_val) {
                            (Value::String(e), Value::String(a)) => {
                                e.to_lowercase() == a.to_lowercase()
                            }
                            _ => exp_val == act_val,
                        };
                        if !matches {
                            test_failed = true;
                            if mismatches.len() < MAX_MISMATCHES {
                                mismatches.push(format!(
                                    "tgId={tg_id} tcId={tc_id} field={key}: \
                                     expected={exp_val} actual={act_val}"
                                ));
                            }
                        }
                    }
                }
                if test_failed {
                    failed_tests += 1;
                }
            }
        }
    }

    Ok(Comparison {
        run: tested + unsupported,
        passed: tested - failed_tests,
        failed: failed_tests,
        unsupported,
        mismatches,
    })
}

pub fn run(req: &RunKatRequest) -> Result<String> {
    let wrapper = Path::new(&req.wrapper);
    let vectors = read_json(Path::new(&req.vectors))?;

    let mut subprocess = Subprocess::new(wrapper, req.param.as_deref())
        .with_context(|| format!("failed to start wrapper {wrapper:?}"))?;
    let responses = subprocess
        .process_vectors(&vectors)
        .with_context(|| format!("failed running vectors through {wrapper:?}"))?;
    let unsupported_by_wrapper = subprocess.unsupported_count();

    let out_path: PathBuf = match &req.out {
        Some(path) => PathBuf::from(path),
        None => std::env::temp_dir().join(format!(
            "katwalk-mcp-responses-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        )),
    };
    std::fs::write(&out_path, serde_json::to_string_pretty(&responses)?)
        .with_context(|| format!("failed to write responses to {out_path:?}"))?;

    let mut summary = serde_json::Map::new();
    summary.insert(
        "responses".into(),
        Value::String(out_path.display().to_string()),
    );
    summary.insert(
        "unsupportedByWrapper".into(),
        Value::from(unsupported_by_wrapper),
    );

    if let Some(expected_path) = &req.expected {
        let expected = read_json(Path::new(expected_path))?;
        let cmp = compare(&responses, &expected)?;
        summary.insert("testsRun".into(), Value::from(cmp.run));
        summary.insert("passed".into(), Value::from(cmp.passed));
        summary.insert("failed".into(), Value::from(cmp.failed));
        summary.insert("unsupportedVsExpected".into(), Value::from(cmp.unsupported));
        summary.insert(
            "result".into(),
            Value::String(if cmp.failed == 0 {
                "PASS".into()
            } else {
                "FAIL".into()
            }),
        );
        if !cmp.mismatches.is_empty() {
            summary.insert(
                "mismatches".into(),
                Value::Array(cmp.mismatches.into_iter().map(Value::String).collect()),
            );
        }
    }

    Ok(serde_json::to_string_pretty(&Value::Object(summary))?)
}
