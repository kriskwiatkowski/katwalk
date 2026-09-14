use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

mod acvp;
mod config;
mod subprocess;
mod utils;

use crate::acvp::ACVPClient;
use crate::config::Config;
use crate::subprocess::Subprocess;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Print module capabilities JSON to stdout
    #[arg(long)]
    regcap: bool,

    /// Location of the configuration JSON file
    #[arg(short, long, default_value = "config.json")]
    config: PathBuf,

    /// Location of a vector-set input file
    #[arg(long)]
    r#in: Option<PathBuf>,

    /// Location of the response file
    #[arg(long)]
    out: Option<PathBuf>,

    /// Directory with request vectors (requires -outdir)
    #[arg(long)]
    indir: Option<PathBuf>,

    /// Directory for storing response files (used with --indir or --testset)
    #[arg(long)]
    outdir: Option<PathBuf>,

    /// JSON manifest of vector sets to run and verify
    #[arg(
        long,
        conflicts_with_all = ["regcap", "in", "out", "indir", "expected", "run", "fetch"]
    )]
    testset: Option<PathBuf>,

    /// Name of primitive to run tests for
    #[arg(long)]
    run: Option<String>,

    /// Name of primitive to fetch vectors for
    #[arg(long)]
    fetch: Option<String>,

    /// Path to the wrapper binary
    #[arg(short, long)]
    wrapper: PathBuf,

    /// Optional parameter that's passed to the wrapper
    #[arg(long)]
    param: Option<String>,

    /// Path to expected results JSON for verification (used with --in/--out)
    #[arg(long)]
    expected: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestSetManifest {
    tests: Vec<TestSetEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestSetEntry {
    #[serde(rename = "in")]
    input: PathBuf,
    expected: PathBuf,
    out: Option<PathBuf>,
}

#[derive(Debug)]
struct ResolvedTestSetEntry {
    input: PathBuf,
    expected: PathBuf,
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // Handle regcap flag
    if args.regcap {
        let mut subprocess = Subprocess::new(&args.wrapper, args.param.as_deref())?;
        let regcap = subprocess.get_config()?;
        println!("{}", serde_json::to_string_pretty(&regcap)?);
        return Ok(());
    }

    if let Some(testset) = &args.testset {
        process_vectors_from_testset(
            &args.wrapper,
            args.param.as_deref(),
            testset,
            args.outdir.as_deref(),
        )?;
        return Ok(());
    }

    // Handle file-based vector processing
    if let (Some(input), Some(output)) = (&args.r#in, &args.out) {
        process_vectors_from_file(
            &args.wrapper,
            args.param.as_deref(),
            input,
            Some(output),
            args.expected.as_deref(),
            true,
            None,
        )?;
        return Ok(());
    }

    // Handle directory-based processing
    if let (Some(indir), Some(outdir)) = (&args.indir, &args.outdir) {
        process_vectors_from_directory(&args.wrapper, args.param.as_deref(), indir, outdir)?;
        return Ok(());
    }

    // Handle interactive mode with ACVP server
    if args.run.is_some() || args.fetch.is_some() {
        let config = Config::from_file(&args.config)?;
        let mut client = ACVPClient::new(config, &args.wrapper, args.param.as_deref()).await?;

        if let Some(primitive) = args.fetch {
            client.fetch_vectors(&primitive).await?;
        }

        if let Some(primitive) = args.run {
            client.run_tests(&primitive).await?;
        }

        return Ok(());
    }

    error!(
        "No operation specified. Use --regcap, --in/--out, --indir/--outdir, \
         --testset, or --run/--fetch"
    );
    std::process::exit(1);
}

fn process_vectors_from_file(
    wrapper_path: &Path,
    param: Option<&str>,
    input: &Path,
    output: Option<&Path>,
    expected_path: Option<&Path>,
    overwrite_output: bool,
    testset_entry: Option<usize>,
) -> Result<()> {
    info!("Processing vectors from file: {:?}", input);

    let input_data = if input.extension().and_then(|s| s.to_str()) == Some("zip") {
        utils::read_vectors_from_zip(input)?
    } else {
        std::fs::read_to_string(input).context("Failed to read input file")?
    };

    let test_vectors: serde_json::Value =
        serde_json::from_str(&input_data).context("Failed to parse input JSON")?;

    let mut subprocess = Subprocess::new(wrapper_path, param)?;
    let responses = subprocess.process_vectors(&test_vectors)?;

    if let Some(output) = output {
        let output_json = serde_json::to_string_pretty(&responses)?;
        if overwrite_output {
            std::fs::write(output, &output_json).context("Failed to write output file")?;
        } else {
            let file = OpenOptions::new().write(true).create_new(true).open(output);
            let mut file = match file {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    anyhow::bail!("Refusing to overwrite output file {}", output.display());
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("Failed to create output file {}", output.display())
                    });
                }
            };
            file.write_all(output_json.as_bytes())
                .context("Failed to write output file")?;
        }
        info!("Responses written to: {:?}", output);
    }

    if subprocess.unsupported_count() > 0 {
        println!(
            "{} test(s) reported unsupported by wrapper",
            subprocess.unsupported_count()
        );
    }

    if let Some(path) = expected_path {
        let expected_data =
            std::fs::read_to_string(path).context("Failed to read expected results file")?;
        let expected: serde_json::Value =
            serde_json::from_str(&expected_data).context("Failed to parse expected JSON")?;
        check_expected_with_context(
            &responses,
            &expected,
            testset_entry.map(|entry| (entry, input)),
        )?;
        println!("PASS");
    }

    Ok(())
}

fn resolve_manifest_path(manifest_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        manifest_dir.join(path)
    }
}

fn output_file_name(input: &Path) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .context("Test-set input path has no file name")?;
    if input.extension().and_then(|extension| extension.to_str()) == Some("zip") {
        let stem = input
            .file_stem()
            .context("Test-set ZIP input path has no file stem")?;
        Ok(PathBuf::from(format!("{}.json", stem.to_string_lossy())))
    } else {
        Ok(PathBuf::from(file_name))
    }
}

fn load_testset(testset: &Path, outdir: Option<&Path>) -> Result<Vec<ResolvedTestSetEntry>> {
    let manifest_data =
        std::fs::read_to_string(testset).context("Failed to read test-set manifest")?;
    let manifest: TestSetManifest =
        serde_json::from_str(&manifest_data).context("Failed to parse test-set manifest")?;
    if manifest.tests.is_empty() {
        anyhow::bail!("Test-set manifest contains no tests");
    }

    let manifest_dir = testset
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Some(outdir) = outdir {
        std::fs::create_dir_all(outdir).context("Failed to create output directory")?;
    }

    let mut output_paths = HashSet::new();
    manifest
        .tests
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let input = resolve_manifest_path(manifest_dir, &entry.input);
            let expected = resolve_manifest_path(manifest_dir, &entry.expected);
            let output = match entry.out {
                Some(output) => Some(resolve_manifest_path(manifest_dir, &output)),
                None => outdir
                    .map(|outdir| output_file_name(&input).map(|name| outdir.join(name)))
                    .transpose()?,
            };

            if let Some(output) = &output {
                if !output_paths.insert(output.clone()) {
                    anyhow::bail!(
                        "Test-set entry {} reuses output path {}",
                        index + 1,
                        output.display()
                    );
                }
                if output.try_exists().with_context(|| {
                    format!("Failed to inspect output file {}", output.display())
                })? {
                    anyhow::bail!(
                        "Test-set entry {} would overwrite existing output file {}",
                        index + 1,
                        output.display()
                    );
                }
            }

            Ok(ResolvedTestSetEntry {
                input,
                expected,
                output,
            })
        })
        .collect()
}

fn process_vectors_from_testset(
    wrapper_path: &Path,
    param: Option<&str>,
    testset: &Path,
    outdir: Option<&Path>,
) -> Result<()> {
    let entries = load_testset(testset, outdir)?;
    info!(
        "Processing {} vector set(s) from {:?}",
        entries.len(),
        testset
    );

    for (index, entry) in entries.iter().enumerate() {
        process_vectors_from_file(
            wrapper_path,
            param,
            &entry.input,
            entry.output.as_deref(),
            Some(&entry.expected),
            false,
            Some(index + 1),
        )
        .with_context(|| {
            format!(
                "Test-set entry {} (input {}, expected {})",
                index + 1,
                entry.input.display(),
                entry.expected.display()
            )
        })?;
    }

    Ok(())
}

#[cfg(test)]
fn check_expected(actual: &serde_json::Value, expected: &serde_json::Value) -> Result<()> {
    check_expected_with_context(actual, expected, None)
}

fn check_expected_with_context(
    actual: &serde_json::Value,
    expected: &serde_json::Value,
    testset_entry: Option<(usize, &Path)>,
) -> Result<()> {
    // Actual may be a single response object or an array of them (one per vsId).
    // Expected results only carry testGroups; we compare group-by-group.
    let actuals = match actual {
        serde_json::Value::Array(arr) => arr.clone(),
        obj => vec![obj.clone()],
    };
    let expecteds = match expected {
        serde_json::Value::Array(arr) => arr.clone(),
        obj => vec![obj.clone()],
    };

    let mut total = 0usize;
    let mut failures = 0usize;
    let mut tested = 0usize;
    let mut failed_tests = 0usize;
    let mut unsupported = 0usize;

    for (act, exp) in actuals.iter().zip(expecteds.iter()) {
        let act_groups = act["testGroups"]
            .as_array()
            .context("actual response missing testGroups")?;
        let exp_groups = exp["testGroups"]
            .as_array()
            .context("expected results missing testGroups")?;

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

            let mut group_unsupported = 0usize;

            for exp_test in exp_tests {
                let tc_id = exp_test["tcId"]
                    .as_u64()
                    .with_context(|| format!("expected test in group {tg_id} missing tcId"))?;

                // A tcId absent from the actual response means the wrapper
                // replied "unsupported" for it; that marker never makes it
                // into the JSON, so a missing tcId here is how it surfaces.
                let Some(act_test) = act_tests.iter().find(|t| t["tcId"].as_u64() == Some(tc_id))
                else {
                    group_unsupported += 1;
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
                        total += 1;
                        let act_val = &act_test[key];
                        let matches = match (exp_val, act_val) {
                            (serde_json::Value::String(e), serde_json::Value::String(a)) => {
                                e.to_lowercase() == a.to_lowercase()
                            }
                            _ => exp_val == act_val,
                        };
                        if !matches {
                            let source = testset_entry
                                .map(|(entry, input)| {
                                    format!("testset entry={entry} input={}: ", input.display())
                                })
                                .unwrap_or_default();
                            eprintln!(
                                "FAIL {source}tgId={tg_id} tcId={tc_id} field={key}: \
                                 expected={exp_val} actual={act_val}"
                            );
                            failures += 1;
                            test_failed = true;
                        }
                    }
                }

                if test_failed {
                    failed_tests += 1;
                }
            }

            if group_unsupported > 0 {
                eprintln!(
                    "UNSUPPORTED tgId={tg_id}: {group_unsupported} test(s) not present in \
                     actual response"
                );
            }
        }
    }

    let run = tested + unsupported;
    let passed_tests = tested - failed_tests;

    if failures > 0 {
        anyhow::bail!(
            "{run} test(s) run: {passed_tests} passed, {failed_tests} failed \
             ({failures}/{total} field(s) did not match), {unsupported} unsupported by wrapper"
        );
    }
    println!("{run} test(s) run: {passed_tests} passed, {unsupported} unsupported by wrapper");
    Ok(())
}

fn process_vectors_from_directory(
    wrapper_path: &Path,
    param: Option<&str>,
    indir: &PathBuf,
    outdir: &PathBuf,
) -> Result<()> {
    info!("Processing vectors from directory: {:?}", indir);

    std::fs::create_dir_all(outdir).context("Failed to create output directory")?;

    let mut subprocess = Subprocess::new(wrapper_path, param)?;

    for entry in std::fs::read_dir(indir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file()
            && path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext == "json" || ext == "zip")
        {
            let input_data = if path.extension().and_then(|s| s.to_str()) == Some("zip") {
                utils::read_vectors_from_zip(&path)?
            } else {
                std::fs::read_to_string(&path)?
            };

            let test_vectors: serde_json::Value = serde_json::from_str(&input_data)?;
            let responses = subprocess.process_vectors(&test_vectors)?;

            let output_path = outdir.join(
                path.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace(".zip", ".json"),
            );

            std::fs::write(&output_path, serde_json::to_string_pretty(&responses)?)?;
            info!("Processed: {:?} -> {:?}", path, output_path);
        }
    }

    if subprocess.unsupported_count() > 0 {
        println!(
            "{} test(s) reported unsupported by wrapper",
            subprocess.unsupported_count()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_expected;
    use serde_json::json;

    #[test]
    fn missing_actual_tcid_is_treated_as_unsupported_not_a_failure() {
        // tgId 2's tcId 1 is absent from the actual response, as happens
        // when the wrapper replied "unsupported" for it and the entry was
        // dropped rather than written to the output JSON.
        let actual = json!({
            "testGroups": [
                {"tgId": 1, "tests": [{"tcId": 1, "md": "AA"}]},
                {"tgId": 2, "tests": []}
            ]
        });
        let expected = json!({
            "testGroups": [
                {"tgId": 1, "tests": [{"tcId": 1, "md": "aa"}]},
                {"tgId": 2, "tests": [{"tcId": 1, "md": "BB"}]}
            ]
        });

        assert!(check_expected(&actual, &expected).is_ok());
    }

    #[test]
    fn field_mismatch_on_a_present_tcid_still_fails() {
        let actual = json!({
            "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "md": "AA"}]}]
        });
        let expected = json!({
            "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "md": "BB"}]}]
        });

        assert!(check_expected(&actual, &expected).is_err());
    }
}
