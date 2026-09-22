# Test-Set Manifests (`--testset`)

`--testset` runs a whole batch of vector sets in one invocation, verifying each
one against its own expected-results file. It is the batch equivalent of
`--in`/`--out`/`--expected`, driven by a small JSON manifest instead of by
command-line arguments.

```bash
katwalk \
  --wrapper ./target/release/fips202_wrapper \
  --testset /path/to/fips202-testset.json \
  --outdir  /tmp/fips202-responses
```

## When to use it

| Mode | Verifies results? | Input selection |
|---|---|---|
| `--in` / `--out` | Only with `--expected` | One file |
| `--indir` / `--outdir` | No | Every `.json`/`.zip` in a directory |
| `--testset` | **Always** | Explicit list, with per-entry expected results |

Use `--indir` to *generate* responses for a directory of prompts, and
`--testset` to *validate* a curated set of known-answer tests — for example as a
regression suite in CI, where each prompt is paired with its expected results
and the process exit code is the pass/fail signal.

## Manifest format

The manifest is a JSON object with a single required key, `tests`, holding a
non-empty array of entries:

```json
{
  "tests": [
    {
      "in": "SHA3-256/prompt.json",
      "expected": "SHA3-256/expectedResults.json"
    },
    {
      "in": "SHAKE-128/prompt.json",
      "expected": "SHAKE-128/expectedResults.json",
      "out": "responses/shake-128.json"
    }
  ]
}
```

### Entry keys

| Key | Required | Description |
|---|---|---|
| `in` | yes | Vector-set prompt file. Either a `.json` file or a `.zip` archive (all JSON members of the archive are concatenated into one array, as with `--in`). |
| `expected` | yes | Expected-results JSON for this vector set. Verification is not optional in this mode. |
| `out` | no | Where to write this entry's responses. Overrides `--outdir` for the entry. |

The schema is strict: any other key is a hard error, so a typo fails loudly
rather than being silently ignored.

```
Error: Failed to parse test-set manifest

Caused by:
    unknown field `output`, expected one of `in`, `expected`, `out` at line 1 column 81
```

### Path resolution

Relative paths are resolved **against the directory katwalk was started from**
— the working directory is the root for everything the manifest names. The
manifest's own location is irrelevant: it can sit anywhere, including outside
that directory, and is only read for its contents. Absolute paths are used
as-is.

This is deliberate, and it is what makes a source-tree manifest usable against
a build tree. A manifest checked in at `src/mlkem/test/acvp/katwalk.json` can
name vectors that only exist under the build directory:

```json
{
  "tests": [
    {
      "in": "KAT/vectors/acvp/FIPS-203/keyGen/prompt.json",
      "expected": "KAT/vectors/acvp/FIPS-203/keyGen/expectedResults.json"
    }
  ]
}
```

```bash
cd out/build/host
./acvptool/katwalk \
  --wrapper src/mlkem/test/acvp/mlkem-acvp-be \
  --testset ../../../src/mlkem/test/acvp/katwalk.json
```

Both `in` paths resolve under `out/build/host`, where the vectors were
staged — not under `src/mlkem/test/acvp`, where the manifest lives. For a CMake
test, set the working directory accordingly (`WORKING_DIRECTORY
${CMAKE_BINARY_DIR}`) and the manifest needs no build-dir paths in it at all.

## Where responses go

Response files are optional in this mode — verification happens either way.
For each entry, the output path is decided as follows:

1. The entry's `out`, if present.
2. Otherwise, if `--outdir` was given: `<outdir>/<input file name>`. A `.zip`
   input contributes its stem plus a `.json` extension, so
   `vectors/ML-KEM-keyGen.zip` becomes `<outdir>/ML-KEM-keyGen.json`.
3. Otherwise, no response file is written at all — the entry is run and
   verified in memory.

`--outdir` is created if it does not exist. Directories named by an entry's
`out` are **not** created for you; write the entry's `out` into a directory that
already exists (or one that `--outdir` created), or the entry fails with
`Failed to create output file`. Like `in` and `expected`, a relative `out` is
interpreted from the working directory.

### Output paths are never overwritten

Unlike `--in`/`--out`, which overwrites its output file, test-set mode refuses
to clobber anything. Before the wrapper is spawned at all, every resolved output
path is checked:

- Two entries resolving to the same path is an error
  (`Test-set entry 2 reuses output path …`). This is easy to hit with
  `--outdir` when two prompts in different directories share a file name, such
  as several `prompt.json` files; give those entries an explicit `out`.
- An output path that already exists is an error
  (`Test-set entry 1 would overwrite existing output file …`).

Because these checks run up front, a manifest with a bad output path fails
before any test is executed. Point `--outdir` at a fresh directory on each run,
or clear it in between.

## Execution and reporting

Entries run sequentially in manifest order, each in its own freshly spawned
wrapper process, so one vector set cannot leave state behind for the next. A
failing entry aborts the run — later entries are not attempted.

Each entry prints a one-line summary and `PASS`:

```
1 test(s) run: 1 passed, 0 unsupported by wrapper
PASS
```

Test cases the wrapper reports as unsupported are counted separately and do not
fail the run: a `tcId` present in the expected results but absent from the
wrapper's response is treated as unsupported rather than as a mismatch.

On a mismatch, every differing field is printed to stderr — prefixed, in this
mode, with the manifest entry number and input path so you can tell which
vector set failed — and the process exits non-zero:

```
FAIL testset entry=1 input=ts/vectors/prompt.json: tgId=1 tcId=1 field=md: expected="00" actual="A7FFC6F8..."
Error: Test-set entry 1 (input ts/vectors/prompt.json, expected ts/vectors/bad-expected.json)

Caused by:
    1 test(s) run: 0 passed, 1 failed (1/1 field(s) did not match), 0 unsupported by wrapper
```

String comparisons are case-insensitive, so a wrapper emitting upper-case hex
matches lower-case expected values.

## Combining with other flags

`--testset` is mutually exclusive with `--regcap`, `--in`, `--out`, `--indir`,
`--expected`, `--run` and `--fetch`; passing any of them alongside it is a usage
error. The flags that do apply are:

| Flag | Effect with `--testset` |
|---|---|
| `--wrapper <path>` | The wrapper under test (required, as always) |
| `--outdir <dir>` | Default output directory for entries without `out` |
| `--param <string>` | Forwarded to each wrapper process |
