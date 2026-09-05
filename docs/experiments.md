# Multi-project Codex evaluations

EvalMesh provides one CLI entry point for several projects' evaluation suites. A
private registry locates each project's manifests and defines reusable Codex model
profiles. An experiment selects projects and profiles, expands their suites into
a matrix, and compares profiles within each project/suite.

The core remains dependency-free. JSONL storage is mandatory; Opik is optional.
Real project paths, cases, credentials and policies belong in the subject project
or an external private evaluation directory, not in EvalMesh's source checkout.

If the CLI is not installed yet, run from the source checkout by replacing
`evalmesh` below with `PYTHONPATH=src python3.11 -m evalmesh`.

## Create a suite

From the directory where you keep evaluations:

```bash
evalmesh init evaluation-a --subject-id subject-a
```

The destination must be new. This creates:

```text
evaluation-a/
  evalmesh.toml         # Subject, suite and independent artifact graders
  cases.jsonl          # Two synthetic tasks with expected values
  fixture/README.md    # Initial workspace, copied separately for every attempt
  registry.toml        # Project registrations and model profiles
  experiment.toml      # Matrix and execution limits
  codex.private.toml   # Optional host login policy, ignored by Git
  .gitignore
  README.md
```

The starter asks Codex to produce a JSON file; EvalMesh reads and grades that file
independently. Replace the two sample tasks with representative tasks and expected
outcomes. Expected answers and case files stay outside the copied workspace.
Use task dimensions such as `task_type`, `difficulty`, and `risk_level` to inspect
weak areas. Start with a small smoke suite, then add regressions and a separately
held-out suite.

The starter's `model-a` and `model-b` are placeholders, not account discoveries.
Replace them with models available to your Codex CLI before execution. For an
existing Codex login, explicitly enable the commented `policy` reference in the
registry. The generated private policy grants access to Codex authentication;
`--ignore-user-config` remains enabled.

## Register projects and model profiles

Registry paths are relative to the registry file, regardless of the invoking
shell's directory. Absolute paths and parent-directory references are also allowed
in this private registry. Each suite's case/fixture paths remain relative to its
own manifest. Symlinks and duplicate project/suite identities are rejected.

```toml
schema_version = 1

[[projects]]
id = "subject-a"
manifests = ["evaluation-a/evalmesh.toml"]
policy = "evaluation-a/codex.private.toml"

[[projects]]
id = "subject-b"
manifests = ["evaluation-b/smoke.toml", "evaluation-b/regression.toml"]
policy = "evaluation-b/codex.private.toml"

[[profiles]]
id = "candidate-a"
model = "model-a"
reasoning_effort = "high"

[[profiles]]
id = "candidate-b"
model = "model-b"
reasoning_effort = "high"
```

Every project ID must equal the `subject_id` of its manifests. All registered
targets selected by an experiment must be Codex targets. By default, selected
projects run all registered suites. An experiment can select a subset with
`suites = { subject-a = ["smoke"], subject-b = ["regression"] }`. Omitted projects
use all their registered suites. Unknown or duplicate selections are rejected.
Changing the expanded matrix requires a new experiment output directory.

Profiles override the suite's root Codex model and reasoning effort. They become
`variant.id`, `variant.model_id`, and `variant.reasoning_effort` in every public
run and summary. The existing application/prompt/toolset/knowledge identities are
preserved. These are **requested settings**, not a server attestation of the
resolved model. Unsupported model/effort combinations produce execution failures;
EvalMesh never substitutes another model. Nested agents or external model calls
need their own fixed configuration in the evaluated project.

Supported effort spellings are `none`, `minimal`, `low`, `medium`, `high`, `xhigh`,
`max`, and `ultra`; individual models may accept only a subset. Models use bounded
identifier slugs. Provider routing and arbitrary Codex configuration overrides are
outside this first experiment contract.

For an individual suite, the same model selection is available directly:

```bash
evalmesh run evaluation-a/evalmesh.toml --model MODEL_ID --reasoning-effort high
```

Or declare `model` and `reasoning_effort` in `[target]`. EvalMesh passes them as
`--model` and `-c 'model_reasoning_effort="high"'`. A reasoning effort requires an
explicit model. With no model selection, legacy single-suite execution retains
Codex's default model behavior; an experiment always specifies both settings.

## Plan and execute

```toml
schema_version = 1
registry = "registry.toml"
projects = ["subject-a", "subject-b"]
profiles = ["candidate-a", "candidate-b"]
baseline = "candidate-a"
repetitions = 3
max_workers = 1
max_attempts = 120
dispatch_timeout_seconds = 3600
```

For two projects with ten cases each, two profiles and three repetitions, the
plan contains 120 attempts. `max_attempts` is required and is checked before
starting any models. A matrix is bounded to 256 jobs, 10,000 attempts, and 256 MiB
of loaded private suite files across profile copies. Each job is one complete
subject/suite/profile batch. Workers run independent batches; attempts within a
batch remain serial. Default concurrency is one, with an upper limit of eight.

```bash
evalmesh experiment plan experiment.toml
evalmesh experiment plan experiment.toml --format json
```

Planning never invokes Codex. Without a key it provides a structural preview.
Execution requires a persistent, independent `EVALMESH_HMAC_KEY` of at least
32 UTF-8 bytes, supplied through the environment. Generate it once using a secure
random source and retain it in your private secret manager; do not reuse an agent
or reporter credential. EvalMesh never reads an `.env` file. All selected suites
must use the standard HMAC variable and digest-only capture.

With that key available, planning also copies and fingerprints initial workspaces
and checks the executable's availability. Execution freezes the case objects and
validates each fresh workspace copy against its keyed fingerprint. An observed
runtime file identity/size/modification-time change or a declared environment
change also blocks execution. This is local reproducibility checking, not a
hermetic container: installed dependencies and remote tools still need to be
versioned by the project. Nothing runs in the original project workspace.

```bash
evalmesh experiment run experiment.toml --output .evalmesh/experiment-001
evalmesh experiment report .evalmesh/experiment-001
evalmesh experiment report .evalmesh/experiment-001 --format json
```

Execution calls real models and consumes account usage. Progress goes to stderr;
`--format json` keeps stdout machine-readable. Choose an empty output directory.
`dispatch_timeout_seconds` stops dispatching new batches after the deadline;
already-started batches finish under their individual target timeouts. This is
not a hard wall-clock kill or a token/dollar budget.

Use `--reporter jsonl,opik` to deliver the same projected public runs to the
existing optional reporter. Its explicit endpoint, TLS/remote opt-in and durable
local-first delivery rules remain unchanged. Reporter configuration is checked
before any model runs. No raw-result reporter or central raw-input store is added.

## Results and resume

The output directory contains private, mode-0600 files:

- `journal.jsonl`: a chained HMAC-authenticated plan and checkpoints.
- `runs-NNNNNN.jsonl`: original `PublicRun` records for each started batch.
- `summary-NNNNNN.json`: completed public summaries, also readable by `compare` and `gate`.
- `lock`: prevents concurrent runners/report readers from using that directory.

Reports show project/suite/profile results, pass@1, stable-pass@k, critical
failures, latency distributions, errors, and token usage when reported by Codex.
Missing usage remains missing; no dollar cost is invented. Baseline comparisons
are made within each subject/suite. There is no pooled cross-project score.
Completed batches can contain target failures. The report displays error and
timeout rates separately from pass rates; `had_execution_errors` includes those
target failures as well as failed batch execution. A failed attempt caused by
infrastructure must not be interpreted as evidence that the model answered wrong.

```bash
evalmesh experiment run experiment.toml --output .evalmesh/experiment-001 --resume
```

Resume verifies the journal and completed summaries with the same privacy key.
It skips all completed batches, including batches with failing evaluations.
An interrupted or errored batch is retried as a whole, with fresh run IDs. Its
previous partial run records remain on disk; they are not counted as a completed
summary. Budget reservation happens durably **before** dispatch, so uncertain
attempts still consume the previous batch's full reservation. Increase
`max_attempts` explicitly if retries would exceed the remaining budget. The budget
always includes earlier reservations in that output directory.

Only worker count, attempt budget and dispatch timeout may change on resume.
Changes to selected subjects/suites/profiles, cases, grader rules, repetitions,
fixtures, declared environment, observed runtime or execution settings require
a new experiment. A saved result with failed remote delivery is retained and
returns reporting failure; resume does not rerun paid work to replay a reporter.

Exit codes: `0` means complete and all evaluations passed, `1` means a complete
experiment contains failed evaluations, and `2` means incomplete execution,
configuration failure or reporting failure. Error jobs expose a fixed reason code,
not private subprocess/parser exception messages.

## Fingerprint migration

The current loader uses `evalmesh.suite.v2` **digest semantics**, while the manifest
and run schema versions remain v1. The keyed suite digest covers cases, grader
rules, subject/suite identity, repetitions and pass threshold. It excludes the
target/model and privacy configuration. `variant.execution_id` separately
identifies execution configuration; with a key it also covers declared environment
and, for pinned experiments, fixture/runtime fingerprints. Without a key, both
identities are deliberately structural and do not fingerprint private content.

Previously captured suite digests differ under this definition. Capture fresh
baselines when upgrading; old summaries remain readable, but comparisons correctly
mark their differing suite digest as incomparable. Do not mix old baselines with
new experiment results and interpret that difference as a model regression.

Print the portable input/output contracts with `evalmesh schema registry`,
`experiment`, `experiment-plan`, and `experiment-result`.

The first version supplies file-based suite authoring, deterministic/artifact
grading and a CLI matrix. Automatic question generation, an independent
post-execution test-command grader, LLM judges, GUI editing, provider-wide model
discovery, and token/cost enforcement remain future extensions.
