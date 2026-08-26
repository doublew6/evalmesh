# EvalMesh

EvalMesh is a privacy-first evaluation harness for agents, automations, and
skills. It runs repeatable black-box cases, applies deterministic graders, and sends
sanitized results to local JSONL and, optionally, Opik.

It deliberately does **not** build another observability database or dashboard.
Opik can provide the central UI; EvalMesh owns the missing execution contract:
which subject to invoke, which fixture to use, what counts as passing, and what may
leave the machine.

## What v0.1 covers

- Command, HTTP, and non-interactive Codex targets.
- Repeated cases for stability measurement.
- Exact, contains, regex, process, latency, metric, and file-artifact graders.
- Temporary copied workspaces for non-destructive Skill evaluation.
- Transactional local JSONL history with private file permissions.
- Optional Opik reporting through the public Python SDK in a sanitized worker.
- Default metadata-only capture, HMAC content identifiers, and a repository leak
  scanner.

Codex task scheduling remains owned by Codex or the host scheduler. A scheduled task
calls `evalmesh run`; EvalMesh records and grades the result.

## Quick start

EvalMesh v0.1 requires Python 3.11 or newer on macOS or another POSIX host for
command/Codex process isolation. From a source checkout, select an interpreter
explicitly and verify it before creating the environment. The core has no runtime
dependencies:

```bash
python3.11 --version
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
evalmesh validate examples/echo/evalmesh.toml
evalmesh run examples/echo/evalmesh.toml
```

The default run stores only content-free metadata in `.evalmesh/runs.jsonl` and
prints a summary. The synthetic echo example never calls a model or external API.

## Manifest

```toml
schema_version = 1
subject_id = "sample-agent"
suite_id = "smoke"
case_files = ["cases.jsonl"]
repetitions = 2
pass_threshold = 1.0

[target]
kind = "command"
argv = ["{python}", "agent.py"]
workspace_mode = "copy"
output_mode = "json"

[[graders]]
id = "answer_matches"
kind = "json_equals"
actual_path = "answer"
```

Each JSONL case gives a case-specific expected value to graders that need one:

```json
{"id":"case-001","input":{"question":"2 + 2"},"expected":{"answer_matches":4}}
```

Expected values are never sent to the target. Process targets run from a temporary
copy that excludes the manifest, case files, VCS metadata, and known credential
files/directories. Loaded private files are tracked by both logical path and file
identity, so renaming one after validation cannot make it enter the copy. Case files
must be explicit relative paths below the manifest
directory; symlinks and duplicate IDs are rejected. Manifests, case suites, target
output, copied workspaces, environment/argument declarations, leak scans, and public
projections all have explicit size/count limits.

See the [configuration and grader reference](docs/reference.md),
[architecture guide](docs/architecture.md), [privacy model](docs/privacy.md), and
[integration recipes](docs/integrations.md) for the complete source contract.

## Opik on a private host

Install the optional reporter with `python -m pip install -e '.[opik]'` and self-host
Opik using its official deployment instructions. If EvalMesh and Opik run on the same
host, use the loopback API endpoint:

```bash
export EVALMESH_OPIK_URL=http://127.0.0.1:5173/api
evalmesh run path/to/evalmesh.toml --reporter console,jsonl,opik
```

EvalMesh refuses to fall back to an SDK or cloud default when the endpoint is absent.
If Opik runs on a different private host, use an authenticated `https://` endpoint and
add `--allow-remote-opik`; plain non-loopback HTTP is rejected. In both topologies,
Opik runs only after the local JSONL fact has been synced successfully. The
self-contained reporter worker receives only the projected `PublicRun` fields and
explicit Opik credentials over stdin; it uses a fresh home/cwd, disables SDK Sentry
and console logs, ignores ambient proxies/configuration, rejects redirects, and
checks both flush status and sender-wide data-loss counters. The
self-hosted dashboard and its backups still contain evaluation metadata and must be
treated as private. See the [official Opik self-host overview](https://www.comet.com/docs/opik/self-host/overview).

That local-first ordering is a `Runner`/CLI guarantee. Library callers must pass
remote reporters to `Runner`; calling `OpikReporter.report()` directly bypasses the
durable-local receipt gate.

## Privacy boundary

Default capture is `digest`, but content fingerprints are emitted only when
`EVALMESH_HMAC_KEY` is set. EvalMesh never emits a bare content SHA-256 because
low-entropy diary text and prompts can be guessed offline. Without a key it emits a
random content ID instead.

With a valid HMAC key, `suite_digest` is also a keyed digest of the full merged suite
contract and cases. Without a key it is deliberately only a content-free structural
digest, so private low-entropy case changes are not fingerprinted.

HMAC material, target-visible environment values, reporter credentials/endpoints,
and host identity strings are separate security domains. EvalMesh rejects raw, hex,
or common base64 collisions across exact target wire payloads, copied fixture
paths/content, public identifiers, and remote reporter projections. Use independent
random values; do not reuse an agent credential as the HMAC key or in a target.

`redacted` capture is available only through an untracked `*.local.toml` policy plus
`--allow-content`. Sending redacted content to Opik requires a second
`--allow-content-remote` flag. Redaction is best effort, not anonymization.

EvalMesh is an execution harness, not a security sandbox. A target can still read
host files by absolute path or use the network available to its OS account. Custom
in-process code is trusted and can bypass the `PublicRun` boundary. Run hostile
targets or untrusted extensions inside a separate account, container, or VM. See
[docs/privacy.md](docs/privacy.md) before connecting personal data.

## Project status

This is an alpha contract-first MVP. The versioned manifests and public run/score
schemas are the supported contracts. `Reporter` is the current injection point;
`Adapter` and `Grader` are public typing protocols but `Runner` v0.1 constructs its
built-ins and does not expose dependency injection for them. CLI exit codes are `0`
for an evaluation pass, `1` for an evaluation failure, and `2` for configuration or
reporting failure. Contributions must use synthetic fixtures and are licensed under
Apache-2.0.
