# Configuration and grader reference

`evalmesh validate MANIFEST` is the authoritative runtime validation command.
`evalmesh schema manifest|case|run|score|inventory` prints the matching Draft 2020-12 JSON
Schema. Private-policy authorization, case-insensitive reserved-header checks, and
cross-field/privacy rules cannot be expressed fully in the portable schema and are
enforced by `validate`.

`evalmesh monitor INVENTORY` validates a separate private inventory contract and
compiles it into a temporary ordinary v1 suite. See [monitoring.md](monitoring.md).

## Suite manifest

| Field | Required | Contract |
| --- | --- | --- |
| `schema_version` | yes | Integer `1` |
| `subject_id`, `suite_id` | yes | Opaque ID slugs; do not use personal names |
| `case_files` | yes | Unique, explicit relative JSONL paths; no `..` or symlinks |
| `repetitions` | no | Integer 1–100; default 1 |
| `pass_threshold` | no | Finite number 0–1; default 1 |
| `variant` | no | Public-safe opaque version identities; defaults to `id = "default"` |
| `target` | yes | Exactly one target configuration below |
| `privacy` | no | Capture and projection limits |
| `graders` | yes | 1–256 deterministic grader tables |

The manifest and an optional private policy are each limited to 2 MiB.

Common command/Codex target fields include `timeout_seconds`, `max_output_bytes`,
`output_mode = "json"|"text"`, `workspace_mode`, `workspace_path` or
`workspace_path_env`, exact `artifact_paths`, `forward_env`, and `use_host_home`.
Isolation variables such as `HOME`, temporary directories, Python paths, and
`CODEX_HOME` cannot be forwarded. `use_host_home` is private-policy-only.
`forward_env` and `argv` are each limited to 256 entries; argv strings are limited to
4096 characters. HTTP header mappings are limited to 128 entries.

### Command target

```toml
[target]
kind = "command"
argv = ["{python}", "agent.py"]
workspace_mode = "copy"
output_mode = "json"
timeout_seconds = 30
```

The process receives one JSON object on stdin:

```json
{"protocol":"evalmesh.case.v1","case_id":"case-001","input":{}}
```

For JSON mode it may return a normal JSON value, or the strict versioned envelope
below. `output` is required, `metrics` is optional, and unknown envelope fields are
fatal protocol errors:

```json
{"protocol":"evalmesh.result.v1","output":{"answer":"ok"},"metrics":{"quality":0.9}}
```

Empty and non-standard JSON (`NaN`, infinities) are errors. The shell is never used.
Command and Codex targets require a POSIX host in v0.1; unsupported platforms fail
closed with a typed attempt error. Both process target kinds require the explicit
`workspace_mode = "copy"`; the manifest, private policy, and case files are excluded
from that copy by loaded path and file identity. A changed loaded-private path aborts
the attempt before target execution.

### HTTP target

```toml
[target]
kind = "http"
url_env = "MY_AGENT_URL"
method = "POST"
output_mode = "json"

[target.headers_from_env]
X-Eval-Key = "MY_AGENT_AUTH"
```

The request body is the same case envelope and never contains expected answers.
URLs use a lowercase ASCII `http://` or `https://` scheme, valid percent escapes, and
cannot contain credentials, query strings, or fragments. Non-loopback HTTP must use
TLS. Header values from the environment must be bounded visible ASCII without
leading/trailing spaces. Redirects and ambient proxies are not used; response capture
is bounded.

### Codex target

Optional `model` selects the actual Codex model; optional `reasoning_effort`
requires an explicit model. `evalmesh run --model MODEL_ID --reasoning-effort high`
overrides these fields for one run. Neither field is accepted for command/HTTP
targets. The requested settings appear in the public variant along with a
loader-generated `execution_id`; a handwritten `variant.model_id` alone remains
only a label. See [multi-project experiments](experiments.md) for model matrices,
registries, creation templates, execution limits, and resume.

```toml
[target]
kind = "codex"
workspace_mode = "copy"
workspace_path = "fixtures/repository"
artifact_paths = ["result.md"]
output_mode = "text"
sandbox = "workspace-write"
skip_git_repo_check = true
skill = "demo-skill"
```

Codex runs as `codex exec - --ephemeral --json` with an explicit sandbox; the prompt
travels over stdin. `workspace_mode = "copy"` is mandatory. Existing Codex login
access requires private-policy `use_host_codex_auth = true`. Because the copy excludes
`.git`, `skip_git_repo_check = true` is also mandatory; see the integration guide.
For text-mode targets with declared artifacts, a completed turn may omit a prose
reply: the captured files are still independently graded. Missing completion,
execution errors, timeouts and missing/incorrect required files remain failures.

## Cases

Every non-empty JSONL row requires `id`, `input`, and object `expected`. Optional
`grader_ids` selects graders for that case and `tags` supplies opaque labels. IDs and
tags must be unique within their arrays. Each file is limited to 16 MiB and 10,000
lines, each row to 1 MiB, and the full suite to 64 MiB and 10,000 non-empty records.

Optional `dimensions` is a strict object whose supported fields are `task_type`,
`risk_level`, `domain`, `source`, `difficulty`, and `lifecycle`. Values are opaque
public-safe identifiers. EvalMesh does not assign domain meaning to them, except that
analytics treats `risk_level = "critical"` as a critical release slice.

Optional `[variant]` requires `id` and accepts `application_id`, `model_id`,
`prompt_id`, `toolset_id`, and `knowledge_id`. These values identify a candidate
without publishing a raw prompt, endpoint, path, or credential. Variant identity is
reported with each run but is deliberately excluded from `suite_digest`, allowing
two variants to be compared against the same suite contract.

## Graders

All graders accept `id`, `kind`, optional `threshold` (0–1), positive `weight`, and
boolean `required`.

| Kind | Configuration | Result |
| --- | --- | --- |
| `exit_code` | optional integer `expected` (default 0) | exact process exit; when active, this grader owns exit-code acceptance |
| `json_equals` | optional `actual_path` | type-strict JSON equality with case expected |
| `contains` | optional `actual_path`, `value`, `case_sensitive` | string containment; uses case expected when `value` is absent |
| `regex` | required `pattern` (max 512 chars); optional `actual_path`, `flags` (`i`, `m`, `s`) | isolated regex match with a one-second hard timeout |
| `metric_threshold` | required `metric` and at least one of `min`, `max` | 0/1 threshold score |
| `precomputed_score` | required `metric` | finite target score in [0,1] |
| `latency` | required non-negative `max_ms` | total target-duration check |
| `file_exists` | required declared artifact `path` | regular-file existence |
| `file_contains` | required declared `path`; optional `value`, `case_sensitive` | bounded UTF-8 artifact containment |
| `file_json_equals` | required declared `path`; optional `actual_path` | type-strict artifact JSON equality |

Every file-grader path must also appear in `target.artifact_paths`. JSON paths may be
dot-separated object keys or RFC 6901-style `/pointer` paths. Each artifact capture is
bounded by `target.max_output_bytes`, with a 64 MiB aggregate in-memory capture cap
across all declared artifacts.

When a target result is unavailable because execution timed out or produced a fatal
protocol/transport error, selected graders are published as `error` with
`target_result_unavailable`; no passing per-grader feedback is retained.

## Privacy and reporting

`privacy.capture = "digest"` is the default. `redacted` is allowed only when set by an
ignored `*.local.toml` or `*.private.toml` policy and paired with `--allow-content`.
`include_metrics` publishes only metric names explicitly referenced by metric graders.
`include_timing = false` replaces both timestamps with the Unix epoch and duration
with zero. The HMAC environment variable can never be forwarded to a target.
Its raw, hex, and common base64 forms are also rejected from target-delivered case
strings/configuration, copied fixture names/content, reportable identifiers, and
reporter operation secrets. Reporter credentials are checked in the other direction
as well. These collision checks are defense in depth, not a general decoder for every
possible transformed secret.

Reporter names are `console`, `jsonl`, and `opik`. Opik requires JSONL. The runner
orders a durable local reporter first, syncs the file, and skips remote delivery if
the local receipt fails. `--allow-content-remote` is a separate opt-in and requires
redacted capture.

JSONL append is locked and newline-delimited. A successful receipt requires file and
directory sync plus inode/size checks through a fresh walk of the configured path.
Partial writes are rolled back before retry; an unconfirmed rollback latches the
reporter closed. This protects normal crashes and detected path races, not later
deletion or replacement by a hostile process with the same OS account.

Every custom reporter must expose immutable tuple declarations for redaction secrets,
credentials, and reportable routing values; use explicit empty tuples when a class has
none. A custom remote reporter must also expose an exact credential-free
`public_projection(run)`. The projection must be an ordinary JSON object with string
keys throughout—lossy key coercion is rejected. `Runner` snapshots capability flags
and the projection callable, checks the projection immediately before delivery, and
still treats the reporter's Python implementation as trusted code.
