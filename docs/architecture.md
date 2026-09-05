# Architecture

EvalMesh is a small orchestration layer around replaceable execution and storage
components:

```text
versioned cases -> Adapter -> RawExecutionResult -> deterministic Graders
                                      |                    |
                                      +-> PrivacyGateway <-+
                                                |
                                           PublicRun
                                                |
                         Console / private JSONL / Opik Reporter
```

## Ownership

- The subject repository owns its fixtures, domain assertions, and invocation entry
  point.
- EvalMesh owns the versioned case/run/score contract, repetitions, privacy gateway,
  and reporter interface.
- Domain systems remain authoritative for domain metrics. They compute their own
  scoring and calibration values; EvalMesh consumes them.
- Opik owns trace storage and the dashboard. OpenTelemetry/OpenInference can be used
  as an independent runtime trace source without changing score reporting.

Real Agent execution tracing is a second, explicit data plane:

```text
runtime prompt/tool events -> Runtime trace projection -> private JSONL -> Opik
```

It does not overload `Reporter` or turn raw execution data into `PublicRun`. Runtime
content is admitted only by an untracked mode-0600 policy outside Git and is bounded
and redacted before local-first delivery. See
[Private runtime tracing](runtime-tracing.md).

## Stable identities

`subject_id`, `suite_id`, grader `id`, and case `id` are safe opaque slugs. They are
always reportable metadata and must not contain names or private content. A run adds a
random run ID and one-indexed attempt number.

## Adapter protocol

Command targets receive one JSON object on stdin:

```json
{"protocol":"evalmesh.case.v1","case_id":"case-001","input":{}}
```

A normal JSON response becomes the result output. A target may return the explicit
envelope below to attach domain metrics. In this version, `output` is required,
`metrics` is optional, and no other envelope fields are accepted:

```json
{
  "protocol": "evalmesh.result.v1",
  "output": {"answer": "ok"},
  "metrics": {"domain_score": 0.9}
}
```

Expected values are kept inside the grader process and are never present in the
target payload. For command/Codex targets, the copied workspace also excludes the
manifest and every case file, so expected answers are not available through the
default working directory. EvalMesh records their file identities when loading and
revalidates their original paths before each attempt; the copier excludes both those
paths and those identities to fail closed across rename or replacement races.

## Skill fixtures

Codex targets should use `workspace_mode = "copy"` with a small synthetic fixture.
The workspace is copied to a mode-0700 temporary directory, evaluated there, and
deleted. Exact declared artifact paths are captured in memory for file graders.
EvalMesh neither runs package-install hooks nor copies symlinks. The copy is capped at
20,000 traversed entries and 256 MiB, and its names/content are streamed through the
protected-key collision check before target execution.

The copy is a data-minimization boundary, not an OS sandbox. A hostile target can use
absolute host paths or its available network. Custom in-process adapters, graders,
reporters, and plugins are trusted computing-base components; use process/container
isolation for code that is not trusted.

## Backend neutrality

The core package has no Opik imports. `OpikReporter` sends the same immutable
`PublicRun` projection to an optional, short-lived SDK subprocess. The subprocess has
a sanitized environment, fresh home/cwd, disabled telemetry/logging and redirects,
and explicit flush/data-loss checks. This prevents the central platform from becoming
the domain model or ambient SDK configuration from entering the core process.

Report delivery is local-first. The runner canonically orders a durable local JSONL
reporter before remote reporters, transactionally appends and syncs each complete
line, revalidates the configured directory/file identity, and skips Opik for that
attempt unless the local receipt succeeds. Reporter failures never alter finalized
scores, but they make the CLI return configuration/reporting exit code 2.

All reporters explicitly declare credential/redaction values and reportable routing
values, including empty declarations. Remote reporters also declare the exact
credential-free projection they intend to send. The runner snapshots this contract,
requires a strict string-keyed JSON object, and scans the projection before every
call. This is an accidental-leak guard, not isolation from malicious reporter code.

Fatal target results cannot retain apparently passing grader feedback. The same
authoritative unavailable-score reconstruction runs inside `PrivacyGateway`, so
direct factory use cannot bypass the rule.
