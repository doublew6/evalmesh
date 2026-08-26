# Privacy and threat model

EvalMesh assumes cases and outputs may include diaries, prompts, tool arguments,
financial research, repository content, and credentials.

## Defaults

- Raw case inputs and expected values remain in memory for as long as the loaded
  suite, `Runner`, or `PrivacyGateway` is referenced. A raw target result is retained
  only through grading and public projection. Built-in reporters accept neither raw
  domain, and built-in persistence stores only `PublicRun`.
- The subprocess receives a temporary `HOME` and `TMPDIR`, a small baseline
  environment, and only explicitly forwarded variables.
- `.env`, the complete parent environment, SSH agent variables, proxy settings,
  `OTEL_*`, and Opik auto-instrumentation settings are not inherited.
- Normal reporters accept `PublicRun` only. It contains no free-form exception or
  grader rationale.
- Command and Codex targets always use a mode-0700 copied workspace. The copier
  excludes the manifest, every declared case file, symlinks, VCS metadata, and
  known credential files/directories; it also enforces entry/byte limits and scans
  fixture names/content for protected raw/hex/base64 key material.
- Newly created JSONL directories are mode 0700 and files mode 0600 where the OS
  supports it. Locked appends, rollback, inode/path revalidation, and file/directory
  sync must all succeed before remote reporting.
- Absolute paths, hostnames, usernames, IPs, endpoints, argv values, and Git remotes
  are not report fields.

## Capture modes

`digest` is the default. It records byte counts and either an HMAC-SHA256 content ID
or a random ID. The HMAC key comes from an explicitly named environment variable and
is never persisted or forwarded to a target. With a valid key, the suite contract
digest is also keyed and covers private case content; without one it covers only a
content-free structural allowlist.

The HMAC key, target-visible environment (including baseline `PATH`), reporter
credentials/endpoints, and host identity values must be independent. Before
execution, EvalMesh rejects raw, hex, and common base64 collisions across the exact
command/HTTP/Codex wire representation, copied fixture relative paths/content,
public identifiers, reporter routing values, and reporter projections. The gateway
also checks the final serialized `PublicRun`, including declared short secrets that
reappear as JSON scalar content. This protects the supported paths from accidental
key reuse; it cannot recognize arbitrary encryption, compression, splitting, or
custom encodings.

Reporter trust decisions and the remote projection callable are snapshotted by
`Runner`; later changes to an extension's `remote`, `durable`, or projection attribute
cannot change the local-first gate. The built-in Opik reporter freezes its validated
endpoint, credential, routing, and content-consent fields. Endpoint, API key, and
routing material must also be mutually distinct.

`redacted` retains limited, recursively scrubbed content. It always removes structured
secret/token fields and common credential, private-key, email, URL-credential, and
absolute-path patterns. It cannot reliably remove names, addresses, encoded secrets,
or semantic personal information. It is not anonymization.

Raw/full capture is intentionally absent from v0.1. Use the subject's own local logs
when a case requires raw inspection.

## Metadata is still data

IDs, tags, score names and values, token counts, timings, model labels, redacted
artifact paths, and failure patterns may still be sensitive. Use opaque IDs, short
retention, and a private dashboard. Content deletion does not erase offline SDK
queues, backups, swap, or copied bundles.

Set `privacy.include_timing = false` to replace both wall-clock timestamps with the
Unix epoch and duration with zero. This removes run-time correlation fields, but IDs,
attempt order, and report arrival time may still reveal sequence.

Target metadata is not a free-form escape hatch: only HTTP status, a fixed set of
Codex event counters, and fixed numeric token-usage keys cross the gateway. Metric
names are published only when an explicit metric grader references them.

## Execution boundary

Temporary workspaces, `HOME`, and environment filtering reduce accidental leakage;
they do not confine the process. Evaluated code can read any host file by absolute
path and reach any network allowed to the OS account. Use a separate account,
container, or VM for untrusted targets, skills, pull requests, or dependencies.
Secrets passed to a trusted target should be low privilege and short lived.

Manifest, private-policy, and case files are bound to their loaded identities. Their
configured paths are rechecked before each attempt, while copied-workspace traversal
excludes both the paths and the identities. This prevents a post-load rename from
turning a private evaluation file into an ordinary copied fixture.

All Python code loaded into the EvalMesh process is part of the trusted computing
base. A malicious custom `Adapter`, `Grader`, `Reporter`, or plugin can inspect Python
frames, read raw objects or files, and open its own network connection. The typed
Raw-to-`PublicRun` factory and reporter protocol prevent accidental boundary crossing;
they are not isolation against hostile in-process code. Put untrusted extensions in
an OS sandbox and expose only a narrow process protocol.

Expected public errors use fixed messages and discard parser/path exception causes,
so normal formatted tracebacks do not echo case content or endpoints. Python
traceback objects still retain live frame locals such as function arguments. Do not
enable traceback-local capture in Sentry, Rich, IDE telemetry, or similar tooling on
processes handling private suites; treat any crash dump as private.

EvalMesh terminates the POSIX process group it starts, but a malicious target can
escape that group by creating a new session. Process-tree containment requires an OS
account, container, VM, or service manager; it is not claimed by the v0.1 harness.

`use_host_codex_auth` and `use_host_home` require an ignored private policy. Prefer
the Codex-specific option: it exposes the authentication directory to the trusted
Codex executable while `--ignore-user-config` remains enabled.

An Agent's own Opik/OpenTelemetry exporter can bypass EvalMesh entirely. Disable
automatic instrumentation in the target and route reporting through the privacy
gateway.

## Opik

EvalMesh requires an explicit Opik endpoint and does not call global SDK configure.
The parent process never imports Opik. Each report starts a short-lived SDK worker
with a fresh home and cwd, no inherited proxy or Opik configuration, Sentry and SDK
console logging disabled before import, redirects disabled, and only projected fields
plus explicit credentials on stdin. A report succeeds only when flush/end succeed and
the sender-wide error report shows zero dropped messages/items.

Local-first delivery is enforced by `Runner` and the CLI, which require a successful
durable JSONL receipt before invoking a remote reporter. Do not call
`OpikReporter.report()` directly when that guarantee is required; the low-level
reporter method has no local-receipt capability.
The open-source self-hosted service should not be directly exposed to a LAN or the
public internet. Bind it to loopback/private networking or place it behind an
authenticated proxy. Disable anonymous usage reporting, protect data volumes, and
treat offline queues and backups as sensitive.

## Public-tree scanner

`evalmesh doctor` never prints matched content. It rejects symlink traversal and
detected inode races, and scans at most 100,000 entries, 64 MiB, 128 directory levels,
10,000 findings, and 2 MiB per file. Hitting any bound emits `scan.resource-limit` or
`scan.file-too-large` and fails closed. Pattern scanning is a release guard, not a
complete DLP system; review generated archives and hosting configuration separately.
