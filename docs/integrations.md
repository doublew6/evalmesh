# Integration recipes

## Existing CLI or Python agent

Add a small adapter command in the subject repository. Read the EvalMesh case envelope
from stdin, invoke the existing public service boundary, and print a result envelope.
Do not import private database models into EvalMesh.

## HTTP agent

Use `kind = "http"`, put the URL in an environment variable named by `url_env`, and
map header names to environment-variable names with `headers_from_env`. Header values
are never part of a run record.

## Domain-metric evaluation

Keep domain calendars, scoring, calibration, and provenance calculations in the
subject project. Return already-authoritative numeric values under `metrics`, then
use `metric_threshold` graders in EvalMesh. This avoids divergent market logic.

## Codex and repository Skills

Codex targets use official non-interactive mode with `--ephemeral`, `--json`, an
explicit sandbox, and `codex exec -` so the case prompt travels over stdin instead
of appearing in the process list. Put the Skill under the fixture's
`.agents/skills/<skill-name>/SKILL.md` or configure an explicit safe Skill name.
The flags follow the [official Codex non-interactive mode documentation](https://learn.chatgpt.com/docs/non-interactive-mode),
and repository Skill discovery follows the [official Skills guide](https://learn.chatgpt.com/docs/build-skills).

Use a copied synthetic workspace and declare exact `artifact_paths`. Combine
`file_exists`, `file_contains`, or `file_json_equals` with final-text graders. Text-only
grading is not enough to claim a repository Skill works.

Set `skip_git_repo_check = true` in every Codex target. Copied workspaces deliberately
exclude `.git`, and EvalMesh requires this explicit acknowledgement before invoking
`codex exec`.

The default Codex sandbox is `read-only`; a file-producing Skill requires
`workspace-write`. `danger-full-access` is rejected by the v0.1 adapter.

The temporary `HOME` intentionally cannot see an existing Codex login. Authorize only
the Codex credential directory, without enabling the whole host home, in an ignored
private policy:

```toml
# codex.private.toml (ignored by Git)
schema_version = 1

[target]
use_host_codex_auth = true
```

Then run `evalmesh run evalmesh.toml --policy codex.private.toml`. This sets
`CODEX_HOME` to the host's explicit value or `$HOME/.codex`; `--ignore-user-config`
still prevents loading user config while Codex authentication remains available.
Use `use_host_home = true` only when a trusted non-Codex target genuinely requires it.

## Scheduled runs

Use the host scheduler or a Codex scheduled task to invoke a fixed command such as:

```bash
evalmesh run evalmesh.toml --case smoke-001
```

The scheduler owns cadence, retries, and notifications. EvalMesh owns attempts,
scores, and report delivery.
