"""Create a synthetic Codex suite and a ready-to-edit experiment registry."""

from __future__ import annotations

import os
from pathlib import Path

from .errors import ConfigurationError
from .manifest import _identifier
from .reporters.jsonl import _absolute_parent, _open_private_directory


def create_starter(destination: str | Path, subject_id: str = "subject-a") -> None:
    """Create a new directory only; never overwrite an existing project."""
    subject_id = _identifier(subject_id, "subject_id")
    files = {
        "evalmesh.toml": f'''schema_version = 1
subject_id = "{subject_id}"
suite_id = "smoke"
case_files = ["cases.jsonl"]

[target]
kind = "codex"
workspace_mode = "copy"
workspace_path = "fixture"
output_mode = "text"
sandbox = "workspace-write"
skip_git_repo_check = true
timeout_seconds = 180
artifact_paths = ["result.json"]

[[graders]]
id = "answer"
kind = "file_json_equals"
path = "result.json"
actual_path = "answer"
''',
        "cases.jsonl": (
            '{"id":"case-001","input":{"prompt":"Write result.json containing an answer field '
            'with the numeric result of 2 + 2."},"expected":{"answer":4},'
            '"dimensions":{"task_type":"calculation","risk_level":"critical"}}\n'
            '{"id":"case-002","input":{"prompt":"Write result.json containing an answer field '
            'with the numeric result of 9 - 12."},"expected":{"answer":-3},'
            '"dimensions":{"task_type":"calculation","difficulty":"boundary"}}\n'
        ),
        "fixture/README.md": "Synthetic workspace for repeatable file-producing tasks.\n",
        "registry.toml": f'''schema_version = 1

[[projects]]
id = "{subject_id}"
manifests = ["evalmesh.toml"]
# To reuse an existing Codex login, uncomment the following private policy.
# policy = "codex.private.toml"

# Replace these placeholders with models available to your Codex account.
[[profiles]]
id = "candidate-a"
model = "model-a"
reasoning_effort = "high"

[[profiles]]
id = "candidate-b"
model = "model-b"
reasoning_effort = "high"
''',
        "experiment.toml": f'''schema_version = 1
registry = "registry.toml"
projects = ["{subject_id}"]
profiles = ["candidate-a", "candidate-b"]
baseline = "candidate-a"
repetitions = 3
max_workers = 1
max_attempts = 12
dispatch_timeout_seconds = 3600
''',
        "codex.private.toml": "schema_version = 1\n[target]\nuse_host_codex_auth = true\n",
        ".gitignore": ".evalmesh/\n*.private.toml\n*.local.toml\n",
        "README.md": """# Synthetic evaluation starter

Edit cases.jsonl and fixture/ to describe repeatable tasks. Expected answers stay
outside the copied fixture. The grader independently checks result.json.

Replace model-a/model-b in registry.toml with supported Codex model IDs. Each
profile selects both model and reasoning effort. Uncomment the private policy
reference only when you want to reuse the host's Codex login.

Run `evalmesh validate evalmesh.toml`, then `evalmesh experiment plan experiment.toml`.
Before execution, set EVALMESH_HMAC_KEY to a separate persistent random secret of
at least 32 bytes. Keep it outside the repository and reuse it for resume/report.
Run `evalmesh experiment run experiment.toml --output .evalmesh/experiment-001`.
This invokes real models and consumes your Codex account usage.

Add more projects to registry.toml using their opaque subject IDs and suite paths.
Paths are relative to the registry file; each suite keeps its own relative paths.
Keep real registries, private policies, cases and credentials out of EvalMesh's
public source checkout. Do not place a private policy inside fixture/.
""",
    }
    message = "could not create evaluation starter"
    try:
        path = Path(destination).expanduser()
        if path.name in {"", ".", ".."}:
            raise ConfigurationError("starter destination must be a new directory")
        parent = _absolute_parent(path)
        directory = _open_private_directory(parent)
        try:
            os.mkdir(path.name, 0o700, dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)
        root = parent / path.name
        for name, content in files.items():
            target = root / name
            directory = _open_private_directory(target.parent)
            try:
                descriptor = os.open(
                    target.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content.encode("utf-8"))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(directory)
            finally:
                os.close(directory)
        return
    except FileExistsError:
        message = "starter destination already exists; nothing was overwritten"
    except ConfigurationError as error:
        message = str(error)
    except Exception:
        pass
    raise ConfigurationError(message)
