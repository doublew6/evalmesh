from __future__ import annotations

import textwrap
from pathlib import Path


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(value).lstrip(), encoding="utf-8")


def write_basic_suite(
    root: Path,
    *,
    script: str,
    target_extra: str = "",
    graders: str = "",
    cases: str | None = None,
    top_extra: str = "",
) -> Path:
    write_text(root / "agent.py", script)
    write_text(
        root / "cases.jsonl",
        cases or '{"id":"case-001","input":{"value":"safe"},"expected":{}}\n',
    )
    write_text(
        root / "evalmesh.toml",
        f"""
        schema_version = 1
        subject_id = "test-subject"
        suite_id = "test-suite"
        case_files = ["cases.jsonl"]
        repetitions = 1
        pass_threshold = 1.0
        {top_extra}

        [target]
        kind = "command"
        argv = ["{{python}}", "agent.py"]
        workspace_mode = "copy"
        output_mode = "json"
        timeout_seconds = 5
        max_output_bytes = 65536
        {target_extra}

        [[graders]]
        id = "process-ok"
        kind = "exit_code"
        expected = 0
        {graders}
        """,
    )
    return root / "evalmesh.toml"
