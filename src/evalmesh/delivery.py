"""Exact target-visible payload construction shared by validation and adapters."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .models import TargetSpec, plain_json


def case_envelope_bytes(case_id: str, case_input: Any) -> bytes:
    """Serialize the exact Command/HTTP case protocol body."""

    return json.dumps(
        {
            "protocol": "evalmesh.case.v1",
            "case_id": case_id,
            "input": plain_json(case_input),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def codex_prompt_text(target: TargetSpec, case_input: Any) -> str | None:
    """Return the exact Codex stdin text, or None for an invalid prompt case."""

    if not isinstance(case_input, Mapping):
        return None
    prompt = case_input.get(target.prompt_field)
    if not isinstance(prompt, str) or not prompt:
        return None
    return f"${target.skill}\n\n{prompt}" if target.skill else prompt
