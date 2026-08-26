"""Codex non-interactive adapter using the documented JSONL event contract."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from ..canonical import strict_json_loads
from ..delivery import codex_prompt_text
from ..models import RawExecutionResult, TargetSpec, frozen_mapping
from ..ports import Invocation
from .process import run_process
from .protocol import parse_target_output

_PUBLIC_EVENT_TYPES = {
    "thread.started",
    "turn.started",
    "turn.completed",
    "turn.failed",
    "item.started",
    "item.updated",
    "item.completed",
    "error",
}


class CodexAdapter:
    def __init__(self, target: TargetSpec, environment: Mapping[str, str]) -> None:
        self.target = target
        self.environment = environment

    def invoke(self, invocation: Invocation) -> RawExecutionResult:
        prompt = codex_prompt_text(self.target, invocation.input)
        if prompt is None:
            return self._input_error("missing_codex_prompt")
        argv = [self.target.executable, "exec"]
        argv.append("--ephemeral")
        argv.extend(["--json", "--sandbox", self.target.sandbox])
        argv.append("--ignore-user-config")
        if self.target.ignore_rules:
            argv.append("--ignore-rules")
        # Copied workspaces intentionally exclude .git metadata.
        argv.append("--skip-git-repo-check")
        # The documented '-' sentinel keeps private prompts out of the process list.
        argv.append("-")
        raw = run_process(
            argv=argv,
            stdin=prompt.encode("utf-8"),
            cwd=invocation.workspace,
            target=self.target,
            environment=self.environment,
        )
        return self._parse_events(raw, self.target.output_mode)

    @staticmethod
    def _input_error(code: str) -> RawExecutionResult:
        return RawExecutionResult(
            output=None,
            stdout="",
            stderr="",
            exit_code=None,
            duration_ms=0,
            error_codes=(code,),
        )

    @staticmethod
    def _parse_events(raw: RawExecutionResult, output_mode: str = "json") -> RawExecutionResult:
        counts: Counter[str] = Counter()
        final_message = ""
        usage: dict[str, int] = {}
        errors = list(raw.error_codes)
        completed_turns = 0
        # Codex emits JSONL, whose record delimiter is LF only. Unicode line
        # separator characters are legal inside a JSON string.
        for line in raw.stdout.split("\n"):
            if not line:
                continue
            try:
                event: Any = strict_json_loads(line)
            except (ValueError, TypeError):
                errors.append("invalid_codex_event")
                continue
            if not isinstance(event, dict) or not isinstance(event.get("type"), str):
                errors.append("invalid_codex_event")
                continue
            event_type = event["type"]
            counts[event_type if event_type in _PUBLIC_EVENT_TYPES else "unknown"] += 1
            if event_type == "item.completed":
                item = event.get("item")
                if isinstance(item, dict) and item.get("type") == "agent_message":
                    text = item.get("text")
                    if isinstance(text, str):
                        final_message = text
            elif event_type == "turn.completed":
                completed_turns += 1
                raw_usage = event.get("usage")
                if isinstance(raw_usage, dict):
                    for name in (
                        "input_tokens",
                        "cached_input_tokens",
                        "output_tokens",
                        "reasoning_output_tokens",
                    ):
                        value = raw_usage.get(name)
                        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                            usage[name] = value
            elif event_type in {"turn.failed", "error"}:
                errors.append("codex_turn_failed")
        if not final_message:
            errors.append("missing_codex_final_message")
        if completed_turns == 0:
            errors.append("missing_codex_turn_completed")
        elif completed_turns > 1:
            errors.append("invalid_codex_event")
        metadata = {
            "event_counts": dict(sorted(counts.items())),
            "usage": usage,
        }
        result = replace(
            raw,
            output=None,
            stdout=final_message,
            stderr="",
            error_codes=tuple(sorted(set(errors))),
            safe_metadata=frozen_mapping(metadata),
        )
        return parse_target_output(result, output_mode) if final_message else result
