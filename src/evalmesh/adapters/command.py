from __future__ import annotations

import sys
from collections.abc import Mapping

from ..delivery import case_envelope_bytes
from ..models import RawExecutionResult, TargetSpec
from ..ports import Invocation
from .process import run_process
from .protocol import parse_target_output


class CommandAdapter:
    def __init__(self, target: TargetSpec, environment: Mapping[str, str]) -> None:
        self.target = target
        self.environment = environment

    def invoke(self, invocation: Invocation) -> RawExecutionResult:
        argv = [sys.executable if item == "{python}" else item for item in self.target.argv]
        payload = case_envelope_bytes(invocation.case_id, invocation.input)
        result = run_process(
            argv=argv,
            stdin=payload,
            cwd=invocation.workspace,
            target=self.target,
            environment=self.environment,
        )
        return parse_target_output(result, self.target.output_mode)
