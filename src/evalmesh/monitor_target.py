"""Private-inventory command target for EvalMesh monitoring suites."""

from __future__ import annotations

import hmac
import json
import os
import sys
from typing import Any

from .canonical import strict_json_loads
from .inventory import load_inventory, probe_asset

_MAX_REQUEST_BYTES = 65_536


def run_request(payload: bytes, environment: dict[str, str]) -> dict[str, Any]:
    kind = "unknown"
    healthy = False
    try:
        if len(payload) > _MAX_REQUEST_BYTES:
            raise ValueError
        request = strict_json_loads(payload)
        if (
            type(request) is not dict
            or request.get("protocol") != "evalmesh.case.v1"
            or type(request.get("case_id")) is not str
            or type(request.get("input")) is not dict
        ):
            raise ValueError
        asset_id = request["input"].get("asset_id")
        if type(asset_id) is not str or asset_id != request["case_id"]:
            raise ValueError
        config_binding = request["input"].get("config_binding")
        if (
            type(config_binding) is not str
            or len(config_binding) != 64
            or any(character not in "0123456789abcdef" for character in config_binding)
        ):
            raise ValueError
        inventory_path = environment.get("EVALMESH_MONITOR_INVENTORY")
        if not inventory_path:
            raise ValueError
        inventory = load_inventory(inventory_path)
        if not hmac.compare_digest(inventory.source_digest, config_binding):
            raise ValueError
        result = probe_asset(inventory, asset_id)
        kind = result.kind
        healthy = result.healthy
    except Exception:
        pass
    return {
        "protocol": "evalmesh.result.v1",
        "output": {"kind": kind, "state": "healthy" if healthy else "unhealthy"},
        "metrics": {"health": 1.0 if healthy else 0.0},
    }


def main() -> int:
    try:
        payload = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
        response = run_request(payload, dict(os.environ))
        json.dump(
            response,
            sys.stdout,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
