"""Compile a private inventory into an ordinary temporary EvalMesh v1 suite."""

from __future__ import annotations

import hashlib
import json
import secrets
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes
from .inventory import Inventory, public_cases


def _private_write(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


@dataclass(frozen=True, slots=True, repr=False)
class CompiledInventorySuite:
    manifest_path: Path
    inventory_path: Path

    def __repr__(self) -> str:
        return "<CompiledInventorySuite private>"


def _snapshot_payload(inventory: Inventory) -> dict[str, Any]:
    assets: list[dict[str, Any]] = []
    for asset in inventory.assets:
        raw: dict[str, Any] = {
            "id": asset.id,
            "kind": asset.kind,
            "tags": list(asset.tags),
        }
        for key, value in asset.config.items():
            if value is None:
                continue
            if key in {"path", "database_path", "activity_path"}:
                configured = Path(value)
                value = (
                    configured
                    if configured.is_absolute()
                    else inventory.source_dir / configured
                )
                value = str(value)
            raw[key] = value
        assets.append(raw)
    return {"schema_version": 1, "host_id": inventory.host_id, "assets": assets}


@contextmanager
def compiled_inventory_suite(inventory: Inventory) -> Iterator[CompiledInventorySuite]:
    """Yield private snapshot plus a content-minimized mode-0700 standard suite."""

    with tempfile.TemporaryDirectory(prefix="emx-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        snapshot = canonical_json_bytes(_snapshot_payload(inventory))
        inventory_path = root / f"cfg-{secrets.token_hex(16)}"
        inventory_path.write_bytes(snapshot)
        inventory_path.chmod(0o600)
        fixture = root / "fixture"
        fixture.mkdir(mode=0o700)
        _private_write(fixture / "README.txt", "Synthetic EvalMesh inventory probe workspace.\n")
        case_lines = "".join(
            json.dumps(
                case,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
            for case in public_cases(
                inventory, config_binding=hashlib.sha256(snapshot).hexdigest()
            )
        )
        _private_write(root / "cases.jsonl", case_lines)
        _private_write(
            root / "evalmesh.toml",
            "\n".join(
                (
                    "schema_version = 1",
                    'subject_id = "asset-health"',
                    f'suite_id = "node-{inventory.host_id}"',
                    'case_files = ["cases.jsonl"]',
                    "repetitions = 1",
                    "pass_threshold = 1.0",
                    "",
                    "[target]",
                    'kind = "command"',
                    'argv = ["{python}", "-m", "evalmesh.monitor_target"]',
                    'workspace_mode = "copy"',
                    'workspace_path = "fixture"',
                    'output_mode = "json"',
                    "timeout_seconds = 20",
                    "max_output_bytes = 65536",
                    'forward_env = ["EVALMESH_MONITOR_INVENTORY"]',
                    "",
                    "[privacy]",
                    'capture = "digest"',
                    'hmac_key_env = "EVALMESH_HMAC_KEY"',
                    "include_metrics = true",
                    "include_timing = true",
                    "",
                    "[[graders]]",
                    'id = "process-ok"',
                    'kind = "exit_code"',
                    "expected = 0",
                    "",
                    "[[graders]]",
                    'id = "health"',
                    'kind = "metric_threshold"',
                    'metric = "health"',
                    "min = 1.0",
                    "",
                )
            ),
        )
        yield CompiledInventorySuite(
            manifest_path=root / "evalmesh.toml",
            inventory_path=inventory_path,
        )
