"""Synthetic target used by the public quick start."""

from __future__ import annotations

import json
import sys


def main() -> int:
    case = json.load(sys.stdin)
    message = case["input"]["message"]
    json.dump(
        {
            "protocol": "evalmesh.result.v1",
            "output": {"message": message},
            "metrics": {"synthetic_quality": 1.0},
        },
        sys.stdout,
        ensure_ascii=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
