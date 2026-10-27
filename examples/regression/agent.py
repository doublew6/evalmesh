"""Synthetic versions illustrating an exact-output regression."""

from __future__ import annotations

import argparse
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("baseline", "candidate"), required=True)
    args = parser.parse_args()
    case = json.load(sys.stdin)
    message = case["input"]["message"]
    if args.mode == "candidate":
        message = message.encode("ascii", errors="ignore").decode("ascii")
    json.dump(
        {"protocol": "evalmesh.result.v1", "output": {"message": message}},
        sys.stdout,
        ensure_ascii=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
