"""Private stdlib HTTP worker isolated behind the parent process deadline."""

from __future__ import annotations

import base64
import http.client
import json
import sys
from contextlib import suppress
from urllib.parse import urlsplit


def _emit(
    *,
    error: str | None,
    status: int | None = None,
    body: bytes = b"",
    truncated: bool = False,
) -> None:
    json.dump(
        {
            "protocol": "evalmesh.http-worker.v1",
            "error": error,
            "status": status,
            "body_base64": base64.b64encode(body).decode("ascii"),
            "truncated": truncated,
        },
        sys.stdout,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def main() -> int:
    connection: http.client.HTTPConnection | None = None
    try:
        request = json.load(sys.stdin)
        url = request["url"]
        method = request["method"]
        headers = request["headers"]
        body = base64.b64decode(request["body_base64"], validate=True)
        maximum = request["max_output_bytes"]
        timeout = request["timeout_seconds"]
        if (
            type(url) is not str
            or method not in {"POST", "PUT"}
            or type(headers) is not dict
            or not all(type(key) is str and type(value) is str for key, value in headers.items())
            or type(maximum) is not int
            or maximum < 1
            or type(timeout) not in {int, float}
            or timeout <= 0
        ):
            _emit(error="http_request_failed")
            return 0
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            _emit(error="http_request_failed")
            return 0
        connection_type = (
            http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        )
        connection = connection_type(parsed.hostname, parsed.port, timeout=float(timeout))
        connection.request(method, parsed.path or "/", body=body, headers=headers)
        response = connection.getresponse()
        captured = bytearray()
        read_chunk = getattr(response, "read1", response.read)
        while len(captured) <= maximum:
            chunk = read_chunk(min(65_536, maximum + 1 - len(captured)))
            if not chunk:
                break
            captured.extend(chunk)
        truncated = len(captured) > maximum
        _emit(
            error=None,
            status=response.status,
            body=bytes(captured[:maximum]),
            truncated=truncated,
        )
        return 0
    except TimeoutError:
        _emit(error="target_timeout")
        return 0
    except Exception:
        _emit(error="http_request_failed")
        return 0
    finally:
        if connection is not None:
            with suppress(OSError):
                connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
