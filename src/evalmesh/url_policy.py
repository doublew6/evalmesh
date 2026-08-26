"""Shared lexical checks applied before permissive URL parsers."""

from __future__ import annotations

import re

_HTTP_PATH = re.compile(r"^(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})*$")


def has_forbidden_url_characters(value: str) -> bool:
    if len(value) > 2048 or value != value.strip():
        return True
    for index, character in enumerate(value):
        codepoint = ord(character)
        if codepoint < 0x21 or codepoint > 0x7E:
            return True
        if character == "%" and (
            index + 2 >= len(value)
            or any(item not in "0123456789abcdefABCDEF" for item in value[index + 1 : index + 3])
        ):
            return True
    return False


def has_http_url_prefix(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def is_valid_http_authority_and_path(netloc: str, path: str, port: int | None) -> bool:
    port_text: str | None = None
    if netloc.startswith("["):
        closing = netloc.find("]")
        suffix = netloc[closing + 1 :] if closing >= 0 else "invalid"
        if suffix:
            if not suffix.startswith(":"):
                return False
            port_text = suffix[1:]
    elif ":" in netloc:
        _host, port_text = netloc.rsplit(":", 1)
    return (
        netloc == netloc.lower()
        and (port is None or 1 <= port <= 65_535)
        and (
            (port is None and port_text is None)
            or (
                port is not None
                and port_text is not None
                and bool(re.fullmatch(r"[1-9][0-9]{0,4}", port_text))
            )
        )
        and bool(_HTTP_PATH.fullmatch(path))
    )


def is_valid_http_field_value(value: str) -> bool:
    """Accept a deterministic visible-ASCII HTTP field value."""

    return (
        0 < len(value) <= 4096
        and value == value.strip(" ")
        and all(0x20 <= ord(character) <= 0x7E for character in value)
    )
