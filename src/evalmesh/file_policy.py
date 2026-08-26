"""Shared case-insensitive policy for files that must stay out of public/copy trees."""

from __future__ import annotations

from pathlib import Path

SENSITIVE_DIRECTORY_NAMES = frozenset(
    {
        ".aws",
        ".azure",
        ".codex",
        ".docker",
        ".evalmesh",
        ".git",
        ".gcloud",
        ".gnupg",
        ".kube",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".ssh",
        ".venv",
        "__pycache__",
        "node_modules",
        "private",
        "venv",
    }
)


def is_forbidden_filename(path: str | Path) -> bool:
    lower_name = Path(path).name.lower()
    return (
        lower_name
        in {
            ".env",
            ".netrc",
            ".npmrc",
            ".pypirc",
            "auth.json",
            "id_ecdsa",
            "id_ed25519",
            "id_rsa",
        }
        or (lower_name.startswith(".env.") and lower_name != ".env.example")
        or lower_name.endswith((".pem", ".key", ".p12", ".pfx"))
        or lower_name.endswith((".local.toml", ".private.toml"))
    )


def is_sensitive_copy_entry(name: str) -> bool:
    return name.lower() in SENSITIVE_DIRECTORY_NAMES or is_forbidden_filename(name)
