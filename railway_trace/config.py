"""API key loading.

The key is read from the GOLDRUSH_API_KEY environment variable or a local .env
file. It is wrapped in `Secret` so that printing, logging or formatting it
never reveals the value. The package never writes the key to disk, never puts
it in a URL, and redacts it from every error message.
"""
from __future__ import annotations

import os
from pathlib import Path

ENV_VAR = "GOLDRUSH_API_KEY"


class MissingKeyError(RuntimeError):
    pass


class Secret:
    """Opaque holder for a credential. `str()`/`repr()` are always masked."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        object.__setattr__(self, "_value", value)

    def __setattr__(self, *_):  # immutable
        raise AttributeError("Secret is immutable")

    def reveal(self) -> str:
        return self._value

    def redact(self, text: str) -> str:
        """Remove the secret from any text (error bodies, exception strings)."""
        if not text or not self._value:
            return text
        return text.replace(self._value, "****")

    def __repr__(self) -> str:
        return "Secret(****)"

    __str__ = __repr__

    def __format__(self, _spec: str) -> str:
        return "Secret(****)"

    def __reduce__(self):  # refuse to pickle
        raise TypeError("Secret cannot be serialized")


def _read_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, val = line.split("=", 1)
        values[key.strip()] = val.strip().strip('"').strip("'")
    return values


def load_api_key(search: list[Path] | None = None) -> Secret:
    """Environment first, then the first .env found in `search` (cwd, project root)."""
    value = os.environ.get(ENV_VAR, "").strip()
    if not value:
        roots = search or [Path.cwd(), Path(__file__).resolve().parent.parent]
        for root in roots:
            value = _read_dotenv(root / ".env").get(ENV_VAR, "").strip()
            if value:
                break
    if not value:
        raise MissingKeyError(
            f"No API key. Set {ENV_VAR} in your shell or copy .env.example to .env "
            "and paste your key there (the file is git-ignored). "
            "Get a key at https://goldrush.dev/platform/auth/register/ "
            "(free trial) or buy a plan at https://goldrush.dev/platform/billing/."
        )
    return Secret(value)
