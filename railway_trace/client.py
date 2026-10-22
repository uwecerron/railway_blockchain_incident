"""Thin, safe HTTP client for the Covalent GoldRush API.

Responsibilities (and only these): authentication, retries with backoff,
error sanitizing, and an optional on-disk response cache. Endpoint knowledge
lives in `goldrush.py`.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import random
import time
from pathlib import Path
from typing import Any, Callable, Mapping

import requests

from .config import Secret

BASE_URL = "https://api.covalenthq.com"
RETRYABLE = {429, 500, 502, 503, 504}


class ApiError(RuntimeError):
    def __init__(self, status: int | None, path: str, detail: str) -> None:
        self.status, self.path, self.detail = status, path, detail
        super().__init__(f"GoldRush {status or 'network error'} on {path}: {detail}")


class ResponseCache:
    """gzip JSON files keyed by sha256(path + params). The API key is never part
    of the cache key or the stored payload."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def key(path: str, params: Mapping[str, Any] | None) -> str:
        blob = json.dumps([path, sorted((params or {}).items())], default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def get(self, key: str) -> Any | None:
        f = self.root / f"{key}.json.gz"
        if not f.exists():
            return None
        try:
            with gzip.open(f, "rt", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None

    def put(self, key: str, data: Any) -> None:
        tmp = self.root / f"{key}.tmp"
        with gzip.open(tmp, "wt", encoding="utf-8") as fh:
            json.dump(data, fh)
        tmp.replace(self.root / f"{key}.json.gz")


def _short(text: str, n: int = 240) -> str:
    text = " ".join((text or "").split())
    if text.lower().startswith("<!doctype") or text.lower().startswith("<html"):
        return "(HTML error page from gateway)"
    return text[:n]


class GoldRushClient:
    def __init__(
        self,
        key: Secret,
        cache: ResponseCache | None = None,
        session: requests.Session | None = None,
        max_retries: int = 5,
        timeout: float = 60.0,
        sleep: Callable[[float], None] = time.sleep,
        base_url: str = BASE_URL,
    ) -> None:
        if not isinstance(key, Secret):
            raise TypeError("key must be a Secret (use config.load_api_key())")
        self._key = key
        self._cache = cache
        self._session = session or requests.Session()
        self._max_retries = max_retries
        self._timeout = timeout
        self._sleep = sleep
        self._base = base_url.rstrip("/")
        self.calls = 0  # network calls made (cache hits excluded)

    def __repr__(self) -> str:
        return f"GoldRushClient(base={self._base!r}, key=****)"

    def get(self, path: str, params: Mapping[str, Any] | None = None, cache: bool = True) -> Any:
        """GET `path`; return the `data` member of the JSON envelope."""
        ck = ResponseCache.key(path, params)
        if cache and self._cache is not None:
            hit = self._cache.get(ck)
            if hit is not None:
                return hit

        last_status: int | None = None
        last_detail = ""
        for attempt in range(self._max_retries + 1):
            if attempt:
                self._sleep(min(30.0, 1.5 * 2 ** (attempt - 1)) + random.uniform(0, 0.5))
            try:
                self.calls += 1
                resp = self._session.get(
                    self._base + path,
                    params=dict(params or {}),
                    headers={"Authorization": f"Bearer {self._key.reveal()}", "Accept": "application/json"},
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                # Exception text can include request details; never let the key through.
                last_status, last_detail = None, self._key.redact(f"{type(exc).__name__}: {exc}")
                continue

            if resp.status_code in RETRYABLE:
                last_status, last_detail = resp.status_code, self._key.redact(_short(resp.text))
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    self._sleep(min(30.0, float(retry_after)))
                continue
            if resp.status_code >= 400:
                raise ApiError(resp.status_code, path, self._key.redact(_short(resp.text)))
            try:
                body = resp.json()
            except ValueError:
                raise ApiError(resp.status_code, path, "response was not JSON") from None
            if isinstance(body, dict) and body.get("error"):
                msg = body.get("error_message") or "API reported an error"
                raise ApiError(body.get("error_code") or resp.status_code, path, self._key.redact(str(msg)))
            data = body.get("data", body) if isinstance(body, dict) else body
            if cache and self._cache is not None:
                self._cache.put(ck, data)
            return data

        raise ApiError(last_status, path, f"gave up after {self._max_retries} retries ({last_detail})")
