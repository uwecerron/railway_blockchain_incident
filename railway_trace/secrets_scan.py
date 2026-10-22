"""Fail if a GoldRush key (or the key currently loaded) appears in project files.

Run before every commit:  python -m railway_trace scan-secrets
Streams files in chunks (with overlap so a key split across chunks is still
found), reads gzip by magic bytes (covers cache *.tmp files), skips symlinks
and anything that is not a regular file, and never crashes on corrupt data.
"""
from __future__ import annotations

import gzip
import os
import re
from pathlib import Path
from typing import Iterator

KEY_PATTERN = re.compile(rb"(cqt_|ckey_)[A-Za-z0-9]{16,}")
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}
SKIP_FILES = {".env"}  # the one place the key is supposed to live (git-ignored)
CHUNK = 1 << 20
OVERLAP = 256


def _chunks(path: Path) -> Iterator[bytes]:
    try:
        with path.open("rb") as fh:
            gz = fh.read(2) == b"\x1f\x8b"
        opener = gzip.open if gz else open
        with opener(path, "rb") as fh:
            tail = b""
            while True:
                block = fh.read(CHUNK)
                if not block:
                    return
                yield tail + block
                tail = block[-OVERLAP:]
    except (OSError, EOFError, ValueError, gzip.BadGzipFile):
        return  # unreadable/corrupt: nothing more we can scan


def _variants(secret: str) -> list[bytes]:
    return [secret.encode("utf-8"), secret.encode("utf-16-le")]


def scan(root: Path, extra_secret: str | None = None) -> list[str]:
    extras = _variants(extra_secret) if extra_secret else []
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in SKIP_FILES:
                continue
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue
            for chunk in _chunks(p):
                if KEY_PATTERN.search(chunk) or any(e in chunk for e in extras):
                    hits.append(str(p.relative_to(root)))
                    break
    return hits
