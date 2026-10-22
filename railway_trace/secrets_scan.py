"""Fail if a GoldRush key (or the key currently loaded) appears in tracked files.

Run before every commit:  python -m railway_trace scan-secrets
"""
from __future__ import annotations

import gzip
import os
import re
from pathlib import Path

KEY_PATTERN = re.compile(r"cqt_[A-Za-z0-9]{16,}")
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}
SKIP_FILES = {".env"}  # the one place the key is supposed to live (git-ignored)


def _texts(path: Path):
    if path.suffix == ".gz":
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as fh:
                yield fh.read()
        except OSError:
            return
    else:
        try:
            yield path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return


def scan(root: Path, extra_secret: str | None = None) -> list[str]:
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in SKIP_FILES:
                continue
            p = Path(dirpath) / name
            for text in _texts(p):
                if KEY_PATTERN.search(text) or (extra_secret and extra_secret in text):
                    hits.append(str(p.relative_to(root)))
    return hits
