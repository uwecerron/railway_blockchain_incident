#!/usr/bin/env python3
"""Shortcut: `python3 trace.py all` == `python3 -m railway_trace all`."""
import sys

from railway_trace.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["all"]))
