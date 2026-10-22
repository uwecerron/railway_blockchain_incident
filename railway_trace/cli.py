"""Command line entry point. Each stage is resumable, so long traces can run in
short sessions:  fetch -> price -> hops -> report   (or `all`)."""
from __future__ import annotations

import argparse
import logging
import sys
import time
from collections import defaultdict
from pathlib import Path

from . import classify as C
from . import forensics, goldrush as G, hops as H, report
from .client import ApiError, GoldRushClient, ResponseCache
from .config import MissingKeyError, load_api_key
from .secrets_scan import scan
from .util import iso, read_json, write_json

RAILWAY_ATTACKER = "0xd9773325282874d18cb83f1fe50f14c39750b2ee"
log = logging.getLogger("railway_trace")

# exit codes
OK, BUDGET, MISSING_KEY, API_ERROR, LEAK = 0, 2, 3, 4, 1


class Budget:
    def __init__(self, seconds: float | None):
        self.deadline = time.monotonic() + seconds if seconds else None

    def spent(self) -> bool:
        return self.deadline is not None and time.monotonic() > self.deadline


def _client(out: Path) -> GoldRushClient:
    return GoldRushClient(load_api_key(), cache=ResponseCache(out / "cache"))


def _load_txs(out: Path) -> list[dict]:
    txs = []
    for f in sorted((out / "raw").glob("*.json")):
        txs += read_json(f, [])
    return txs


def _moves(out: Path, address: str) -> tuple[list[dict], list[C.Movement]]:
    txs = _load_txs(out)
    moves = [m for t in txs for m in C.movements(t, address)]
    prices = {tuple(k.split("|", 1)): v for k, v in (read_json(out / "prices.json", {}) or {}).items()}
    C.apply_prices(moves, prices)
    moves.sort(key=lambda m: m.time)
    return txs, moves


def cmd_fetch(a) -> int:
    api, out, budget = _client(a.out), a.out, Budget(a.budget)
    since = iso(a.since)
    acts = G.chain_activity(api, a.address)
    write_json(out / "chains_activity.json", [vars(x) for x in acts])
    wanted = [x.chain_name for x in acts if x.last_seen_at and iso(x.last_seen_at) >= since]
    if a.chains:
        wanted = [c for c in wanted if c in set(a.chains.split(","))]
    log.info("%d chains with history; %d active since %s", len(acts), len(wanted), a.since)
    done = {p.stem for p in (out / "raw").glob("*.json")} if not a.refresh else set()
    for ch in wanted:
        if ch in done:
            continue
        if budget.spent():
            log.warning("time budget reached; rerun the same command to resume"); return BUDGET
        try:
            txs = [C.slim_tx(t, ch) for t in G.iter_transactions(api, ch, a.address, since, max_pages=a.max_pages)]
        except ApiError as e:
            log.warning("%s: %s", ch, e); continue
        write_json(out / "raw" / f"{ch}.json", txs)
        log.info("%s: %d txs", ch, len(txs))
    return 0


def cmd_price(a) -> int:
    out, budget = a.out, Budget(a.budget)
    api = _client(out)
    _txs, moves = _moves(out, a.address)
    day = a.since[:10]
    need = defaultdict(set)
    for m in moves:
        if m.contract != "native" and m.amount and not C.looks_like_spoof(m.asset):
            need[m.chain].add(m.contract)
    prices = read_json(out / "prices.json", {}) or {}
    tried = set(read_json(out / "prices_tried.json", []) or [])  # per (chain|contract), so new tokens get priced
    for ch, cas in sorted(need.items()):
        todo = sorted(c for c in cas if f"{ch}|{c}" not in tried)
        if not todo:
            continue
        if budget.spent():
            log.warning("time budget reached; rerun to resume"); return BUDGET
        try:
            got = G.historical_prices(api, ch, todo, day)
        except ApiError as e:
            log.warning("%s: %s", ch, e); continue
        prices.update({f"{ch}|{k}": v for k, v in got.items()})
        tried.update(f"{ch}|{c}" for c in got)  # unpriced ones are retried next run (price may publish later)
        write_json(out / "prices.json", prices); write_json(out / "prices_tried.json", sorted(tried))
        log.info("%s: priced %d/%d tokens", ch, len(got), len(todo))
    return 0


def cmd_hops(a) -> int:
    out = a.out
    api = _client(out)
    txs, moves = _moves(out, a.address)
    f = forensics.analyze(a.address, txs, moves)
    hops = []
    for row in f.cashout:
        if row["usd"] < a.min_usd:
            continue
        if row["kind"] != "direct_send":  # swaps into pools/routers are not cash-outs to follow
            continue
        hops += report.hops_as_dicts(H.follow(api, row["chain"], row["recipient"], a.address, row["usd"], a.address,
                                                     received_at=row["first"]))
        log.info("%s %s: followed", row["chain"], row["recipient"])
    write_json(out / "hops.json", hops)
    return 0


def cmd_report(a) -> int:
    txs, moves = _moves(a.out, a.address)
    f = forensics.analyze(a.address, txs, moves)
    path = report.write(a.out, f, read_json(a.out / "hops.json", []) or [], moves, txs)
    log.info("report written to %s", path)
    return 0


def cmd_scan(a) -> int:
    roots = {Path(__file__).resolve().parent.parent, a.out.resolve()}
    try:
        extra = load_api_key().reveal()
    except MissingKeyError:
        extra = None
    hits = [f"{r}/{h}" for r in sorted(roots) if r.exists() for h in scan(r, extra)]
    if hits:
        log.error("KEY FOUND in: %s", ", ".join(hits)); return LEAK
    log.info("ok: no API keys found outside .env"); return OK


def cmd_all(a) -> int:
    for fn in (cmd_fetch, cmd_price):
        rc = fn(a)
        if rc:
            return rc
    cmd_hops(a)
    return cmd_report(a)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="railway_trace", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in [("fetch", cmd_fetch), ("price", cmd_price), ("hops", cmd_hops), ("report", cmd_report),
                     ("all", cmd_all), ("scan-secrets", cmd_scan)]:
        s = sub.add_parser(name)
        s.set_defaults(fn=fn)
        s.add_argument("--address", default=RAILWAY_ATTACKER)
        s.add_argument("--since", default="2026-10-21T00:00:00Z")
        s.add_argument("--out", type=Path, default=Path("out"))
        s.add_argument("--chains", help="comma-separated chain names to limit fetch")
        s.add_argument("--budget", type=float, help="stop starting new work after N seconds (resumable)")
        s.add_argument("--refresh", action="store_true", help="refetch chains already on disk")
        s.add_argument("--min-usd", type=float, default=500.0, help="hops: follow cash-outs above this")
        s.add_argument("--max-pages", type=int, default=200, help="fetch: page cap per chain (100 txs/page)")
        s.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    a = p.parse_args(argv)
    logging.basicConfig(level=a.log_level, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    logging.getLogger("urllib3").setLevel(logging.WARNING)  # never log request details
    a.address = a.address.lower()
    try:
        return a.fn(a)
    except MissingKeyError as e:
        log.error("%s", e); return MISSING_KEY
    except ApiError as e:  # already redacted
        log.error("%s", e); return API_ERROR
