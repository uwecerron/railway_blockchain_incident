"""Follow the attacker's cash-out a few hops with cheap GoldRush calls.

Two custodial patterns investigators look for:
  * native deposit:  fresh address receives ETH, forwards it to a hot wallet;
  * token deposit:   address receives USDT/USDC, a "gas station" wallet tops it
                     up with a little native coin, then the tokens are swept.
The destination of either sweep is a wallet with 10^5+ transactions: the
service's hot wallet. We report the pattern; we do not invent a name for it.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import goldrush as G
from .client import ApiError
from .forensics import is_lookalike

SERVICE_TX_THRESHOLD = 10_000


@dataclass
class Hop:
    chain: str
    depth: int
    address: str
    received_from: str
    usd_in: float
    total_txs: int | None
    first_seen: str | None
    balance_usd: float | None
    verdict: str
    forwarded_to: str
    forward_tx: str
    received_at: str
    forward_kind: str
    gas_funder: str
    poison_senders: str


def _token_sweep(api: G.Getter, chain: str, addr: str, tx_hash: str) -> str:
    """Recipient of an ERC-20 Transfer from `addr` inside `tx_hash` ('' if none)."""
    try:
        tx = G.transaction(api, chain, tx_hash) or {}
    except ApiError:
        return ""
    for lg in tx.get("log_events") or []:
        d = lg.get("decoded") or {}
        if d.get("name") != "Transfer":
            continue
        p = {x.get("name"): x.get("value") for x in d.get("params") or []}
        if str(p.get("from", "")).lower() == addr:
            return str(p.get("to", "")).lower()
    return ""


def inspect(api: G.Getter, chain: str, addr: str, attacker: str, after: str = "") -> dict:
    """Summary + (for small wallets) forwarding, gas top-up and poisoning.
    Only activity at/after `after` (when the traced funds arrived) is considered,
    so a deposit address with years of history is judged on what it did next."""
    info = {"total": None, "first": None, "balance": None, "next": "", "ftx": "", "ftime": "", "kind": "",
            "gas": "", "poison": []}
    try:
        s = G.transactions_summary(api, chain, addr) or {}
        info["total"] = s.get("total_count", 0)
        info["first"] = (s.get("earliest_transaction") or {}).get("block_signed_at")
    except ApiError:
        return info
    if info["total"] >= SERVICE_TX_THRESHOLD:
        try:
            info["balance"] = round(G.balances_usd(api, chain, addr), 2)
        except ApiError:
            pass
        return info
    try:
        raw = G.first_page(api, chain, addr) if info["total"] <= 100 else G.latest_page(api, chain, addr)
        page = sorted((t for t in raw if (t.get("block_signed_at") or "") >= after),
                      key=lambda t: t.get("block_signed_at") or "")
    except ApiError:
        page = []
    for t in page:
        frm, to = (t.get("from_address") or "").lower(), (t.get("to_address") or "").lower()
        val = int(t.get("value") or 0)
        if to == addr and is_lookalike(frm, attacker):  # dust or zero from a vanity twin
            info["poison"].append(frm)
            continue
        if to == addr and val > 0 and frm != attacker and not info["next"]:
            info["gas"] = info["gas"] or frm  # native top-up before a sweep = gas station
        if frm == addr and not info["next"]:
            if val > 0:
                info.update(next=to, ftx=t.get("tx_hash") or "", ftime=t.get("block_signed_at") or "", kind="native")
            else:
                dest = _token_sweep(api, chain, addr, t.get("tx_hash") or "")
                if dest:
                    info.update(next=dest, ftx=t.get("tx_hash") or "", ftime=t.get("block_signed_at") or "",
                                kind="token")
    return info


def _verdict(info: dict) -> str:
    total = info["total"]
    if total is None:
        return "unknown (API error)"
    if total >= SERVICE_TX_THRESHOLD:
        return "high-volume service wallet (exchange/hot-wallet pattern)"
    if info["kind"] == "token" and info["gas"]:
        return "token deposit-address pattern (gas top-up, then sweep)"
    if info["kind"] == "native" and total <= 10:
        return "fresh pass-through (deposit-address pattern)"
    if info["kind"] and total > 10:
        return "long-lived forwarding address (reused deposit-address pattern)"
    if info["kind"]:
        return "forwarding wallet"
    return "holding wallet (no outgoing transfer seen)"


def follow(api: G.Getter, chain: str, start: str, sender: str, usd: float, attacker: str,
           received_at: str = "", max_depth: int = 3) -> list[Hop]:
    hops, addr, prev, depth, seen, when = [], start.lower(), sender.lower(), 1, set(), received_at
    while addr and depth <= max_depth and addr not in seen:
        seen.add(addr)
        info = inspect(api, chain, addr, attacker, after=when)
        hops.append(Hop(chain, depth, addr, prev, round(usd, 2), info["total"], info["first"], info["balance"],
                        _verdict(info), info["next"], info["ftx"], when, info["kind"], info["gas"],
                        ",".join(sorted(set(info["poison"])))))
        if info["total"] is None or info["total"] >= SERVICE_TX_THRESHOLD:
            break
        prev, addr, depth, when = addr, info["next"], depth + 1, info["ftime"]
    return hops
