"""Forensic analysis over classified movements. Pure: no network, no disk."""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from . import classify as C
from .labels import label
from .util import iso

VICTIM_ROLES = {C.VICTIM_NATIVE, C.VICTIM_TOKEN}


@dataclass
class Victim:
    wallet: str
    chains: list[str]
    n_chains: int
    drains: int
    usd: float
    first: str
    last: str
    spread_seconds: int     # time between first and last chain drained


@dataclass
class ChainRow:
    chain: str
    txs: int
    drains: int
    victims: int
    usd_in: float
    usd_out: float
    junk_inbound: int
    first_drain: str
    last_drain: str


@dataclass
class Venue:
    address: str
    label: str
    txs: int
    chains: str
    events: str


@dataclass
class Findings:
    address: str
    overview: dict
    chains: list[ChainRow]
    victims: list[Victim]
    hourly: list[dict]
    assets_in: list[dict]
    venues: list[Venue]
    cashout: list[dict]
    junk: dict
    cadence: dict
    mirrors: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def analyze(address: str, txs: list[dict], moves: list[C.Movement]) -> Findings:
    a = address.lower()
    ok = [m for m in moves if m.flag == C.OK]
    # dust from vanity twins of the attacker is poisoning, not a victim
    drains_in = [m for m in ok if m.direction == "in" and m.role in VICTIM_ROLES
                 and not is_lookalike(m.counterparty, a)]
    drain_ids = {id(m) for m in drains_in}

    # --- per victim --------------------------------------------------------
    vic = defaultdict(lambda: {"chains": set(), "drains": 0, "usd": 0.0, "times": []})
    for m in drains_in:
        v = vic[m.counterparty]
        v["chains"].add(m.chain); v["drains"] += 1; v["usd"] += m.usd or 0; v["times"].append(m.time)
    victims = []
    for w, v in vic.items():
        ts = sorted(v["times"])
        victims.append(Victim(w, sorted(v["chains"]), len(v["chains"]), v["drains"], round(v["usd"], 2), ts[0], ts[-1],
                              int((iso(ts[-1]) - iso(ts[0])).total_seconds())))
    victims.sort(key=lambda x: -x.usd)

    # --- per chain ---------------------------------------------------------
    per = defaultdict(lambda: {"txs": 0, "drains": 0, "victims": set(), "in": 0.0, "out": 0.0, "junk": 0, "times": []})
    for t in txs:
        per[t["chain"]]["txs"] += 1
    for m in moves:
        p = per[m.chain]
        if m.flag in (C.SPOOF, C.SCAM, C.ZERO) and m.direction == "in":
            p["junk"] += 1
        if m.flag != C.OK:
            continue
        if id(m) in drain_ids:  # only victim-signed value counts as drained
            p["in"] += m.usd or 0
            p["drains"] += 1; p["victims"].add(m.counterparty); p["times"].append(m.time)
        elif m.direction == "out" and m.role == C.ATTACKER_TX and m.plain:
            p["out"] += m.usd or 0  # direct sends only; swap legs would double count
    chains = [ChainRow(ch, p["txs"], p["drains"], len(p["victims"]), round(p["in"], 2), round(p["out"], 2), p["junk"],
                       min(p["times"]) if p["times"] else "", max(p["times"]) if p["times"] else "")
              for ch, p in per.items()]
    chains.sort(key=lambda r: -r.usd_in)

    # --- timeline ------------------------------------------------------------
    hourly = defaultdict(lambda: {"drains": 0, "usd": 0.0, "chains": set()})
    for m in drains_in:
        h = m.time[:13] + ":00Z"
        hourly[h]["drains"] += 1; hourly[h]["usd"] += m.usd or 0; hourly[h]["chains"].add(m.chain)
    hourly_rows = [{"hour_utc": h, "drains": v["drains"], "usd": round(v["usd"], 2), "chains": len(v["chains"])}
                   for h, v in sorted(hourly.items())]

    # --- cadence: how fast did the sweeper move? -----------------------------
    times = sorted(iso(m.time) for m in drains_in)
    gaps = [(b - c).total_seconds() for c, b in zip(times, times[1:])]
    multi = [v for v in victims if v.n_chains > 1]
    first_hour = [t for t in times if times and (t - times[0]).total_seconds() <= 3600]
    per_second = Counter(m.time for m in drains_in)
    cadence = {
        "median_gap_seconds_between_drains": statistics.median(gaps) if gaps else None,
        "drains_in_first_hour": len(first_hour),
        "max_drains_in_one_second": max(per_second.values()) if per_second else 0,
        "victims_hit_on_multiple_chains": len(multi),
        "max_chains_for_one_victim": max((v.n_chains for v in victims), default=0),
        "median_cross_chain_spread_seconds": statistics.median([v.spread_seconds for v in multi]) if multi else None,
    }

    # --- what came in -------------------------------------------------------
    by_asset = defaultdict(lambda: {"usd": 0.0, "n": 0})
    for m in drains_in:
        by_asset[m.asset]["usd"] += m.usd or 0; by_asset[m.asset]["n"] += 1
    assets_in = [{"asset": k, "usd": round(v["usd"], 2), "transfers": v["n"]}
                 for k, v in sorted(by_asset.items(), key=lambda kv: -kv[1]["usd"])]

    # --- attacker-signed activity: where did they route funds? ---------------
    ven = defaultdict(lambda: {"n": 0, "chains": set(), "events": Counter(), "names": set()})
    for t in txs:
        if t["from"] != a:
            continue
        v = ven[t["to"]]
        v["n"] += 1; v["chains"].add(t["chain"])
        for lg in t["logs"]:
            if lg.get("event"):
                v["events"][lg["event"]] += 1
            if lg.get("sender_address") == t["to"] and lg.get("sender_name"):
                v["names"].add(lg["sender_name"])
    venues = [Venue(addr, label(addr, v["names"]), v["n"], ",".join(sorted(v["chains"])),
                    ", ".join(f"{k}×{n}" for k, n in v["events"].most_common(5)))
              for addr, v in sorted(ven.items(), key=lambda kv: -kv[1]["n"])]

    # --- cash-out: value the attacker pushed to plain addresses -------------
    outs = defaultdict(lambda: {"usd": 0.0, "n": 0, "assets": Counter(), "first": None, "txs": [], "direct": False})
    for m in ok:
        if m.direction != "out" or m.role != C.ATTACKER_TX:
            continue
        o = outs[(m.chain, m.counterparty)]
        o["usd"] += m.usd or 0; o["n"] += 1; o["assets"][m.asset] += m.amount
        o["first"] = min(o["first"] or m.time, m.time); o["txs"].append(m.tx_hash)
        # direct send = plain native transfer or plain token.transfer(), not a swap/bridge call
        o["direct"] |= m.plain
    cashout = [{"chain": ch, "recipient": r, "usd": round(o["usd"], 2), "transfers": o["n"], "first": o["first"],
                "assets": ", ".join(f"{k} {v:,.4f}" for k, v in o["assets"].most_common(3)),
                "kind": "direct_send" if o["direct"] else "via_contract",
                "label": label(r), "example_tx": o["txs"][0]}
               for (ch, r), o in sorted(outs.items(), key=lambda kv: -kv[1]["usd"])]

    # --- junk inbound: poisoning & spoofed tokens -----------------------------
    junk_moves = [m for m in moves if m.direction == "in" and m.flag in (C.SPOOF, C.SCAM, C.ZERO)]
    junk = {
        "transfers": len(junk_moves),
        "lookalike_spoof": sum(m.flag == C.SPOOF for m in junk_moves),
        "scam_airdrop": sum(m.flag == C.SCAM for m in junk_moves),
        "zero_value": sum(m.flag == C.ZERO for m in junk_moves),
        "distinct_contracts": len({(m.chain, m.contract) for m in junk_moves}),
        "examples": [ascii(s) for s, _ in Counter(m.asset for m in junk_moves if m.flag == C.SPOOF).most_common(8)],
        "unpriced_transfers_excluded": sum(m.flag == C.UNPRICED for m in moves),
        "outlier_marks_excluded": sum(m.flag == C.OUTLIER for m in moves),
    }

    usd_in = sum(m.usd or 0 for m in drains_in)
    usd_out = sum(r["usd"] for r in cashout if r["kind"] == "direct_send")
    victim_set = {v.wallet for v in victims}
    # verification of "no approve+transferFrom drains": attacker-signed inbound legs pulled from a victim
    pulls_from_victims = sum(1 for m in ok if m.direction == "in" and m.role == C.ATTACKER_TX
                             and m.counterparty in victim_set)

    # --- poisoning aimed at the attacker: fake "attacker sent X" events -----
    # Bots deploy fake tokens whose Transfer events claim the attacker sent the
    # same amount to a lookalike of a real recipient, hoping the attacker later
    # copies the wrong address from their history.
    real = {(r["chain"], r["recipient"]): r for r in cashout}
    mirrors = []
    for m in moves:
        if m.direction != "out" or m.role == C.ATTACKER_TX or m.flag == C.OK:
            continue
        for (ch, rcp), r in real.items():
            if ch == m.chain and is_lookalike(m.counterparty, rcp):
                mirrors.append({"chain": ch, "real_recipient": rcp, "lookalike": m.counterparty,
                                "fake_token": ascii(m.asset), "amount": m.amount, "bot_signer": m.signer,
                                "time": m.time, "tx_hash": m.tx_hash})
    junk["mirror_events"] = len(mirrors)
    overview = {
        "chains_with_activity": len(per),
        "chains_with_drains": sum(1 for r in chains if r.drains),
        "transactions": len(txs),
        "victim_wallets": len(victims),
        "drain_transfers": len(drains_in),
        "usd_drained_priced": round(usd_in, 2),
        "usd_direct_sends_out": round(usd_out, 2),
        "attacker_signed_pulls_from_victims": pulls_from_victims,
        "first_drain": times[0].isoformat().replace("+00:00", "Z") if times else None,
        "last_drain": times[-1].isoformat().replace("+00:00", "Z") if times else None,
        "roles": dict(Counter(C.tx_role(t, a) for t in txs)),
    }
    return Findings(a, overview, chains, victims, hourly_rows, assets_in, venues, cashout, junk, cadence, mirrors)


def is_lookalike(candidate: str, target: str, head: int = 3, tail: int = 4) -> bool:
    """Address-poisoning check: same leading/trailing hex chars, different address.
    Wallet UIs show roughly `0xd97…b2ee`, which is all a vanity generator must match."""
    c, t = candidate.lower()[2:], target.lower()[2:]
    return c != t and c[:head] == t[:head] and c[-tail:] == t[-tail:]
