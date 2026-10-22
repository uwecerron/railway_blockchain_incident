"""Write findings to Markdown + CSV. Formatting only."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .forensics import Findings
from .util import short, write_csv, write_json


def _usd(x) -> str:
    return f"${x:,.0f}" if x is not None else "n/a"


def _dur(seconds) -> str:
    if seconds is None:
        return "n/a"
    s = int(seconds)
    return f"{s // 3600}h {s % 3600 // 60}m" if s >= 3600 else f"{s // 60}m {s % 60}s" if s >= 60 else f"{s}s"


def write(out: Path, f: Findings, hops: list[dict], moves, txs) -> Path:
    write_csv(out / "chains.csv", f.chains)
    write_csv(out / "victims.csv", f.victims)
    write_csv(out / "hourly.csv", f.hourly)
    write_csv(out / "venues.csv", f.venues)
    write_csv(out / "cashout.csv", f.cashout)
    write_csv(out / "hops.csv", hops)
    write_csv(out / "poisoning_mirrors.csv", f.mirrors)
    write_csv(out / "movements.csv", moves)
    write_csv(out / "transactions.csv", [{k: t[k] for k in ("chain", "time", "block", "tx_hash", "from", "to", "value",
                                                            "value_quote", "fee_usd", "successful")} for t in txs])
    write_json(out / "findings.json", {"overview": f.overview, "cadence": f.cadence, "junk": f.junk,
                                       "assets_in": f.assets_in, "hops": hops})
    o, c, j = f.overview, f.cadence, f.junk
    L = [
        f"# Forensic trace: `{f.address}`", "",
        f"_Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC from Covalent GoldRush data._", "",
        "## Headline", "",
        f"- **{o['victim_wallets']} victim wallets** drained across **{o['chains_with_drains']} chains** "
        f"(activity on {o['chains_with_activity']} chains, {o['transactions']} transactions).",
        f"- **{_usd(o['usd_drained_priced'])} priced value** taken in {o['drain_transfers']} drain transfers.",
        f"- First drain **{o['first_drain']}**, last **{o['last_drain']}**.",
        f"- Transaction roles: {', '.join(f'{k} {v}' for k, v in sorted(o['roles'].items(), key=lambda x: -x[1]))}.", "",
        "## How the sweeper behaved", "",
        f"- {c['drains_in_first_hour']} drains in the first hour; median gap between drains {_dur(c['median_gap_seconds_between_drains'])}.",
        f"- Up to {c['max_drains_in_one_second']} drains landed in the same second.",
        f"- {c['victims_hit_on_multiple_chains']} wallets were drained on more than one chain "
        f"(max {c['max_chains_for_one_victim']}); median spread between a wallet's first and last chain "
        f"{_dur(c['median_cross_chain_spread_seconds'])}.", "",
        "## Per chain", "",
        "| Chain | Txs | Drains | Victims | USD in | USD out | Junk inbound | First drain | Last drain |",
        "|---|---:|---:|---:|---:|---:|---:|---|---|",
    ]
    for r in f.chains:
        L.append(f"| {r.chain} | {r.txs} | {r.drains} | {r.victims} | {_usd(r.usd_in)} | {_usd(r.usd_out)} | "
                 f"{r.junk_inbound} | {r.first_drain[11:19]} | {r.last_drain[11:19]} |")
    L += ["", "## What was taken", "", "| Asset | USD | Transfers |", "|---|---:|---:|"]
    L += [f"| {x['asset']} | {_usd(x['usd'])} | {x['transfers']} |" for x in f.assets_in[:15]]
    L += ["", "## Largest victims", "", "| Wallet | USD | Chains | Drains | Spread |", "|---|---:|---:|---:|---:|"]
    L += [f"| `{v.wallet}` | {_usd(v.usd)} | {v.n_chains} | {v.drains} | {_dur(v.spread_seconds)} |" for v in f.victims[:15]]
    L += ["", "## Hour by hour (UTC)", "", "| Hour | Drains | USD | Chains |", "|---|---:|---:|---:|"]
    L += [f"| {h['hour_utc'][5:16]} | {h['drains']} | {_usd(h['usd'])} | {h['chains']} |" for h in f.hourly]
    L += ["", "## Contracts the attacker called", "", "| Contract | Label | Txs | Chains | Events |", "|---|---|---:|---|---|"]
    L += [f"| `{short(v.address, 10)}` | {v.label} | {v.txs} | {v.chains} | {v.events} |" for v in f.venues[:15]]
    L += ["", "## Value the attacker sent out", "", "| Chain | Recipient | USD | Assets | First |", "|---|---|---:|---|---|"]
    L += [f"| {x['chain']} | `{x['recipient']}` | {_usd(x['usd'])} | {x['assets']} | {x['first']} |"
          for x in f.cashout[:15]]
    if hops:
        L += ["", "## Following the cash-out", "",
              "| Chain | Hop | Address | Total txs | First seen | Verdict | Forwarded to | Gas top-up from |",
              "|---|---:|---|---:|---|---|---|---|"]
        L += [f"| {h['chain']} | {h['depth']} | `{h['address']}` | "
              f"{h['total_txs'] if h['total_txs'] is not None else 'n/a'} | {(h['first_seen'] or '')[:10]} | "
              f"{h['verdict']} | `{h['forwarded_to'] or '-'}` {('(' + h['forward_kind'] + ')') if h['forward_kind'] else ''} | "
              f"{('`' + h['gas_funder'] + '`') if h['gas_funder'] else '-'} |" for h in hops]
        poison = sorted({p for h in hops for p in h["poison_senders"].split(",") if p})
        if poison:
            L += ["", "Lookalike senders (address poisoning aimed at the attacker's own history): "
                      + ", ".join(f"`{p}`" for p in poison)]
    if f.mirrors:
        L += ["", "## Poisoning aimed at the attacker", "",
              "Bots mirrored the attacker's real cash-outs with fake-token Transfer events to lookalike addresses.", "",
              "| Chain | Real recipient | Lookalike | Fake token | Amount | Time |", "|---|---|---|---|---:|---|"]
        L += [f"| {x['chain']} | `{x['real_recipient']}` | `{x['lookalike']}` | {x['fake_token']} | {x['amount']:,.2f} | "
              f"{x['time']} |" for x in f.mirrors[:20]]
    L += ["", "## Junk sent to the attacker (excluded from totals)", "",
          f"- {j['transfers']} inbound junk transfers from {j['distinct_contracts']} contracts: "
          f"{j['lookalike_spoof']} lookalike-ticker spoofs, {j['scam_airdrop']} scam airdrops, {j['zero_value']} zero-value.",
          f"- Spoofed tickers seen (escaped to show hidden characters): {', '.join(j['examples']) or 'none'}",
          f"- Also excluded: {j['unpriced_transfers_excluded']} unpriced transfers, "
          f"{j['outlier_marks_excluded']} transfers with implausible marks (> $250k per transfer).", "",
          "## Method", "",
          "- Activity: `GET /v1/address/{addr}/activity/`. History: `transactions_v3/page/{n}` walking `links.next` from page 0.",
          "- Roles from who signed: a victim's key signing a transfer to the attacker = drain; attacker's key = routing.",
          "- USD: native via the tx's `value_quote` (or `gas_quote_rate`), tokens via GoldRush historical price that day. "
          "Tokens with no price and lookalike tickers are excluded rather than guessed.", ""]
    path = out / "REPORT.md"
    path.write_text("\n".join(L), encoding="utf-8")
    return path


def hops_as_dicts(hops) -> list[dict]:
    return [asdict(h) for h in hops]
