"""Turn raw GoldRush transactions into typed value movements.

Pure functions only (no I/O) so every rule here is unit-tested.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable

from .labels import CANONICAL
from .util import lower

# --- roles a transaction can play relative to the traced address -------------
VICTIM_NATIVE = "victim_signed_native"   # victim key signed a native transfer to attacker
VICTIM_TOKEN = "victim_signed_token"     # victim key signed an ERC-20 transfer to attacker
ATTACKER_TX = "attacker_initiated"       # attacker's own key: approvals, swaps, bridges, cash-out
THIRD_PARTY = "third_party_push"         # someone else pushed tokens in (airdrops, poisoning)
OTHER = "other"

# --- movement flags ------------------------------------------------------------
OK, SPOOF, SCAM, UNPRICED, OUTLIER, ZERO = ("ok", "lookalike_spoof", "scam_airdrop", "unpriced",
                                           "outlier_mark", "zero")
_URLISH = re.compile(r"https?:|www\.|\.(com|cfd|xyz|org|io|net|app|site|top|vip)\b|claim|visit|reward", re.I)


@dataclass
class Movement:
    direction: str            # "in" | "out" relative to the traced address
    chain: str
    time: str
    tx_hash: str
    role: str
    signer: str               # tx.from (who signed / paid gas)
    tx_to: str                # tx.to (contract or wallet the signer called)
    counterparty: str         # sender for inflows, recipient for outflows
    asset: str
    contract: str             # "native" or token contract
    amount: float
    usd: float | None = None
    flag: str = ""
    native_rate: float | None = field(default=None, repr=False)
    plain: bool = False       # a bare send (no swap/bridge logic ran in the tx)
    decimals_known: bool = True


def slim_tx(tx: dict, chain: str) -> dict:
    """Keep what the analysis needs; drop the bulky parts of each log."""
    logs = []
    for lg in tx.get("log_events") or []:
        d = lg.get("decoded") or {}
        entry = {
            "sender_address": lower(lg.get("sender_address")),
            "sender_name": lg.get("sender_name"),
            "ticker": lg.get("sender_contract_ticker_symbol"),
            "decimals": lg.get("sender_contract_decimals"),
            "event": d.get("name"),
        }
        if d.get("name") == "Transfer":
            entry["params"] = {p.get("name"): p.get("value") for p in (d.get("params") or [])}
        logs.append(entry)
    gm = tx.get("gas_metadata") or {}
    return {
        "chain": chain,
        "time": tx.get("block_signed_at"),
        "block": tx.get("block_height"),
        "tx_hash": tx.get("tx_hash"),
        "from": lower(tx.get("from_address")),
        "to": lower(tx.get("to_address")),
        "value": str(tx.get("value") or "0"),
        "value_quote": tx.get("value_quote"),
        "native_rate": tx.get("gas_quote_rate"),
        "native_symbol": gm.get("contract_ticker_symbol") or "NATIVE",
        "native_decimals": gm.get("contract_decimals") or 18,
        "fee_usd": tx.get("gas_quote"),
        "successful": tx.get("successful"),
        "logs": logs,
    }


def _transfers(tx: dict) -> Iterable[tuple[dict, str, str, int]]:
    for lg in tx["logs"]:
        if lg.get("event") != "Transfer" or not lg.get("params"):
            continue
        p = lg["params"]
        if "value" not in p:
            continue  # ERC-721 (tokenId, no value): not a fungible amount
        if lg.get("sender_address") in NATIVE_TOKEN_CONTRACTS.get(tx["chain"], ()) and int(tx["value"]) > 0:
            continue  # chains whose native coin also emits an ERC-20 Transfer: already counted as native
        try:
            raw = int(p.get("value") or 0)
        except (TypeError, ValueError):
            continue  # malformed
        yield lg, lower(str(p.get("from", ""))), lower(str(p.get("to", ""))), raw


def tx_role(tx: dict, address: str) -> str:
    a = lower(address)
    if tx["from"] == a:
        return ATTACKER_TX
    if tx["to"] == a and int(tx["value"]) > 0:
        return VICTIM_NATIVE
    roles = set()
    for _lg, f, t, _raw in _transfers(tx):
        if t == a:
            roles.add(VICTIM_TOKEN if f == tx["from"] else THIRD_PARTY)
    if VICTIM_TOKEN in roles:
        return VICTIM_TOKEN
    return THIRD_PARTY if roles else OTHER


POLYGON_NATIVE_LOGGER = "0x0000000000000000000000000000000000001010"  # emits LogTransfer on every POL send
# Native coins that ALSO emit an ERC-20 Transfer log for plain value transfers (double-count risk).
NATIVE_TOKEN_CONTRACTS = {
    "celo-mainnet": {"0x471ece3750da237f93b8e339c536989b8978a438"},
    "zksync-mainnet": {"0x000000000000000000000000000000000000800a"},
    "metis-mainnet": {"0xdeaddeaddeaddeaddeaddeaddeaddeaddead0000"},
}


def _is_plain(tx: dict, contract: str, counterparty: str) -> bool:
    logs = [lg for lg in tx["logs"] if lg.get("sender_address") != POLYGON_NATIVE_LOGGER]
    if contract == "native":
        return tx["to"] == counterparty and not logs
    return tx["to"] == contract and all(lg.get("event") == "Transfer" and lg.get("sender_address") == contract
                                        for lg in logs)


def movements(tx: dict, address: str) -> list[Movement]:
    """Every native or ERC-20 transfer into or out of `address` in this tx."""
    if tx.get("successful") is False:
        return []
    a, role, out = lower(address), tx_role(tx, address), []
    val = int(tx["value"])
    if val:
        amt = val / 10 ** int(tx["native_decimals"])
        common = dict(chain=tx["chain"], time=tx["time"], tx_hash=tx["tx_hash"], role=role, signer=tx["from"],
                      tx_to=tx["to"], asset=tx["native_symbol"], contract="native", amount=amt, usd=tx.get("value_quote"),
                      native_rate=tx.get("native_rate"))
        if tx["to"] == a:
            out.append(Movement("in", counterparty=tx["from"], **common))
        elif tx["from"] == a:
            out.append(Movement("out", counterparty=tx["to"], plain=_is_plain(tx, "native", tx["to"]), **common))
    for lg, f, t, raw in _transfers(tx):
        if a not in (f, t) or f == t:
            continue
        dec = lg.get("decimals")
        amt = raw / 10 ** int(dec if dec is not None else 18)
        common = dict(chain=tx["chain"], time=tx["time"], tx_hash=tx["tx_hash"], role=role, signer=tx["from"],
                      tx_to=tx["to"], asset=str(lg.get("ticker") or lg["sender_address"]), contract=lg["sender_address"],
                      amount=amt, decimals_known=dec is not None)
        if t == a:
            out.append(Movement("in", counterparty=f, **common))
        else:
            out.append(Movement("out", counterparty=t, plain=_is_plain(tx, lg["sender_address"], t), **common))
    return out


# --- spoof detection & pricing -------------------------------------------------
_INVISIBLE = {"Cf", "Mn", "Zs"}  # format chars (zero-width), combining marks, odd spaces


def looks_like_spoof(symbol: str) -> bool:
    """True for symbols padded with invisible/combining characters, or using
    Cyrillic/Greek/Armenian/Lisu/etc. homoglyphs inside an otherwise Latin
    ticker (e.g. 'ꓴ឵ՏᎠ឵Ⲧ', 'U‍SDT'). Legit non-ASCII tickers like 'USD₮'
    only use symbols/currency signs, which this allows."""
    s = symbol or ""
    if any(unicodedata.category(ch) in _INVISIBLE and ch != " " for ch in s):
        return True
    letters = [ch for ch in s if ch.isalpha()]
    latin = sum(1 for ch in letters if ch.isascii())
    foreign = [ch for ch in letters if not ch.isascii()]
    if not foreign:
        return False
    scripts = {unicodedata.name(ch, "?").split()[0] for ch in foreign}
    # a mostly-foreign-script name (e.g. Chinese meme token) is not a homoglyph trick
    return latin > 0 or bool(scripts & {"CYRILLIC", "GREEK", "ARMENIAN", "LISU", "CHEROKEE", "COPTIC",
                                         "KHMER", "LATIN"})


def apply_prices(moves: list[Movement], prices: dict[tuple[str, str], float],
                 max_usd_per_move: float = 250_000.0) -> None:
    """Fill `usd` and `flag`. Value counts only if we can price it honestly:
    native via tx quote/native rate, tokens via GoldRush historical price.
    Large marks on thin tokens are flagged; native coins and canonical
    stablecoins/majors are trusted at any size (a $256k USDT drain is real)."""
    for m in moves:
        if m.contract == "native":
            if not m.usd and m.native_rate:  # missing OR zero quote: fall back to the native rate
                m.usd = m.amount * float(m.native_rate)
        else:
            p = prices.get((m.chain, m.contract))
            m.usd = m.amount * p if p is not None else None
        if not m.amount:
            m.flag = ZERO
        elif m.contract != "native" and m.usd is None and looks_like_spoof(m.asset):
            m.flag = SPOOF
        elif m.contract != "native" and m.usd is None and _URLISH.search(m.asset):
            m.flag = SCAM
        elif m.usd is None or not m.decimals_known:  # unknown decimals = unknown amount
            m.flag = UNPRICED
        elif m.usd > max_usd_per_move and m.contract != "native" and (m.chain, m.contract) not in CANONICAL:
            m.flag = OUTLIER
        else:
            m.flag = OK
