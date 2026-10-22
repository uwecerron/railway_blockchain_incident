"""GoldRush endpoint wrappers. Each function knows one endpoint's shape.

Endpoints used (docs: https://goldrush.dev/docs):
  GET /v1/address/{addr}/activity/                           cross-chain activity
  GET /v1/{chain}/address/{addr}/transactions_v3/page/{n}/   paginated history
  GET /v1/{chain}/address/{addr}/transactions_summary/       counts, first/last tx
  GET /v1/{chain}/address/{addr}/balances_v2/                current balances
  GET /v1/pricing/historical_by_addresses_v2/{chain}/USD/{contracts}/
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Iterator, Protocol

from .client import ApiError
from .util import iso


class Getter(Protocol):
    def get(self, path: str, params: dict | None = None, cache: bool = True): ...


@dataclass(frozen=True)
class ChainActivity:
    chain_name: str
    chain_id: str | None
    label: str | None
    tier: str | None
    first_seen_at: str | None
    last_seen_at: str | None


def chain_activity(api: Getter, address: str) -> list[ChainActivity]:
    data = api.get(f"/v1/address/{address}/activity/", cache=False)
    rows = []
    for it in data.get("items") or []:
        ch = it.get("extends") or it  # fields are flat on the item; older shape nested them
        name = ch.get("name")
        if not name:
            continue
        rows.append(ChainActivity(name, ch.get("chain_id"), ch.get("label"), it.get("priority_label"),
                                  it.get("first_seen_at"), it.get("last_seen_at")))
    return rows


def iter_transactions(api: Getter, chain: str, address: str, since: datetime,
                      max_pages: int = 200, with_logs: bool = True) -> Iterator[dict]:
    """Yield txs at/after `since`. Page 0 is the OLDEST page; walk `links.next`
    forward until it is null (following `prev` from page 0 silently stops at 100)."""
    params = {"quote-currency": "USD"}
    if not with_logs:
        params["no-logs"] = "true"
    for page in range(max_pages):
        data = api.get(f"/v1/{chain}/address/{address}/transactions_v3/page/{page}/", params, cache=False)
        for tx in data.get("items") or []:
            if iso(tx["block_signed_at"]) >= since:
                yield tx
        if not (data.get("links") or {}).get("next"):
            return
    raise RuntimeError(f"{chain}: more than {max_pages} pages; raise max_pages")


def transactions_summary(api: Getter, chain: str, address: str) -> dict | None:
    items = api.get(f"/v1/{chain}/address/{address}/transactions_summary/").get("items") or []
    return items[0] if items else None


def first_page(api: Getter, chain: str, address: str) -> list[dict]:
    """Oldest page of history without logs (cheap; good for following a hop)."""
    return api.get(f"/v1/{chain}/address/{address}/transactions_v3/page/0/", {"no-logs": "true"}).get("items") or []


def latest_page(api: Getter, chain: str, address: str) -> list[dict]:
    """Most recent page of history without logs."""
    return api.get(f"/v1/{chain}/address/{address}/transactions_v3/", {"no-logs": "true"}).get("items") or []


def transaction(api: Getter, chain: str, tx_hash: str) -> dict | None:
    """One transaction with decoded logs."""
    items = api.get(f"/v1/{chain}/transaction_v2/{tx_hash}/").get("items") or []
    return items[0] if items else None


def balances_usd(api: Getter, chain: str, address: str) -> float:
    items = api.get(f"/v1/{chain}/address/{address}/balances_v2/", {"no-spam": "true"}).get("items") or []
    return float(sum((i.get("quote") or 0) for i in items))


def historical_prices(api: Getter, chain: str, contracts: list[str], day: str, batch: int = 20,
                      lookback_days: int = 7) -> dict[str, float]:
    """USD price per contract: the latest daily close on or before `day` within
    `lookback_days` (the current day's close is published late). Contracts with
    no price are omitted, which is itself a signal: fresh lookalike tokens have none.
    A batch rejected because of one bad contract is retried one contract at a time."""
    end = date.fromisoformat(day)
    params = {"from": (end - timedelta(days=lookback_days)).isoformat(), "to": end.isoformat()}
    uniq = sorted({c.lower() for c in contracts if c and c != "native"})
    out: dict[str, float] = {}

    def fetch(chunk: list[str]) -> None:
        data = api.get(f"/v1/pricing/historical_by_addresses_v2/{chain}/USD/{','.join(chunk)}/", params)
        for it in (data if isinstance(data, list) else (data.get("items") or [])):
            dated = sorted(((p.get("date") or "", p["price"]) for p in (it.get("prices") or [])
                            if p.get("price") and (p.get("date") or "") <= end.isoformat()), reverse=True)
            if dated and it.get("contract_address"):
                out[it["contract_address"].lower()] = float(dated[0][1])

    for i in range(0, len(uniq), batch):
        chunk = uniq[i:i + batch]
        try:
            fetch(chunk)
        except ApiError as e:
            if e.status != 400 or len(chunk) == 1:
                raise
            for one in chunk:
                try:
                    fetch([one])
                except ApiError as e1:
                    if e1.status != 400:
                        raise
    return out
