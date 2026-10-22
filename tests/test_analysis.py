import unittest
from datetime import datetime, timezone

from railway_trace import classify as C
from railway_trace import forensics as F
from railway_trace import goldrush as G

ATK = "0xd9773325282874d18cb83f1fe50f14c39750b2ee"
V1 = "0x" + "11" * 20
V2 = "0x" + "22" * 20
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
SPOOFC = "0x" + "ab" * 20
ROUTER = "0x" + "cc" * 20
DEPOSIT = "0x" + "dd" * 20


def tx(chain, t, frm, to, value=0, quote=None, logs=(), rate=2500.0):
    return {"chain": chain, "time": t, "block": 1, "tx_hash": f"0x{abs(hash((chain, t, frm, to, value))):x}",
            "from": frm, "to": to, "value": str(value), "value_quote": quote, "native_rate": rate,
            "native_symbol": "ETH", "native_decimals": 18, "fee_usd": 0.1, "successful": True, "logs": list(logs)}


def transfer(contract, ticker, frm, to, raw, decimals=6):
    return {"sender_address": contract, "sender_name": ticker, "ticker": ticker, "decimals": decimals,
            "event": "Transfer", "params": {"from": frm, "to": to, "value": str(raw)}}


def fixture():
    return [
        tx("eth-mainnet", "2026-10-21T19:36:23Z", V1, ATK, value=10**18, quote=2500.0),                  # native drain
        tx("eth-mainnet", "2026-10-21T19:36:25Z", V1, USDC, logs=[transfer(USDC, "USDC", V1, ATK, 1_000 * 10**6)]),
        tx("base-mainnet", "2026-10-21T19:40:00Z", V1, ATK, value=10**17, quote=None, rate=2400.0),      # quote missing
        tx("eth-mainnet", "2026-10-21T19:50:00Z", V2, ATK, value=2 * 10**18, quote=5000.0),
        tx("eth-mainnet", "2026-10-21T20:00:00Z", "0x" + "99" * 20, SPOOFC,                             # poisoning push
           logs=[transfer(SPOOFC, "U‍SDT", "0x" + "98" * 20, ATK, 5_000 * 10**6)]),
        tx("eth-mainnet", "2026-10-21T21:00:00Z", ATK, ROUTER,                                          # swap
           logs=[transfer(USDC, "USDC", ATK, ROUTER, 900 * 10**6), {"sender_address": ROUTER, "event": "Swap"}]),
        tx("eth-mainnet", "2026-10-22T00:00:23Z", ATK, DEPOSIT, value=3 * 10**18, quote=7500.0),       # cash-out
        tx("eth-mainnet", "2026-10-22T00:05:00Z", "0x" + "77" * 20, SPOOFC,                             # mirror event
           logs=[transfer(SPOOFC, "U\u200dSDT", ATK, "0x" + "dd" * 2 + "00" * 16 + "dd" * 2, 3 * 10**6)]),
    ]


class RoleTests(unittest.TestCase):
    def test_roles(self):
        t = fixture()
        self.assertEqual(C.tx_role(t[0], ATK), C.VICTIM_NATIVE)
        self.assertEqual(C.tx_role(t[1], ATK), C.VICTIM_TOKEN)
        self.assertEqual(C.tx_role(t[4], ATK), C.THIRD_PARTY)
        self.assertEqual(C.tx_role(t[5], ATK), C.ATTACKER_TX)

    def test_failed_tx_moves_nothing(self):
        t = fixture()[0]
        t["successful"] = False
        self.assertEqual(C.movements(t, ATK), [])


class SpoofTests(unittest.TestCase):
    def test_spoofs(self):
        for s in ["U‍SDT", "ꓴ឵ՏᎠ឵Ⲧ", "USḌC", " UЅDC", "UЅDT"]:
            self.assertTrue(C.looks_like_spoof(s), s)

    def test_legit(self):
        for s in ["USDC", "USDC.e", "USD₮", "喜羊羊", "PEPE", "pUSD"]:
            self.assertFalse(C.looks_like_spoof(s), s)


class PricingTests(unittest.TestCase):
    def test_apply(self):
        moves = [m for t in fixture() for m in C.movements(t, ATK)]
        C.apply_prices(moves, {("eth-mainnet", USDC): 1.0})
        by = {(m.chain, m.asset, m.direction): m for m in moves}
        self.assertAlmostEqual(by[("base-mainnet", "ETH", "in")].usd, 240.0)  # native via gas_quote_rate
        self.assertEqual(by[("eth-mainnet", "U‍SDT", "in")].flag, C.SPOOF)
        self.assertEqual(by[("eth-mainnet", "USDC", "in")].usd, 1000.0)

    def test_outlier(self):
        m = C.Movement("in", "eth-mainnet", "t", "h", C.VICTIM_TOKEN, V1, USDC, V1, "SOS", "0xsos", 1e9)
        C.apply_prices([m], {("eth-mainnet", "0xsos"): 0.01})
        self.assertEqual(m.flag, C.OUTLIER)


class CanonicalCapTests(unittest.TestCase):
    def test_big_real_stablecoin_counts(self):
        usdt = "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"
        m = C.Movement("in", "arbitrum-mainnet", "t", "h", C.VICTIM_TOKEN, V1, usdt, V1, "USDT", usdt, 261_538.49)
        C.apply_prices([m], {("arbitrum-mainnet", usdt): 0.98})
        self.assertEqual(m.flag, C.OK)


class ForensicsTests(unittest.TestCase):
    def setUp(self):
        self.txs = fixture()
        self.moves = [m for t in self.txs for m in C.movements(t, ATK)]
        C.apply_prices(self.moves, {("eth-mainnet", USDC): 1.0})
        self.f = F.analyze(ATK, self.txs, self.moves)

    def test_overview(self):
        o = self.f.overview
        self.assertEqual(o["victim_wallets"], 2)
        self.assertEqual(o["chains_with_drains"], 2)
        self.assertAlmostEqual(o["usd_drained_priced"], 2500 + 1000 + 240 + 5000)
        self.assertEqual(o["first_drain"], "2026-10-21T19:36:23Z")

    def test_victims_and_spread(self):
        v1 = next(v for v in self.f.victims if v.wallet == V1)
        self.assertEqual(v1.n_chains, 2)
        self.assertEqual(v1.spread_seconds, 217)
        self.assertEqual(self.f.cadence["victims_hit_on_multiple_chains"], 1)

    def test_junk_excluded(self):
        self.assertEqual(self.f.junk["lookalike_spoof"], 1)
        self.assertNotIn("U‍SDT", [a["asset"] for a in self.f.assets_in])

    def test_cashout_kinds(self):
        kinds = {r["recipient"]: r["kind"] for r in self.f.cashout}
        self.assertEqual(kinds[DEPOSIT], "direct_send")
        self.assertEqual(kinds[ROUTER], "via_contract")

    def test_mirror_poisoning_detected(self):
        self.assertEqual(len(self.f.mirrors), 1)
        self.assertEqual(self.f.mirrors[0]["real_recipient"], DEPOSIT)

    def test_lookalike(self):
        self.assertTrue(F.is_lookalike("0xd97995a8108d5f3a28b0d6ba59d43192c350b2ee", ATK))
        self.assertTrue(F.is_lookalike("0xd977b8626fd974d4a5d862c657626771c874b2ee", ATK))
        self.assertFalse(F.is_lookalike(ATK, ATK))
        self.assertFalse(F.is_lookalike("0x" + "00" * 20, ATK))


class PaginationTests(unittest.TestCase):
    def test_walks_next_from_page_zero(self):
        pages = {
            0: {"items": [{"block_signed_at": "2026-10-20T00:00:00Z", "id": 0},
                          {"block_signed_at": "2026-10-21T19:36:00Z", "id": 1}],
                "links": {"prev": None, "next": "p1"}},
            1: {"items": [{"block_signed_at": "2026-10-21T20:00:00Z", "id": 2}], "links": {"prev": "p0", "next": None}},
        }

        class Api:
            def get(self, path, params=None, cache=True):
                return pages[int(path.rstrip("/").split("/")[-1])]

        since = datetime(2026, 10, 21, tzinfo=timezone.utc)
        self.assertEqual([t["id"] for t in G.iter_transactions(Api(), "eth-mainnet", ATK, since)], [1, 2])


class PriceLookupTests(unittest.TestCase):
    def test_lookback_and_bad_contract_fallback(self):
        from railway_trace.client import ApiError
        good, bad = "0x" + "aa" * 20, "0x" + "ff" * 20

        class Api:
            def get(self, path, params=None, cache=True):
                assert params["from"] == "2026-10-14" and params["to"] == "2026-10-21"
                if bad in path:
                    raise ApiError(400, path, "Contract address not found")
                return [{"contract_address": good, "prices": [
                    {"date": "2026-10-22", "price": 5.0}, {"date": "2026-10-21", "price": None},
                    {"date": "2026-10-20", "price": 0.98}]}]

        self.assertEqual(G.historical_prices(Api(), "eth-mainnet", [good, bad], "2026-10-21"), {good: 0.98})


class HopTests(unittest.TestCase):
    def test_token_deposit_pattern_then_hot_wallet(self):
        from railway_trace import hops as H
        dep, hot, gas, tok = "0x" + "d1" * 20, "0x" + "e1" * 20, "0x" + "9a" * 20, "0x" + "70" * 20

        class Api:
            def get(self, path, params=None, cache=True):
                if path.endswith("transactions_summary/"):
                    n = 900_000 if hot in path else 4
                    return {"items": [{"total_count": n, "earliest_transaction": {"block_signed_at": "2026-10-21"}}]}
                if "/balances_v2/" in path:
                    return {"items": [{"quote": 1e6}]}
                if "/transaction_v2/" in path:
                    return {"items": [{"log_events": [{"decoded": {"name": "Transfer", "params": [
                        {"name": "from", "value": dep}, {"name": "to", "value": hot}, {"name": "value", "value": "1"}]}}]}]}
                return {"items": [
                    {"block_signed_at": "1", "from_address": ATK, "to_address": tok, "value": "0", "tx_hash": "a"},
                    {"block_signed_at": "2", "from_address": gas, "to_address": dep, "value": "5", "tx_hash": "b"},
                    {"block_signed_at": "3", "from_address": dep, "to_address": tok, "value": "0", "tx_hash": "c"}]}

        hops = H.follow(Api(), "arbitrum-mainnet", dep, ATK, 1000, ATK)
        self.assertEqual([h.address for h in hops], [dep, hot])
        self.assertEqual(hops[0].forward_kind, "token")
        self.assertEqual(hops[0].gas_funder, gas)
        self.assertIn("deposit-address", hops[0].verdict)
        self.assertIn("service", hops[1].verdict)


if __name__ == "__main__":
    unittest.main()
