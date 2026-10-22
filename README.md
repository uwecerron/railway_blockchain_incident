# Railway drainer trace

On October 21, 2026 Railway had a breach that exposed customer environment variables. Some apps on Railway kept hot wallet private keys in those variables. A few hours later one address started emptying those wallets on every EVM chain it could reach:

`0xd9773325282874d18cb83f1fe50f14c39750b2ee`

[Tay Monahan (@tayvano_)](https://x.com/tayvano_/status/2113056813646238196) flagged it first. I wanted the full picture: every chain, every wallet, every dollar, and where it went. This repo is that trace, built on the [Covalent GoldRush API](https://goldrush.dev). It is a forensic report and a tool you can point at any other address.

All numbers come from `out/REPORT.md`, which this code generates. Window: Oct 21 00:00 UTC to Oct 22 about 17:00 UTC.

## If you run anything with keys in env vars, read this first

1. **Rotate now.** If a private key ever sat in a Railway variable, treat it as public. Move the funds to a fresh wallet that was never in that environment, then rotate. Rotating first and moving later just races the attacker.
2. **One key covers every EVM chain.** This attacker hit 22 chains, including ones most teams forget they have dust on: Robinhood Chain, MegaETH, Ink, Scroll, Unichain, Mantle, Berachain. Your key is good on all of them.
3. **Keep signing keys off app servers.** Use a KMS or HSM signer, an MPC wallet, or a separate signing service with its own credentials. An app server should ask for a signature, not hold the key.
4. **Keep hot wallets small.** The four biggest victims here lost $348K between them. Top up hot wallets on a schedule from cold storage. Don't park treasury money in them.
5. **Add spending limits where you can.** Smart accounts with per-day caps and allowlisted recipients would have stopped most of this.
6. **Watch your addresses.** Alert on any outbound transfer you didn't schedule. This sweep took about an hour, and a working alert gives you time to move.
7. **Never copy an address out of your transaction history.** Within minutes of every cash-out, poisoning bots planted lookalike addresses in the attacker's history. They will do it to you too.
8. **Check whether you were hit.** Search `out/victims.csv` for your addresses.

## What happened

| | |
|---|---|
| Chains with attacker activity | **22** (Tay counted 19+) |
| Chains where wallets were drained | **17** |
| Victim wallets | **231** |
| Drain transfers | **532** (860 transactions touched the address) |
| Value taken | **$381,503** (Tay estimated about $371K) |
| First touch | **Oct 21, 19:36:03 UTC** on Polygon |
| Last drain | **Oct 22, 02:32:07 UTC** on Celo |
| Sent on to exchange deposit addresses | **about $380K, within about 5 hours** |

The $381,503 is a floor. I only count a transfer when I can price it honestly. Native coins use the transaction's own USD quote, and tokens use GoldRush's daily price. 117 transfers of tokens with no price are left out, and so is about $2K of native POL, MON, HYPE and Arc USDC with no quote.

### The keys were stolen, not phished

Every transaction is sorted by who signed it.

| Signed by | Txs | What it means |
|---|---:|---|
| Victim key, native coin | 408 | The victim's own key sent ETH/BNB/etc. to the attacker |
| Victim key, token | 209 | The victim's own key called `transfer()` to the attacker |
| Attacker key | 169 | Approvals, swaps, bridges, cash-out |
| Someone else | 38 | Spam and poisoning pushed into the attacker |
| Other | 36 | Mostly fake "attacker sent" events from poisoning contracts |

617 transactions were signed with the victims' own keys. I also checked the other direction: there are zero transactions where the attacker pulled tokens out of a victim wallet using an approval. No drainer contract, no phishing site. The attacker had the raw private keys, which is exactly what leaked env vars give you.

The biggest victims were busy app wallets, not personal ones. `0xf51731a1…52fb` had 47,216 transactions on Arbitrum, `0xf78b2eda…d6ce` had 171,423 on Ethereum, and `0x661f257d…098a` had been active on Polygon since 2021. Those are bot and service keys that live on servers.

Money that reached the attacker without a victim signature ($32.8K from bridge fills, CCTP mints and swap returns on the attacker's own funds) is not counted as drained, so nothing is counted twice.

### Timeline (UTC)

| Time | What happened |
|---|---|
| **19:36:03** | First touch. 944.75 POL taken from `0xe56c1c45…e6cb` on Polygon. The same wallet was drained on Ethereum 20 seconds later. ([Polygon tx](https://polygonscan.com/tx/0x9a7b4ef1b7bd758934e0b47d110b36ba3afe19568799f86e1a27018ce11e509a), [Ethereum tx](https://etherscan.io/tx/0x6868f0c25cd63142a388b29ed48362305f4b537c52aa38398688eda2576c6c93)) |
| 19:36 to 20:59 | Testing. Five small drains, about $156, on three chains. |
| **21:13 to 21:55** | The big ones. 261,538 USDT from one wallet on Arbitrum ($256,149, two thirds of everything, [tx](https://arbiscan.io/tx/0x2f25c3ab8ba6cb2e23b8fc1a71d62bb8897dc19070e8e16338c4dc66afebb9b4)). 34,433 USDC on Ethereum ([tx](https://etherscan.io/tx/0x3c233b37b02be8cd6dc49e2d5bf3bee9658485fb838391f016421114e8757964)). 23,649 pUSD on Polygon ([tx](https://polygonscan.com/tx/0xc43398d378f21597e197d0ffd4239f4a3592975784b6d7eb2366defad1bbae0a)). $330K in that hour. |
| **22:00 to 22:59** | The sweep. 490 drains on 17 chains in one hour, one every 3 seconds on median. Ten smaller chains (Avalanche, Optimism, Ink, Unichain, Scroll, MegaETH, Mantle, Blast, Berachain, World) were all emptied between 22:27:09 and 22:30:31. |
| 23:13 to 23:50 | Consolidation. Swaps through DEX aggregators, the 0x AllowanceHolder and LI.FI. USDC moved over Circle CCTP. |
| **23:53 to 00:20** | Cash-out. 225,146 and 40,044 USDT to two Arbitrum deposit addresses, 55,047 USDC and 14.34 ETH on Ethereum, 15,187 USDC on Polygon. |
| 23:56 onward | Poisoning bots start going after the attacker, 2 to 7 minutes after each big cash-out. |
| 01:35 to 06:19 | The exchanges sweep those deposit addresses into their hot wallets. |
| 03:04 | One more 9,372 USDC send, to a deposit address that has existed since August 2020 ([tx](https://etherscan.io/tx/0x1769d1c449c0b08ab5cee2117f250f967ad1d1cd775b918442ebd194c6fe6fd8)). |

### How the script behaved

- **Parallel across chains.** 80 wallets were drained on more than one chain, up to 7. Median time between a wallet's first and last chain was about 30 minutes.
- **DeFi aware.** It took a victim's `syrupUSDC` and filed a Maple redemption request for it, for a $5 position ([tx](https://etherscan.io/tx/0x1fd718ed30c66463328d5300b3e6b400b54f059d8bf863adaaaca325b8d5a292)). Polymarket `pUSD` went out through LI.FI and an order-based bridge.
- **New chains included.** Robinhood Chain had 46 victims and 55 drains between 22:24 and 22:45.
- **Top heavy.** The top four wallets lost $347,730, which is 91%. The other 227 lost about $34K combined, mostly gas money and small balances.

### What was taken

| Asset | USD | Transfers |
|---|---:|---:|
| USDT | $259,914 | 21 |
| USDC | $51,401 | 77 |
| ETH (all chains) | $38,886 | 295 |
| pUSD (Polygon) | $23,569 | 9 |
| BNB | $2,520 | 37 |
| Everything else (USD₮ on Celo, WETH, WBTC, USDG, USDC.e, cbBTC and more) | about $5,200 | 93 |

By chain: Arbitrum $262,185, Ethereum $78,113, Polygon $24,594, Base $8,985, Robinhood Chain $3,464, BSC $2,588, Celo $999. The other ten chains were under $200 each.

### Where the money went

I followed each send from the attacker to a plain address. Two exchange deposit patterns show up:

- **Native deposit.** A fresh address gets ETH and forwards all of it within hours to a wallet with hundreds of thousands of transactions.
- **Token deposit.** An address gets USDT or USDC. A gas wallet sends it a little native coin. Then the tokens get swept to the same kind of huge wallet.

| Chain | Deposit address | From attacker | Pattern | Swept to | That wallet's tx count |
|---|---|---:|---|---|---:|
| Arbitrum | `0xf006355119fd57be5412369dfcd7e76d78936e8e` | 225,146 USDT | token deposit, gas from `0x0cd7ec8a…f481` | `0xcc8a55a8c5c00d1a79779928ab19adf6c19d4c2f` | 136,135 |
| Arbitrum | `0xffc890fe09053f1f04565c7a1f3161df885cf1cd` | 40,044 USDT | token deposit, same gas wallet | `0xcc8a55a8…4c2f` | same |
| Arbitrum | `0x07e2d8eb2d40eff119951998d94eb91107f776f5` | 0.71 ETH | native deposit | `0xcc8a55a8…4c2f` | same |
| Ethereum | `0xaaa939dacff5ce411995eaa5d16dc307ca29901c` | 55,047 USDC | token deposit, gas from `0xa953abe0…94dd` | `0x80787af194c33b74a811f5e5c549316269d7ee1a` | 749,436, about $4M balance |
| Ethereum | `0x78421155a6ff1adbb471672b501b715cf66ce065` | 14.34 ETH | native deposit | `0x80787af1…ee1a` | same |
| Ethereum | `0x676be7c17ac1d080d3274ab3f497620509293a44` | 9,372 USDC | token deposit, same gas wallet, address active since Aug 2020 | `0x80787af1…ee1a` | same |
| Ethereum | `0x1cadfb6fb68c555cc0657537022b178d65a007da` | 1,498 USDT | address active since Aug 2020 | `0x80787af1…ee1a` | same |
| Polygon | `0xa3cce5eb44ab3efd88a52cd43f95bc9495e2c0a3` | 15,187 USDC | token deposit, gas from `0x48bb0907…9a82` | `0x1240c57c23bc7deaf34fe51362f3dfe11ecc6702` | 282,142 |
| BSC | `0x1481e58411608b2d628ef305b92b01cf4f83db70` | 3.46 BNB (plus 9,578 POL on Polygon) | sent straight to a service wallet | itself | 1,487,839 |
| Celo | `0x11afddca3f85f50b30b9114891e7bc386faee434` | 999 USD₮ | **still sitting there** at 16:50 UTC Oct 22 | none | none |

What this tells responders:

1. **A few compliance requests cover almost everything.** On Arbitrum, three deposit addresses feed one hot wallet and two share a gas wallet. On Ethereum, four feed one hot wallet and two share a gas wallet. That is one service's deposit system on each chain, and together they hold about $360K of the flow.
2. **Two Ethereum deposit addresses go back to 2020.** Exchanges tie deposit addresses to customer accounts. Old addresses point to established accounts. The exchange can confirm.
3. **Tay named HitBTC.** The pattern fits a centralized exchange. I don't name the hot wallets here because I can't verify the label from on-chain data alone.
4. **There is still something to freeze.** 999 USD₮ is sitting on Celo, and Tether can freeze it.

### The poisoners went after the hacker

Minutes after each cash-out, address poisoning bots deployed fake tokens like `ꓴ឵ՏᎠ឵Ⲧ`, `UЅDC` (a hair space plus a Cyrillic Ѕ) and `USḌC`. Those tokens emitted fake transfer events saying the attacker had sent the same amount to a lookalike of the real deposit address. The bots were betting the attacker would copy the wrong address later. GoldRush shows 29 of these.

| Real deposit address | Lookalike planted in the attacker's history | Amount mirrored |
|---|---|---:|
| `0xf006355119…6e8e` | `0xf00601d42b…6e8e`, `0xf0061b38ae…6e8e` | 225,146.00 |
| `0xffc890fe09…f1cd` | `0xffc8614531…f1cd`, `0xffc8d02e4d…f1cd` | 40,043.78 |
| `0xaaa939dacf…901c` | `0xaaa2d423b0…901c` | 55,046.92 |
| `0xa3cce5eb44…c0a3` | `0xa3ccf822be…c0a3`, `0xa3cce18236…c0a3` | 15,186.71 |

Vanity twins of the attacker's own address (`0xd977b862…b2ee` and `0xd97995a8…b2ee`) also sent dust to one of its deposit addresses. They are not the attacker's wallets. If you cluster by "who sent to the same deposit address" you will get this wrong. The code flags these with a prefix and suffix match.

### What I left out and why

- 19 junk transfers into the attacker from 16 contracts: 13 lookalike tickers and 6 scam airdrops with URLs in the name.
- 117 transfers of tokens GoldRush had no price for, mostly memecoins.
- Big marks on thin tokens are capped at $250K per transfer. Native coins and the main USDC, USDT, WETH, WBTC and DAI contracts are trusted at any size. That is why the $256K USDT drain counts.

## Get a GoldRush API key

You need your own key. This repo does not ship one, and never commit yours.

- **Free trial:** [goldrush.dev/platform/auth/register](https://goldrush.dev/platform/auth/register/). 14 days, 25,000 credits, no credit card.
- **Buy a plan:** [goldrush.dev/platform/billing](https://goldrush.dev/platform/billing/). Plans are listed at [goldrush.dev/pricing](https://goldrush.dev/pricing/).
- **Talk to the team** about enterprise volume, custom limits or investigations work: [sales@goldrush.dev](mailto:sales@goldrush.dev), the [support page](https://goldrush.dev/support), or the [Discord](https://discord.gg/8ZWgu2pWY4).

Plans as listed on Oct 22, 2026:

| Plan | Price | Credits | Rate limit | Over the limit |
|---|---|---|---|---|
| Free Trial | $0 for 14 days | 25,000 | 4 req/s | none |
| Vibe Coding | $10/mo | 10,000 | 4 req/s | $0.001 per credit |
| Professional | $250/mo | 300,000 | 50 req/s | $0.00077 per credit |
| Inner Circle | custom | custom | custom | custom |

GoldRush is also sold through the Google Cloud and QuickNode marketplaces. Use the [pricing calculator](https://goldrush.dev/docs/pricing-calculator) to estimate a job before you run it.

## Run it

### Requirements

- Python 3.10 or newer, or Docker
- A GoldRush API key

### Setup

```bash
git clone <this repo>
cd covalent_railway_research
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # installs the railway-trace command
cp .env.example .env               # open .env and paste your key after GOLDRUSH_API_KEY=
make test                          # 39 offline tests, no key needed
make scan                          # confirms no key is sitting anywhere it shouldn't be
cp scripts/pre-commit .git/hooks/pre-commit   # blocks any commit that contains a key
```

You can also skip `.env` and export the key in your shell: `export GOLDRUSH_API_KEY=...`

### Trace

```bash
railway-trace all                                  # reproduces this report
railway-trace all --address 0xSUSPECT --since 2026-10-01T00:00:00Z --out out_suspect
```

Or one stage at a time. Each stage saves its work, so you can stop and start:

```bash
railway-trace fetch      # find the chains, pull every transaction
railway-trace price      # historical USD for every token touched
railway-trace hops       # follow cash-outs to deposit and hot wallets
railway-trace report     # write out/REPORT.md and the CSVs
```

With Docker:

```bash
make docker-build
make docker-trace ARGS="--address 0xSUSPECT --since 2026-10-01T00:00:00Z"
```

The key goes in at runtime through `--env-file .env`. It is never built into the image.

### Options

| Flag | Default | What it does |
|---|---|---|
| `--address` | the Railway attacker | address to trace |
| `--since` | `2026-10-21T00:00:00Z` | ignore activity before this time |
| `--out` | `out` | output folder |
| `--chains` | all active | comma list to limit `fetch`, e.g. `eth-mainnet,base-mainnet` |
| `--budget` | none | stop starting new work after N seconds; rerun to continue |
| `--refresh` | off | refetch chains already on disk |
| `--min-usd` | 500 | `hops` only follows cash-outs above this |
| `--max-pages` | 200 | page cap per chain (100 transactions per page) |
| `--log-level` | INFO | DEBUG, INFO, WARNING or ERROR |

Exit codes: `0` ok, `1` key found by `scan-secrets`, `2` time budget reached, `3` no API key, `4` API error.

### What you get in `out/`

| File | Contents |
|---|---|
| `REPORT.md` | The full report |
| `chains.csv` | Per chain: transactions, drains, victims, USD in and out, first and last drain |
| `victims.csv` | Every victim wallet with chains hit, USD lost and timing |
| `hourly.csv` | Drains and USD per hour |
| `venues.csv` | Every contract the attacker called, with decoded event counts |
| `cashout.csv` | Every attacker send, marked direct send or through a contract |
| `hops.csv` | Deposit address to hot wallet, with gas wallets |
| `poisoning_mirrors.csv` | Fake mirror events and the lookalike addresses |
| `movements.csv` | Every native and token movement with role, USD and flag |
| `transactions.csv` | Every transaction that touched the address |

### Troubleshooting

| Problem | Fix |
|---|---|
| `No API key` | Put `GOLDRUSH_API_KEY=...` in `.env` in the folder you run from, or export it. |
| `401` | The key is wrong or expired. Get a new one from the dashboard. |
| `429` or `504` | The client already retries with backoff. If it keeps failing, use `--budget` and rerun later. Cached pages are not fetched again. |
| `Chain ... not supported` | That chain isn't on your plan or isn't indexed. Use `--chains` to skip it. |
| Prices missing for today | Daily closes publish late. The code uses the latest close from the past 7 days and retries unpriced tokens on the next `price` run. |

## How it works: the GoldRush calls

**1. Which chains has this address touched?** One call checks 100+ chains.

```python
api.get(f"/v1/address/{addr}/activity/")
```

That is how all 22 chains turned up, including Robinhood Chain, MegaETH, Plasma and Arc.

**2. Full history per chain, with decoded logs.**

```python
# Page 0 is the OLDEST page. Keep going forward until links.next is empty.
for page in itertools.count():
    data = api.get(f"/v1/{chain}/address/{addr}/transactions_v3/page/{page}/", {"quote-currency": "USD"})
    yield from data["items"]
    if not data["links"]["next"]:
        break
```

Watch out: if you start at page 0 and follow `links.prev`, you stop at 100 transactions and get no error. My first run undercounted Ethereum and Base because of that.

**3. Sort by signer.** If the victim's key signed a transfer to the attacker, it's a drain. If the attacker's key signed it, it's routing. Decoded `Transfer` events give the token legs. Events on the attacker's own transactions (`Swap`, `Approval`, `MessageSent`, `RedemptionRequested`) show where it moved funds. See `railway_trace/classify.py`.

**4. Price it honestly.**

```python
api.get(f"/v1/pricing/historical_by_addresses_v2/{chain}/USD/{contracts}/",
        {"from": "2026-10-14", "to": "2026-10-21"})
```

Freshly deployed lookalike tokens never have a price. That, plus a check for homoglyphs in the ticker, removes every fake USDT and USDC.

**5. Follow the money.**

```python
api.get(f"/v1/{chain}/address/{a}/transactions_summary/")   # 4 txs or 749,436 txs tells you a lot
api.get(f"/v1/{chain}/transaction_v2/{tx_hash}/")            # decoded logs for token sweeps
```

## Code layout

```
railway_trace/
  config.py        key loading and the Secret type
  client.py        HTTP: auth, retries with backoff, error redaction, gzip cache
  goldrush.py      one function per endpoint
  classify.py      roles, movements, spoof detection, pricing rules (no I/O)
  forensics.py     victims, timeline, cadence, venues, cash-out, poisoning (no I/O)
  hops.py          deposit address and hot wallet following
  labels.py        a small address book, only entries backed by on-chain events
  report.py        Markdown and CSV output
  cli.py           the stages, resumable, with time budgets and exit codes
  secrets_scan.py  fails if anything key-shaped is outside .env
tests/             39 offline tests
.github/workflows/ci.yml   lint, tests and secret scan on Python 3.10 to 3.13
```

Each module does one job. Analysis code depends on a small `Getter` interface instead of `requests`, so tests pass in fakes and you could swap in another data source the same way.

### How your key is protected

- It lives in your environment or in `.env`. `.env` is git-ignored and Docker-ignored. `.env.example` is empty.
- In memory it's a `Secret` that can't be printed, formatted, pickled or changed. Printing it shows `Secret(****)`.
- It only goes out in the `Authorization: Bearer` header. Never in a URL, never in a query string.
- Every error message, from HTTP bodies to network exceptions, is scrubbed before it's raised.
- Cached responses are keyed on the request path and parameters only. The key is never stored.
- `make scan` checks the repo, `out/` and the gzip cache for anything key-shaped. CI runs it on every push and the pre-commit hook runs it on every commit.
- If a key leaks anyway, rotate it in the GoldRush dashboard. Deleting it from git history is not enough.

## Limits

- USD uses GoldRush daily prices and the transactions' own quotes. Unpriced tokens are left out, so the totals are a floor.
- A "victim" is any wallet whose key signed a transfer to the attacker in the window. A few could be the attacker's own funding wallets. Check before contacting anyone.
- The exchange calls are based on behavior (deposit patterns and transaction counts), not verified labels.
- Oct 21 prices weren't published yet when this ran, so the code used the Oct 20 close.

## License

MIT. See `LICENSE`. Data from [Covalent GoldRush](https://goldrush.dev) ([@goldrushdev](https://x.com/goldrushdev), [@Covalent_HQ](https://x.com/Covalent_HQ)).
