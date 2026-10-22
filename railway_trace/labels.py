"""A deliberately small address book. Only entries whose identity is public and
that the trace also corroborates by on-chain events (e.g. Burn+MessageSent for
CCTP). Everything else is reported as unlabeled rather than guessed."""

KNOWN = {
    "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae": "LI.FI Diamond (bridge/swap aggregator)",
    "0x0000000000001ff3684f28c67538d4d072c22734": "0x AllowanceHolder (0x swap settler)",
    "0x28b5a0e9c621a5badaa536219b3a228c8168cf5d": "Circle CCTP v2 TokenMessenger (USDC burn-and-mint bridge)",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC (Ethereum)",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT (Ethereum)",
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": "USDC (Base)",
    "0xaf88d065e77c8cc2239327c5edb3a432268e5831": "USDC (Arbitrum)",
    "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": "USDT (Arbitrum)",
    "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": "USDC (Polygon)",
}


# Canonical high-liquidity contracts: their GoldRush price is trustworthy at any size,
# so they are exempt from the per-transfer outlier cap. Keyed by (chain, contract).
CANONICAL = {
    ("eth-mainnet", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),  # USDC
    ("eth-mainnet", "0xdac17f958d2ee523a2206206994597c13d831ec7"),  # USDT
    ("eth-mainnet", "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),  # WETH
    ("eth-mainnet", "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"),  # WBTC
    ("eth-mainnet", "0x6b175474e89094c44da98b954eedeac495271d0f"),  # DAI
    ("arbitrum-mainnet", "0xaf88d065e77c8cc2239327c5edb3a432268e5831"),  # USDC
    ("arbitrum-mainnet", "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"),  # USDT
    ("arbitrum-mainnet", "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8"),  # USDC.e
    ("arbitrum-mainnet", "0x82af49447d8a07e3bd95bd0d56f35241523fbab1"),  # WETH
    ("base-mainnet", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),  # USDC
    ("base-mainnet", "0x4200000000000000000000000000000000000006"),  # WETH
    ("optimism-mainnet", "0x0b2c639c533813f4aa9d7837caf62653d097ff85"),  # USDC
    ("optimism-mainnet", "0x4200000000000000000000000000000000000006"),  # WETH
    ("matic-mainnet", "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"),  # USDC
    ("matic-mainnet", "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"),  # USDC.e
    ("matic-mainnet", "0xc2132d05d31c914a87c6611c10748aeb04b58e8f"),  # USDT
    ("bsc-mainnet", "0x55d398326f99059ff775485246999027b3197955"),  # USDT
    ("bsc-mainnet", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"),  # USDC
}


def label(address: str, names_seen: set[str] | None = None) -> str:
    a = (address or "").lower()
    if a in KNOWN:
        return KNOWN[a]
    if names_seen:
        return " / ".join(sorted(n for n in names_seen if n))[:80] + " (name from GoldRush token metadata)"
    return "unlabeled"
