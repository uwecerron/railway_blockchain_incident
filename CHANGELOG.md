# Changelog

## 1.1.0 (2026-10-22): post-audit
- Per-chain "USD in" now counts only victim-signed value (it previously included bridge fills and swap proceeds).
- Native coins that also emit an ERC-20 Transfer (Celo, zkSync, Metis) are no longer counted twice.
- NFT (ERC-721) transfers are skipped instead of showing up as zero-value junk.
- Tokens with unknown decimals are marked unpriced, not assumed to have 18.
- A zero native quote now falls back to the native rate.
- Dust from vanity twins of the attacker is no longer counted as a victim.
- "USD out" now means direct sends only, so swap legs aren't counted twice.
- Pricing resumes per contract, and empty price answers are never cached.
- Complete transaction pages are cached so an interrupted fetch resumes cheaply. The newest page is always refetched.
- The pagination cap raises a handled error instead of crashing.
- Hop following walks back from the newest page and no longer mistakes the previous hop for a gas funder.
- Secret scan streams files with overlapping chunks, reads gzip by magic bytes, and skips symlinks and special files. Corrupt files no longer crash it. Also catches `ckey_` keys and UTF-16 copies.
- Logging uses levels (`--log-level`), and exit codes are documented.
- Packaging: `pyproject.toml` (`railway-trace` CLI), Dockerfile, Makefile, CI on Python 3.10 to 3.13, pre-commit hook.

## 1.0.0 (2026-10-22)
- First release: fetch, price, hops and report stages; forensic report; 30 tests.
