# Security

- Your GoldRush API key belongs in `.env` (git-ignored) or the `GOLDRUSH_API_KEY` environment variable. Never commit it.
- The key is held in a `Secret` type that cannot be printed, formatted, pickled or modified. It is sent only in the `Authorization: Bearer` header and is redacted from every error message.
- Cached API responses (`out/cache/`) are keyed by request path and parameters only; they never contain the key.
- `python3 -m railway_trace scan-secrets` (also run in CI and by `scripts/pre-commit`) fails if anything key-shaped appears outside `.env`.
- If a key leaks, rotate it in the GoldRush dashboard immediately; scrubbing git history is not enough.
- Report a vulnerability privately to the repository owner rather than in a public issue.
