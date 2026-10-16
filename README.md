# one-time-vault

One-time secret vault. This is lot 1: the storage layer (Redis or Valkey, atomic Lua scripts).

- `create`: store a secret with a TTL and an attempts counter.
- `open`: deliver and delete in one atomic step (at most one delivery).
- Wrong password: counted atomically, the secret is destroyed on the 5th.
- The verifier comparison (`hmac.compare_digest`) is in Python, never in Lua.
- Missing, already read and expired all return `NotFound`.

## Develop

```
uv sync --locked
uv run ruff check . && uv run mypy
uv run pytest tests/test_storage.py tests/test_race.py   # needs Docker
```

Tests run against real `redis:7.4` and `valkey/valkey:8.0` containers (testcontainers).
Negative proofs: [docs/negative-proofs.md](docs/negative-proofs.md).
