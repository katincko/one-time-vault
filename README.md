# one-time-vault

One-time secret vault. The browser encrypts, the server stores ciphertext it cannot read, and a
link opens once. Done so far: lot 1 (storage), lot 2 (API and browser pages). The access password
is lot 3.

## What exists

- `create`: server-made 128-bit id (base64url), ciphertext with a lifetime of 1 hour, 1 day or 7 days.
- `GET /s/<id>` (and `HEAD`): the open page. It never touches storage, so link previews and
  crawlers consume nothing. The page asks for a click on "Reveal".
- `POST /api/secrets/<id>/reveal`: delivers and deletes in one atomic Lua step. Missing, already
  read, expired and malformed ids all get the same 404, byte for byte.
- Browser JS (plain ES modules, no build, typed with JSDoc and `tsc --noEmit`): a 256-bit key per
  secret, HKDF-SHA256 with the labels `encryption` and `password`, AES-256-GCM. The plaintext is
  padded to blocks of 256 bytes before encryption (ISO/IEC 7816-4), so the ciphertext only shows
  the block count. The link is `/s/<id>#<key>`; the key never goes to the server.
- A link without a whole key (no `#`, cut, padded, wrong characters) shows "Incomplete link" and
  does not call the server. After a reveal the `#` is removed from the address bar.
- Storage: Redis or Valkey, one hash per secret, key TTL is the expiry. The verifier comparison for
  the future password uses `hmac.compare_digest` in Python, never in Lua.

Not in this lot: the access password, per-IP creation limit, security headers and CSP, Docker
Compose, CI. Spec tests 3 (storage level), 7, 10 and 11 are covered by the storage suite or by
later lots; see `docs/negative-proofs.md` for what is proven.

## Develop

```
uv sync --locked
npm install                       # only TypeScript, for the type check
uv run ruff check . && uv run mypy && npm run typecheck
# pytest wants the test files named one by one, and Docker running:
uv run pytest tests/test_storage.py tests/test_storage_hardening.py tests/test_race.py \
  tests/test_race_processes.py tests/test_api.py tests/test_browser.py tests/test_canary_finder.py -q
```

Tests run against real `redis:7.4` and `valkey/valkey:8.0` containers (testcontainers), and the
browser tests use Playwright with Chromium against the real server in its own process.
Run the app: `OTV_REDIS_URL=redis://localhost:6379 uv run uvicorn --factory one_time_vault.app:app_from_env`.

Negative proofs (bug planted, red output, restored, green): [docs/negative-proofs.md](docs/negative-proofs.md).
