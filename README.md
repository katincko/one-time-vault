# one-time-vault

One-time secret vault. The browser encrypts, the server stores ciphertext it cannot read, and a
link opens once. Done so far: lots 1 to 3 (storage, API and browser pages, access password,
creation limit, security headers). Docker Compose, CI and the demo are still to do.

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

- Access password (optional, like Bitwarden Send): it is access control, not encryption. The
  browser sends `PBKDF2-SHA256(password, salt = "password" subkey)` with 600,000 iterations
  (the server refuses 600,000 to 1,000,000 outside the interval, and a verifier without iterations).
  The server stores `HMAC-SHA256(server key, verifier)` with the key version and the iteration
  count in front, and compares in Python with `hmac.compare_digest`. A wrong verifier counts an
  attempt in Lua; the fifth deletes the secret. Answers: 403 `password_required` (not counted),
  403 `wrong_password` with `attempts_left`, else the same 404 as always.
  Who can decrypt without the password: anyone with the link and read access to the database.
  Anyone who only knows the id can learn that the secret exists and is protected, and can spend
  its five attempts.
- Server keys: `OTV_SERVER_KEYS="2:<base64url>,1:<base64url>"`, 32 bytes or more each, the first
  one signs new secrets. Required at boot; old versions stay in the list until their secrets are
  gone (a missing version is a 500, never a wrong password).
- Creation limit per client IP (`OTV_CREATE_LIMIT`, `OTV_CREATE_WINDOW_SECONDS`, default 20 per
  hour), counted in one Lua step. `OTV_TRUSTED_HOPS=N` is the number of proxies in front; the
  client is the Nth `X-Forwarded-For` entry from the right, so a forged header cannot pick the
  bucket. With 0 (default) the header is ignored. The app must only be reachable through those
  proxies. IPv6 is counted per /64. Over the limit: 429 with `Retry-After`; a body over 16 KB: 413.
- Headers on every response, pages and API: the spec CSP with a new nonce per response,
  `nosniff`, HSTS, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.

Not yet: Docker Compose, CI and the demo. The server checks the ciphertext by padded blocks, so it
accepts texts up to 10495 bytes; the 10 KB limit is enforced in the browser.
`docs/negative-proofs.md` lists what is proven and how.

## Develop

```
uv sync --locked
npm install                       # only TypeScript, for the type check
uv run ruff check . && uv run mypy && npm run typecheck
# pytest wants the test files named one by one, and Docker running:
uv run pytest tests/test_storage.py tests/test_storage_hardening.py tests/test_race.py \
  tests/test_race_processes.py tests/test_api.py tests/test_browser.py tests/test_canary_finder.py \n  tests/test_browser_crypto.py tests/test_browser_password.py tests/test_headers.py \n  tests/test_limits.py tests/test_password.py tests/test_keyring.py -q
```

Tests run against real `redis:7.4` and `valkey/valkey:8.0` containers (testcontainers), and the
browser tests use Playwright with Chromium against the real server in its own process.
Run the app (`--no-proxy-headers`: the app does its own client IP logic):
`OTV_REDIS_URL=redis://localhost:6379 OTV_SERVER_KEYS=1:<32+ random bytes, base64url> uv run uvicorn --factory --no-proxy-headers one_time_vault.app:app_from_env`.

Negative proofs (bug planted, red output, restored, green): [docs/negative-proofs.md](docs/negative-proofs.md).
