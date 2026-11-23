# Security and guarantees

Each guarantee names the test that checks it (`file::test`). A statement with no test says so.
The tests for the guarantees come with a planted bug shown red for the right reason (see
[negative-proofs.md](negative-proofs.md)). The short version is in the
[README](../README.md#security-at-a-glance).

## What "the server cannot read it" means here

A password sent by chat or e-mail stays in that chat or mailbox for good. One-time vaults fix
that, but most only claim that the server cannot read what you store. Here the claim is tested:
two canaries (the text and the generated key) are searched, in several encodings, in every
request the browser makes, in the server log and in every Redis key
(`tests/test_browser.py::test_neither_the_text_nor_the_key_leaves_the_browser`), and every request
the page sends is checked as a structure, whatever the encoding: header names from an allowed
list, each header value against the pattern Chromium sends, exactly the expected keys in each API
body, and every body value against the server's own request model, so lengths and padding are
exact (`tests/request_shape.py`). The claim
depends on the browser receiving the JavaScript in this repository (see the threat model).

## Guarantees and the tests behind them

- The text is at most 10 KB and is padded to 256-byte blocks before encryption (ISO/IEC 7816-4),
  so the stored size only shows the block count
  (`test_browser.py::test_ciphertext_size_shows_only_the_block_count`,
  `test_api.py::test_valid_sizes_up_to_the_limit_are_accepted`, and one block over the limit is
  refused in `test_api.py::test_every_refusal_is_an_error_and_stores_nothing`). The lifetimes
  become 3600, 86400 and 604800 seconds (`test_api.py::test_expiry_names_become_seconds`).
- A link without a whole key (no `#`, cut, padded, wrong characters) shows "Incomplete link" and
  never calls the server
  (`test_browser.py::test_a_link_without_the_whole_key_says_so_and_never_calls_the_server`).
- Missing, already read, expired and malformed ids all get the same 404, byte for byte
  (`test_api.py::test_404_is_byte_identical_for_missing_read_expired_and_malformed`).
- The page opened by `GET /s/<id>` is the same for every id
  (`test_api.py::test_the_open_page_is_the_same_for_every_id`).
- Optional access password, in the style of Bitwarden Send: it is access control, not
  encryption. The browser sends `PBKDF2-SHA256(password, salt = "password" subkey)` with 600,000
  iterations; the server stores `HMAC-SHA256(server key, verifier)` and compares it in Python
  with `hmac.compare_digest`. A wrong verifier counts an attempt in Lua; the fifth one deletes the
  secret. Tests: the verifier is PBKDF2 with the `password` subkey as salt
  (`test_browser_password.py::test_the_verifier_is_pbkdf2_of_the_password_salted_with_the_password_subkey`),
  the stored value is a keyed hash
  (`test_password.py::test_the_server_stores_a_keyed_hash_never_the_verifier`), the compare uses
  `hmac.compare_digest`
  (`test_storage_hardening.py::test_verifier_is_compared_with_hmac_compare_digest`), five wrong
  passwords delete the secret (`test_password.py::test_five_wrong_passwords_destroy_the_secret`).
- Creation is limited per client IP (default 20 per hour, not tested; the tests set their own
  limit), counted in Lua
  (`test_limits.py::test_the_count_is_one_atomic_step_under_concurrency`). Over the limit: 429 with
  `Retry-After` (`test_limits.py::test_the_creation_after_the_limit_is_429_with_retry_after`). A
  body over the limit: 413, by `Content-Length` or streamed
  (`test_api.py::test_a_body_over_the_limit_is_413_by_content_length`,
  `test_api.py::test_a_streamed_body_over_the_limit_is_413_without_content_length`). The 16 KB
  figure itself is not asserted: the tests use 200,000 bytes and 500,000 streamed bytes, and
  `test_api.py::test_valid_sizes_up_to_the_limit_are_accepted` checks that the largest valid
  request fits.
- Every response the app produces, pages, API and 500s, carries the security headers: a CSP with
  a new nonce per response (`default-src 'none'; script-src 'nonce-N' 'strict-dynamic'; connect-src 'self'; ...`),
  `nosniff`, HSTS, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`. One test checks
  all of them on 200, 201, 404, 413, 422 and 429 responses, with HSTS `max-age` of at least 8
  digits (`test_headers.py::test_every_response_has_the_security_headers`); another checks the
  500s (`test_headers.py::test_a_500_from_a_route_has_the_headers_a_generic_body_and_a_log_line`,
  `test_headers.py::test_a_500_from_an_inner_middleware_has_the_headers_a_generic_body_and_a_log_line`).
  The nonce is new per response
  (`test_headers.py::test_the_nonce_is_new_on_every_response_and_matches_the_script_tag`).
  A protocol error (a malformed request line, for example) is answered by uvicorn before the app
  runs, so that 400 carries none of these headers (seen by hand on the real server; no test). The
  proxy in front, which the app needs for TLS anyway, must add them to those answers.

## Configuration

The default values are not tested.

| Variable | Meaning |
|---|---|
| `OTV_REDIS_URL` | Redis or Valkey URL, default `redis://localhost:6379` |
| `OTV_SERVER_KEYS` | Required. `2:<base64url>,1:<base64url>`, 32 bytes or more each. The first one seals new secrets; older versions stay listed until their secrets are gone. The app does not boot without it (`test_keyring.py::test_bad_server_keys_refuse_to_boot`, `test_keyring.py::test_the_real_server_process_does_not_start_without_the_keys`). |
| `OTV_CREATE_LIMIT`, `OTV_CREATE_WINDOW_SECONDS` | Creations per client IP per window, default 20 per 3600 s |
| `OTV_TRUSTED_HOPS` | Number of proxies in front. The client is the Nth `X-Forwarded-For` entry from the right, so a forged header cannot pick the bucket. With 0 (default) the header is ignored. |
| `OTV_CLIENT_IP_HEADER` | A header that the edge always overwrites with the visitor's address, such as `CF-Connecting-IP` behind Cloudflare. When set, the client is that header's single value and neither the socket peer nor `X-Forwarded-For` is read. A request without one valid address in it is counted in a bucket of its own (`no-client-ip`), never in the proxy's. It cannot be set together with `OTV_TRUSTED_HOPS`: the app refuses to boot. Empty means unset. |

## Threat model

What it protects against:

| Threat | Why it holds | Test |
|---|---|---|
| A server or database reader learns the text | The server never receives the text or the key | `test_browser.py::test_neither_the_text_nor_the_key_leaves_the_browser` |
| A second reader | One atomic Lua step delivers and deletes; 50 simultaneous readers get at most one delivery, in one process and across processes, on Redis and Valkey | `test_race.py::test_at_most_one_delivery_and_counter_capped`, `test_race_processes.py::test_one_delivery_across_processes` |
| Link previews and crawlers burning the link | `GET` and `HEAD` of the open page never touch storage; the click on "Reveal" is the read | `test_api.py::test_get_and_head_with_preview_agents_consume_nothing`, `test_browser.py::test_opening_the_link_in_a_browser_consumes_nothing` |
| Telling dead ids from live ones | One 404 for missing, read, expired and malformed ids | `test_api.py::test_404_is_byte_identical_for_missing_read_expired_and_malformed` |
| An altered ciphertext | The browser refuses it (AES-GCM) and says so | `test_browser.py::test_an_altered_secret_is_refused` |
| Learning the text length | The ciphertext size shows only the block count | `test_browser.py::test_ciphertext_size_shows_only_the_block_count` |
| The server learning the password | Only the PBKDF2 verifier is sent; the server stores a keyed hash of it | `test_browser_password.py::test_the_password_never_reaches_the_server`, `test_password.py::test_the_server_stores_a_keyed_hash_never_the_verifier` |
| Password guessing | The fifth wrong attempt deletes the secret, also under simultaneous tries | `test_password.py::test_simultaneous_wrong_passwords_are_counted_exactly_to_the_limit` |
| A forged `X-Forwarded-For` dodging the creation limit | The client is taken from the trusted end of the header | `test_limits.py::test_a_forged_forwarded_header_does_not_pick_the_bucket`, `test_limits.py::test_the_real_server_ignores_a_forged_header_and_answers_429_and_413` |
| A forged `CF-Connecting-IP` (or a missing one) dodging the creation limit | With `OTV_CLIENT_IP_HEADER`, only the edge writes the header; a missing or invalid value shares one bucket, never the proxy's | `test_limits.py::test_the_client_ip_header_picks_the_bucket_not_the_peer_or_forwarded_for`, `test_limits.py::test_a_missing_client_ip_header_fails_closed_in_its_own_bucket`, `test_limits.py::test_the_real_server_counts_by_the_client_ip_header` |
| Injected inline script | Every response, 500s included, carries a CSP with a fresh nonce | `test_headers.py::test_the_nonce_is_new_on_every_response_and_matches_the_script_tag`, `test_browser_password.py::test_the_pages_run_under_the_csp_without_a_violation` |

What it does not protect against:

- **A server that serves altered JavaScript.** The browser does the encryption with the code the
  server sends. Whoever controls the server, or the connection when TLS is missing, can send code
  that leaks the text or the key. The app does not terminate TLS: put it behind a proxy that does.
- **Where you paste the link.** The key is in the link. Whoever can read the chat, the e-mail or a
  synced browser history that holds the link has the key. The `#` is removed from the address bar
  after opening, which does not help the creator's side.
- **A malicious browser extension** on either side.
- **A bot or a person that clicks "Reveal"** before the intended reader. The click consumes the
  secret.
- **Anyone who has the link can spend the password attempts.** Anyone who only knows the id can
  learn that the secret exists and is protected (the 403 answers), and can use up its five
  attempts, which deletes the secret.
- **Link plus database access.** The password is access control, not encryption: whoever has the
  link and read access to the database decrypts without the password.
- **The exact 10 KB text limit on the server.** The server checks padded blocks, so it accepts
  texts up to 10495 bytes; the 10 KB limit is enforced in the browser.

## Stack in detail

| Part | Choice | Why |
|---|---|---|
| Server | Python 3.12, FastAPI, pydantic in strict mode | Request bodies are validated with extra fields forbidden, so a caller cannot choose an id or add a field |
| Storage | Redis or Valkey, one hash per secret, the key TTL is the expiry | Lua scripts make deliver-and-delete and the attempt counter atomic; the suite runs on `redis:7.4` and `valkey/valkey:8.0` |
| Browser code | Plain ES modules, JSDoc types checked by `tsc --noEmit`, no build step | The JavaScript a browser gets is the file in the repository |
| Cryptography | WebCrypto: HKDF-SHA256, AES-256-GCM, PBKDF2-SHA256 | Built into the browser; no crypto library is shipped. An independent Python decryptor checks the HKDF labels and the cipher (`test_browser.py::test_the_browser_uses_hkdf_labels_and_aes_gcm_like_an_independent_implementation`) |
| Tests | pytest, testcontainers (real Redis and Valkey), Playwright with Chromium against the real server process | The guarantees are about a browser talking to a server and a database, so the tests use all three |
| Tooling | uv, ruff, mypy (strict), Docker Compose, GitHub Actions, gitleaks | One lock file, the same commands locally and in CI |

## Engineering practices in detail

- **Negative proofs.** Each test that guards a guarantee was run with the bug planted, shown red
  for the right reason, and restored. The rows are in
  [negative-proofs.md](negative-proofs.md), lot by lot.
- **Harnesses that check themselves.** The race harness is run against a deliberately naive
  storage and must report violations (`test_race.py::test_race_harness_catches_a_non_atomic_storage`,
  `test_race_processes.py::test_process_harness_catches_a_non_atomic_storage`). The leak finder is
  tested against every encoding it claims to find (`test_canary_finder.py`).
- **Real services.** No fake Redis: containers for Redis and Valkey, and a real uvicorn process for
  the tests that need one.
- **One gate.** `make verify` runs ruff, ruff format, mypy, `tsc`, the whole suite, a
  dependency audit (`pip-audit` over the locked set, which needs the network), gitleaks over the
  whole history and the working tree, and a dash check. CI runs the same target, and the audit
  also as a step of its own.
- **CI hygiene.** Actions are pinned by commit SHA, the workflow has `contents: read` only,
  `setup-uv` caches, `uv sync --locked`, and Dependabot watches `github-actions`, `uv` and `npm`
  (the TypeScript dev dependency in `package.json`). The Docker base images, the gitleaks image
  and the Redis and Valkey test images are pinned by digest, and Dependabot does not watch them.
  The test images are pinned by digest too: the Redis one is read from `compose.yaml`, so the
  tests and the app run the same image (`test_gates.py::test_the_test_images_are_pinned_by_digest_and_redis_is_the_one_of_the_compose_file`).
- **The README is tested.** The test command in the README is run by `tests/test_readme.py`, which also
  checks that it names every test file once.

## Decisions and trade-offs

- **Reveal needs a click.** A `GET` cannot be the read, or any preview would spend the link. The
  cost: a bot that clicks spends it too.
- **The password is access control.** It does not feed the encryption key: the `password` HKDF
  subkey only salts the verifier. The cost: link plus database decrypts without it.
- **The server checks blocks, the browser checks the 10 KB.** The padded size is what the server
  can see, so that is what it enforces.
- **Server keys have versions.** Rotating adds a new first key and keeps the old ones until their
  secrets are gone. A missing version is a 500, never a wrong password, so it does not burn
  attempts (`test_password.py::test_a_dropped_key_is_a_server_error_that_does_not_burn_attempts`).
- **Counting at the proxy edge.** IPv6 is counted per /64; an IPv4 mapped into IPv6 counts as that
  IPv4 address. The app must only be reachable through the proxies counted in `OTV_TRUSTED_HOPS`. With `OTV_CLIENT_IP_HEADER` the header is only as trustworthy as that rule: the app must be reachable through the edge that overwrites it and nothing else, or a caller can write the header and pick its bucket.
- **Compose publishes only the app, on 127.0.0.1.** Redis has no published port.
  It runs with `--maxmemory 64mb --maxmemory-policy noeviction`, so when memory is full, creating
  fails instead of a secret being dropped early. No test fills the memory.
- **The password hash is compared in Python.** The Lua scripts never see the candidate verifier
  (`test_storage_hardening.py::test_no_script_argument_contains_the_candidate_verifier`).

## Security findings fixed

Found in the reviews of lots 1 to 4, fixed, and covered by the tests named. The commit is the
fix.

| Finding | Fix | Commit | Test |
|---|---|---|---|
| The caller chose the secret id | Ids are made by the server from 128 random bits | `305731e` | `test_storage_hardening.py::test_secret_ids_are_made_by_the_server_from_128_random_bits`, `test_api.py::test_the_server_picks_the_id` |
| An id collision could overwrite a stored secret | The create script refuses an existing key and the server retries with a new id, then gives up | `305731e` | `test_storage_hardening.py::test_create_retries_on_an_id_collision_and_never_overwrites` |
| Nothing stopped the verifier compare from becoming a plain `==`, or the candidate verifier from reaching a Lua script | Guards: `hmac.compare_digest` in Python, and no script argument may hold the candidate verifier | `305731e` | `test_storage_hardening.py::test_verifier_is_compared_with_hmac_compare_digest` |
| Id and base64url checks used `^...$`, which in Python also matches before a trailing newline | `fullmatch`. Defense in depth: the round-trip check already refused such input, so no status code changed and there is no dedicated test | `b188193` | none |
| Unknown paths under `/api/secrets/` answered the framework's own 404, different from the uniform one | One catch-all route returns the uniform 404 | `a361796` | `test_api.py::test_malformed_routes_under_api_secrets_get_the_same_404` |
| A fixed IV and a fixed key left all 138 tests of that lot green (the count of that old lot; today's is in the README), because they still round-trip | Tests look at what was made: fresh IV and key per secret, AES key not extractable | `425a7b5` | `test_browser_crypto.py::test_every_secret_gets_a_fresh_iv_and_key_of_the_right_size` |
| No test covered an IV or a key reused inside one page load | Tests cover the form and `encrypt` | `fe761de` | `test_browser_crypto.py::test_one_page_load_never_reuses_an_iv_or_a_key_through_the_form` |
| A 500 was answered by Starlette's own handler, outside the middleware, so it had no security headers | A middleware catch gives the headers, a generic body and a log line | `99dbd27` | `test_headers.py::test_a_500_from_a_route_has_the_headers_a_generic_body_and_a_log_line` |
| The 500 log line could carry control characters and the secret id from the path | Control characters are escaped and secret ids are masked | `307358f` | `test_headers.py::test_a_500_log_line_carries_no_control_character_and_no_secret_id` |
| An error after the response had started was answered a second time | It is raised instead | `b6b6cb2` | `test_headers.py::test_an_error_after_the_response_started_is_raised_not_answered_twice` |
| An IPv4 mapped into IPv6 was cut to a /64, so all of them shared one bucket | It counts as the plain IPv4 address | `b4aeffd` | `test_limits.py::test_two_mapped_ipv4_addresses_have_their_own_buckets` |
| The socket peer fallback skipped that rule, and a peer that was free text became a bucket key | The peer gets the same normalization as the header address | `a919b75` | `test_limits.py::test_an_ipv4_mapped_in_ipv6_is_the_plain_ipv4` |
| The README test command had a literal backslash and `n`, and missed a test file | The command is tested as pasted | `df822f5` | `test_readme.py::test_the_pasted_command_collects_every_test_without_error` |

Found in the audit before going public (see "Before going public" in
[negative-proofs.md](negative-proofs.md)):

| Finding | Fix | Commit | Test |
|---|---|---|---|
| uvicorn's access log wrote `GET /s/<id>` and `POST /api/secrets/<id>/...` with the client IP | The access log is masked by the same function as the 500 log, whatever flags the server runs with | `d3bbe65` | `test_access_log.py::test_the_server_log_never_holds_the_id_of_a_secret` |
| The mask only matched paths starting exactly with `/s/` or `/api/secrets/`: `//s/<id>`, `/x/../s/<id>`, `/s/%2F<id>` wrote the whole id | Any run of 22 or more id characters is masked anywhere in the path or query, besides the prefix rule | this commit | `test_access_log.py::test_the_server_log_never_holds_the_id_in_any_form_of_path` |
| The leak canary only knew some encodings of the key (a hex header with colons or a JSON array of decimals passed) | Structural check of every request: allowed header names, exact body keys | `1481082` | `test_request_shape.py`, `test_browser.py::test_neither_the_text_nor_the_key_leaves_the_browser` |
| The README said every response has the security headers, but uvicorn answers protocol errors alone | The claim is for what the app produces; `--no-server-header` | `ad076e1` | `test_gates.py::test_the_readme_claims_the_headers_only_for_what_the_app_produces` |
| Two locked dependencies with known vulnerabilities, and no scan | Both updated; `pip-audit` in `make verify` and in the CI | `ae5e00b` | `test_gates.py::test_the_dependency_audit_is_a_step_of_make_verify_and_of_the_ci` |
| The test images were tags, not digests | Pinned by digest, Redis read from `compose.yaml` | `b375374` | `test_gates.py::test_the_test_images_are_pinned_by_digest_and_redis_is_the_one_of_the_compose_file` |
| The open page accepted any PBKDF2 iteration count from the server and ignored a failed derivation | The count must be inside the server limits; a failure shows an error | `2cdafa1` | `test_browser_iterations.py` |
