# Negative proofs

Each row: a bug planted in `src/` (or in the page JS), the named test run against real Redis 7.4
(first red lines shown), bug removed with `git checkout`, suite green again.

## Lot 1 (storage layer)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| Lua reveal replaced by `HGET` then `DEL` as separate commands | `Stats(delivered=50, ...)`, `assert not ['50 deliveries']` (Valkey 8.0 too) | `test_race.py::test_at_most_one_delivery_and_counter_capped` |
| Wrong-attempt counter as read then write instead of Lua | `Stats(delivered=1, wrong_replies=1, key_left=True, ...)`, `['delivered but still stored']` | `test_race.py::test_at_most_one_delivery_and_counter_capped` |
| `EXPIRE` removed from create | `assert 0 < -1` on `PTTL` | `test_storage.py::test_ttl_is_set_and_secret_vanishes_in_real_redis` |
| `DEL` removed from reveal | `Revealed(payload=b'cipher') == NotFound()` | `test_storage.py::test_second_read_fails` |
| Last wrong attempt no longer destroys (`>=` to `>`) | `assert 1 == 0` on `EXISTS` | `test_storage.py::test_five_wrong_passwords_destroy_the_secret` |

The race harness is also kept alive in the suite: `test_race_harness_catches_a_non_atomic_storage`
runs it against a deliberately naive storage and requires it to report the violations.

## Lot 1, review fixes (storage hardening and multi-process race)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| `bytes(stored) == verifier` instead of `hmac.compare_digest` | `assert [] == [(b'CANDIDATE...', b'wrong'), ...]` (the spy was never called) | `test_storage_hardening.py::test_verifier_is_compared_with_hmac_compare_digest` |
| Candidate verifier added to the `FAIL` script arguments | `candidate verifier reached the server` | `test_storage_hardening.py::test_no_script_argument_contains_the_candidate_verifier` |
| Candidate verifier added to the `REVEAL` script arguments | `candidate verifier reached the server` | same |
| `secrets.token_bytes(16)` replaced by `random.randbytes(16)` | `assert [] == [16]` | `test_secret_ids_are_made_by_the_server_from_128_random_bits` |
| `ID_BYTES = 8` | `assert [8] == [16]` | same |
| `create` gets a `secret_id` parameter | `assert 'secret_id' not in mappingproxy(...)` | same |
| `ID_BYTES = 1` | `assert 256 == 5000` distinct ids | `test_ids_do_not_repeat` |
| Retries cut to 1 | `RuntimeError: could not allocate a free secret id` on a collision | `test_create_retries_on_an_id_collision_and_never_overwrites` |
| `EXISTS` guard removed from the create script | `assert '7bBJ...' == 'BBBB...'` (an existing secret was overwritten, so no retry) | same |
| Retry exhausted returns the taken id instead of raising | `Failed: DID NOT RAISE RuntimeError` | `test_create_gives_up_when_every_id_is_taken` |
| Reveal as `HGET` then `DEL` from Python, readers in 6 processes with their own connections | `Stats(delivered=35, wrong_replies=0, key_left=False, attempts_in_key=0)` | `test_race_processes.py::test_one_delivery_across_processes` |
| Wrong-attempt counter as read then write from Python, 6 processes | `Stats(delivered=1, wrong_replies=17, key_left=True, attempts_in_key=3)` | same |

`test_process_harness_catches_a_non_atomic_storage` keeps the multi-process harness honest the
same way the asyncio one is: it runs `NaiveStorage` in the worker processes and requires the
violations to show up.

### Race suite repeated

`tests/test_race.py` and `tests/test_race_processes.py` (8 tests: asyncio and processes, on Redis
7.4 and Valkey 8.0) were run 10 times in a row with `uv run pytest ... -q`:

| Runs | Passed | Failed | Failed by timeout |
|---|---|---|---|
| 10 | 10 (8 tests each) | 0 | 0 |

The runs took 96 s to 138 s each. Nothing was changed to get this result: the pool is warmed
before the 50 simultaneous readers (lot 1), and every process warms its own 20 connections before
the start signal. Most runs shared the machine with other work of mine (npm install, editing,
a few quick test files), which slowed them down without causing a timeout.

## Lot 2 (API and pages)

### Leak finder (`tests/canary.py`)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| Base64 forms only at offset 0 | the set of encodings differs from the expected one | `test_canary_finder.py` |
| Wrong skip count for base64 at offset 1 | `assert False` on `any(n.startswith("base64") ...)` | `test_base64_is_found_at_any_alignment` |
| `hex-upper` removed | the set of encodings differs from the expected one | `test_the_finder_looks_for_every_expected_encoding` |

### API (`tests/test_api.py`, spec tests 2, 4, 8, 9, 12)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| Reveal reads the hash without deleting it | `assert 200 == 404` on the second reveal; concurrent: `[200, 200, 20...]` instead of one 200 | `test_create_then_reveal_once_then_404`, `test_concurrent_reveals_deliver_once` |
| `"1d"` maps to 8640 seconds | `assert (86400 - 5) <= 8640` | `test_expiry_names_become_seconds[1d]` |
| Malformed id answers a different 404 | `Left contains 3 more items` (too short, too long, wrong chars differ from the uniform 404) | `test_404_is_byte_identical_for_missing_read_expired_and_malformed` |
| IV length not checked | `('iv 11 bytes', '{"id":...}')`, `assert 201 == 422` | `test_every_refusal_is_an_error_and_stores_nothing` |
| Block multiple not checked | `('ciphertext with no block', ...)`, `assert 201 == 422` | same |
| Maximum size not checked | `('ciphertext over the limit', ...)`, `assert 201 == 422` | same |
| Expiry accepts any string | `KeyError: '2h'` (and `'1H'`, `''`) | same |
| Canonical base64url check removed | `('iv with padding', ...)`, `('iv standard alphabet', ...)`, `assert 201 == 422` | same |
| Unknown fields ignored (a caller-made `id` is accepted) | `assert 201 == 422` | `test_the_server_picks_the_id`, same |
| Missing fields get defaults | `assert 201 == 422` | `test_missing_fields_are_refused` |
| Limit one block too low | `ciphertext is larger than 10256 bytes`, `assert 422 == 201` on a valid 41-block secret | `test_valid_sizes_up_to_the_limit_are_accepted` |
| Body limit middleware removed | `assert 422 == 413` | `test_a_body_over_the_limit_is_413_by_content_length`, `..._streamed_body...` |
| Streamed bytes not counted | `assert 422 == 413` | `test_a_streamed_body_over_the_limit_is_413_without_content_length` |
| `GET /s/<id>` consumes the secret | `assert 0 == 1` on `EXISTS`, for every preview user agent | `test_get_and_head_with_preview_agents_consume_nothing` |
| `GET /s/<id>` answers 404 for dead ids | `assert 2 == 1` distinct pages | `test_the_open_page_is_the_same_for_every_id` |
| `/static` mount removed | `assert 404 == 200` | `test_pages_and_scripts_are_served` |

One check is redundant by design and has no red case: the Content-Length test of the body limit is
also caught by the streamed-bytes count, so removing only the header check changes nothing a
client can see. It stays as a cheap early refusal.

### Browser (`tests/test_browser.py`, spec tests 1, 4, 5, 6, 13, plus the crypto contract)

Real Chromium against the real server process and Redis 7.4.

| Planted bug | Red output (reason) | Test |
|---|---|---|
| Key appended to the reveal URL (`?k=<key>`) | `key canary in requests, after reveal` (`['base64-url+0']`) | `test_neither_the_text_nor_the_key_leaves_the_browser` |
| Plaintext sent as the ciphertext | `text canary in requests, after create` (`base64-std+0`, `base64-url+0`) | same |
| Plaintext sent to a telemetry URL after decrypting | `text canary in requests, after reveal` (`raw`, `percent`, `percent-plus`) | same |
| Page reveals on load | the Reveal button is gone, `Locator expected to be visible: hidden` | `test_opening_the_link_in_a_browser_consumes_nothing` |
| Key length not checked | `Locator expected to contain text 'Incomplete link'`, actual `Ready. Opening the secret...` | `test_a_link_without_the_whole_key_says_so_and_never_calls_the_server` |
| Page calls the server when the key is incomplete | `assert [<Request ... /reveal method='POST'>] == []` | same |
| Every link treated as incomplete | `Locator expected to be visible: hidden` | `test_a_link_with_the_whole_key_offers_to_reveal` |
| Decrypt failure reported as success | `Locator expected to contain text 'Could not decrypt'`, actual `Secret opened.` | `test_an_altered_secret_is_refused`, `test_the_wrong_key_is_refused` |
| Fragment not cleared | `assert '#G0O2...' == ''` and `assert '#' not in 'http://127...'` | `test_the_fragment_is_removed_from_the_address_bar_after_opening` |
| No `hashchange` handling | `Page.click: Timeout` waiting for the Reveal button | `test_completing_the_fragment_on_the_open_page_enables_reveal_without_a_reload` |
| Padding depends on text length parity | `assert 704 == 363` ciphertext characters for 1 and 200 byte texts | `test_ciphertext_size_shows_only_the_block_count` |
| Encryption key derived with the `password` label | `cryptography.exceptions.InvalidTag` in the independent decryptor | `test_the_browser_uses_hkdf_labels_and_aes_gcm_like_an_independent_implementation` |
| Password subkey derived with the `encryption` label | the bytes differ from the independent HKDF (`b'\xc4\xd9...' != b'\x98\xa4...'`) | same |
| 10 KB limit removed from the page and from `encrypt` | `Locator expected to contain text 'longer than 10 KB'` | `test_text_over_10kb_is_refused_in_the_browser_before_any_request` |
| `unpad` keeps the `0x80` marker | the secret never shows: `Locator expected to be visible: hidden` | `test_text_round_trips_including_unicode_and_the_size_limit` |

Limits worth knowing:

- The tamper test flips one byte of the stored IV, ciphertext start, middle and GCM tag. Its
  proof is the page-level plant above (a failure shown as success), not a weakened cipher.
- The server cannot enforce the exact 10240-byte text limit, only the padded block count, so it
  accepts texts up to 10495 bytes; the browser enforces 10 KB.
- Spec tests 7 (password), 10 (creation limit) and 11 (headers) are covered in the Lot 3
  sections below.

## Lot 3, part A (review gaps of lot 2)

Run on Redis 7.4 (`-k redis-7.4`), `src/` restored with `git checkout` after each row, green again.

| Planted bug | Red output (reason) | Test |
|---|---|---|
| IV always 12 zero bytes in `encrypt` | `AssertionError: an IV was used twice`, `assert 1 == 4` | `test_browser_crypto.py::test_every_secret_gets_a_fresh_iv_and_key_of_the_right_size` |
| `newKey()` always the same 32 bytes | `AssertionError: a key was used twice`, `assert 1 == 4` | same |
| AES key derived with `extractable: true` | `assert True is False` on `extractable` | `test_browser_crypto.py::test_the_derived_aes_key_is_not_extractable` |

Before these tests, planting the zero IV and the fixed key left all 138 tests green: both still
round-trip, so only looking at what was made can catch them.
| `/api/secrets/` catch-all answers a different 404 body | `Left contains 10 more items` (every probe differs from the reveal 404) | `test_api.py::test_malformed_routes_under_api_secrets_get_the_same_404` |

(Before the catch-all, the same test was red with the framework's own `{"detail":"Not Found"}` on all 10 probes.)

## Lot 3, part B: security headers (spec test 11) and creation limit (spec test 10)

Run on Redis 7.4. Each plant was removed right after its run and the file restored.

### Headers (`tests/test_headers.py`)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| `connect-src 'self'` becomes `'none'` | `Left contains 12 more items` (every response has a different CSP) | `test_every_response_has_the_security_headers` |
| Nonce is the constant `"A" * 22` | `AssertionError: a nonce was reused`, `assert 1 == 9` | `test_the_nonce_is_new_on_every_response_and_matches_the_script_tag` |
| Headers added only when the status is below 400 | `create 413`, `create 422`, `create 429` have no `cache`, `hsts`, `nosniff`, `referrer` | `test_every_response_has_the_security_headers` |
| `Referrer-Policy: same-origin` | `{'create 201': {'referrer': 'same-origin'}, ...}` | same |
| HSTS header removed | `{'create 201': {'hsts': ''}, ...}` | same |
| Open page script tag with `nonce="fixed"` instead of the response nonce | `assert '<script type="module" nonce="3UHF...' in '<!doctype html>...nonce="fixed"...'` | `test_the_nonce_is_new_on_every_response_and_matches_the_script_tag` |

The byte-for-byte 404 tests now blank the nonce before comparing: it is random on purpose.

### Creation limit (`tests/test_limits.py`)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| Client IP is the leftmost `X-Forwarded-For` entry | `[201, 201, 201, 201, 201] == [201, 201, 201, 429, 429]` (forging the header dodges the limit) | `test_a_forged_forwarded_header_does_not_pick_the_bucket` |
| Count with `GET` then `SET` from Python | `assert [201, 201, 20...201, 201, ...] == [...]`, `At index 10 diff: 201 != 429` (60 simultaneous creations, more than 10 pass) | `test_the_count_is_one_atomic_step_under_concurrency` |
| `PEXPIRE` removed from the Lua script | `assert 0 < -1` on the counter's `PTTL` (no window) | same |
| Trusted hops ignored (bucket is always the peer) | `assert [429] == [201]` (a different real client is limited too) | `test_a_forged_forwarded_header_does_not_pick_the_bucket` |
| A non-address entry becomes the bucket key | `AssertionError: assert 'not-an-ip' == '10.0.0.9'` | `test_client_ip_buckets` |
| IPv6 not grouped by /64 | `assert [201, 201, 201, 201] == [201, 201, 201, 429]` | `test_a_whole_ipv6_64_shares_one_bucket` |
| Limiter placed inside the body limit (refused bodies are not counted) | `assert 201 == 429` | `test_a_refused_body_still_counts_toward_the_limit` |
| `Retry-After` header dropped | `KeyError: 'retry-after'` | `test_the_creation_after_the_limit_is_429_with_retry_after` |

## Lot 3, part B: access password (spec test 7), API and server keys

Run on Redis 7.4. Each plant restored right after its run.

### Server (`tests/test_password.py`, `tests/test_keyring.py`)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| `seal` stores the raw verifier after the header instead of its HMAC | `assert b"\x02\x00\t'...\x1d\x1e\x1f" == b"\x02\x00\t'...xdfj\xf0c\xaf"` | `test_password.py::test_the_server_stores_a_keyed_hash_never_the_verifier` (and `test_keyring.py::test_seal_is_header_plus_hmac...`) |
| `==` instead of `hmac.compare_digest` on the keyed path | `assert [] == [(b"\x02\x00...", b"\x02\x00...")]` (the spy was never called) | `test_the_candidate_is_compared_in_constant_time_in_python` |
| `bind` uses the current key instead of the key version stored with the secret | `assert 403 == 200` for a v1 secret opened after rotation | `test_a_key_rotation_keeps_old_secrets_openable` |
| An unknown key version falls back to the current key | `assert 403 == 500` (a dropped key is treated as a wrong password) | `test_a_dropped_key_is_a_server_error_that_does_not_burn_attempts` |
| Wrong-password counter as read then write from Python | `[403, 403, 40...] == [403, ..., 404, ...]`, `At index 5 diff: 403 != 404` (40 simultaneous wrong tries, more than 5 counted) | `test_simultaneous_wrong_passwords_are_counted_exactly_to_the_limit` |
| Iterations floor lowered to 1 | `('iterations one below the floor', ...)`, `assert 201 == 422` | `test_every_password_refusal_is_an_error_and_stores_nothing` |
| Iterations ceiling removed | `('iterations one above the ceiling', ...)`, `assert 201 == 422` | same |
| Verifier and iterations no longer required together | `('verifier without iterations', ...)`, `assert 201 == 422` | same |
| Wrong password answers nothing (no own response) | `[200, 200, 200, 200, 200] == [403, 403, 403, 403, 403]` | `test_five_wrong_passwords_destroy_the_secret` |
| "Password required" answered as the 404 | `assert (404, {'detail': 'not found'}) == (403, {'error': 'password_required', ...})` | `test_a_protected_secret_asks_for_the_password_and_keeps_every_attempt` |
| Unknown fields accepted in the reveal body | `assert 200 == 422` | `test_a_malformed_verifier_is_refused_and_not_counted` |
| Verifier length not checked | `assert 403 == 422` on a 31 byte verifier | same |
| Missing server keys accepted at boot (`Keyring.parse` guard removed) | `AttributeError: 'NoneType' object has no attribute 'split'` instead of `KeyringError` | `test_keyring.py::test_bad_server_keys_refuse_to_boot` |

What the password does not hide: whoever holds a secret id (128 random bits) can learn that the
secret exists and is protected (the 403 answers), and can spend its five attempts. Someone with
no id learns nothing; ids that are missing, read, expired or malformed all get the same 404,
with or without a verifier (`test_a_gone_secret_gets_the_one_404_with_or_without_a_verifier`).

### Password in the browser (`tests/test_browser_password.py`)

Real Chromium, Redis 7.4.

| Planted bug | Red output (reason) | Test |
|---|---|---|
| The create call sends the password in an extra header | `AssertionError: password canary in requests`, encodings `raw`, `percent`, `percent-plus` | `test_the_password_never_reaches_the_server` |
| Verifier salt is 32 zero bytes instead of the `password` subkey | `assert b'\x96O\x8c...' == b'9\xd9\xff+Q...'` against Python's own `hashlib.pbkdf2_hmac` | `test_the_verifier_is_pbkdf2_of_the_password_salted_with_the_password_subkey` |
| 1,000 iterations while the page declares 600,000 | `assert b'\x8bl\t...' == b'9\xd9\xff+Q...'` | same |
| `normalize("NFKC")` removed | `assert [False, False] == [True, False]` (composed and decomposed forms differ) | `test_the_same_password_typed_in_two_unicode_forms_gives_the_same_verifier` |
| AES key derived with `extractable: true` (whole-flow recorder) | `Left contains 4 more items`, first `{"name":"deriveKey","algo":"AES-GCM","extractable":true}` | `test_no_key_the_pages_make_is_extractable_in_the_whole_flow` |
| Inline `<script>` without nonce added to the open page | `Executing inline script violates the following Content Security Policy directive 'script-src 'nonce-...'` | `test_the_pages_run_under_the_csp_without_a_violation` |
| Wrong-password message without the countdown | `Locator expected to contain text 'Wrong password. 4 attempts left'`, actual `Wrong password. ` | `test_a_wrong_password_counts_down_and_the_right_one_still_works` |
| Fragment not cleared when the fifth wrong password destroys the secret | `assert '#' not in 'http://127...#6bJv...'` | `test_five_wrong_passwords_destroy_the_secret_and_the_page_says_so` |
| The page ignores the 403 "password required" answer | `Locator expected to be visible` on `#password-form`, actual `hidden` | `test_a_protected_secret_asks_for_the_password_and_opens_with_it` |

One plant was refused by the browser itself: PBKDF2 base key with `extractable: true` makes Chromium
throw, so the page cannot even create (red on `#result`, not on the recorder). That is why the
recorder row above uses the AES key instead.

### Creation limit against the real server process (`tests/test_limits.py`)

Real uvicorn (`--no-proxy-headers`), one trusted hop, limit 3.

| Planted bug | Red output (reason) | Test |
|---|---|---|
| Client IP is the leftmost `X-Forwarded-For` entry | `assert [201, 201, 201, 201, 201] == [201, 201, 201, 429, 429]` | `test_the_real_server_ignores_a_forged_header_and_answers_429_and_413` |
| Body limit middleware removed | `assert 422 == 413` | same |

## Lot 4

### Fresh IV and key inside one page load (`tests/test_browser_crypto.py`)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| IV drawn once at module level and reused by `encrypt` | `AssertionError: an IV was used twice on one page load`, `assert 1 == 4`; and `encrypt repeated an IV`, `assert 1 == (2 * 20)` | `test_one_page_load_never_reuses_an_iv_or_a_key_through_the_form`, `test_the_encrypt_function_never_repeats_an_iv_or_newkey_a_key_in_one_page` |
| `newKey` caches its key in a module variable | `AssertionError: a key was used twice on one page load`, `assert 1 == 4`; and `newKey repeated a key`, `assert 1 == 20` | same two tests |

### Security headers on a 500 (`tests/test_headers.py`)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| No catch in `SecurityHeadersMiddleware` (Starlette's own 500 handler answers, outside our middleware); route raises | `assert '' == "default-src ...ct-src 'none'"` (no CSP on the 500) | `test_a_500_from_a_route_has_the_headers_a_generic_body_and_a_log_line` |
| Same, the limit middleware (inside) raises | `assert '' == "default-src ...ct-src 'none'"` | `test_a_500_from_an_inner_middleware_has_the_headers_a_generic_body_and_a_log_line` |
| Same, three 500s in a row | `KeyError: 'content-security-policy'` | `test_each_500_gets_its_own_nonce` |

### IPv4 mapped into IPv6 (`tests/test_limits.py`)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| Mapped address cut to /64 like any IPv6 (the code before the fix) | `assert [429] == [201]`: a second mapped IPv4 lands in the first one's `::/64` bucket | `test_two_mapped_ipv4_addresses_have_their_own_buckets` |
| same | `assert [201] == [429]`: the mapped and the plain IPv4 do not share a bucket | `test_a_mapped_ipv4_and_the_plain_one_share_a_bucket` |
| same, address from `X-Forwarded-For` | `assert [429] == [201]` | `test_a_mapped_ipv4_in_the_forwarded_header_has_its_own_bucket` |
| same, pure function | 6 of 7 rows red, e.g. `AssertionError: assert '::/64' == '198.51.100.7'`; the real IPv6 row stays green | `test_an_ipv4_mapped_in_ipv6_is_the_plain_ipv4` |

### README test command (`tests/test_readme.py`)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| A continuation turned back into a literal backslash and `n` (the old README) | `AssertionError: assert '\n' not in 'uv run pyte...readme.py -q'` | `test_the_command_has_no_literal_backslash_n` |
| same | `ERROR: file or directory not found: n`, `assert 4 == 0` when the pasted command is collected | `test_the_pasted_command_collects_every_test_without_error` |
| Old README (a test file missing from the command, the `n` argument) | `the README command and tests/ disagree` | `test_the_command_names_every_test_file_once` |

### Log line of a 500 (`tests/test_headers.py`)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| The raw decoded path goes to the log | `AssertionError: 'unhandled error on GET /s/x<LF>FAKE LOG LINE<CR><ESC><DEL><0x85>'` (a real newline in the message) | `test_a_500_log_line_carries_no_control_character_and_no_secret_id` |
| The secret id is not masked (escaping stays) | `AssertionError: unhandled error on GET /s/x\nFAKE LOG LINE...`, the escaped form, but the id and `FAKE` are still in the line | same |
| Control characters are not escaped (the id mask stays) | `AssertionError: 'unhandled error on GET /x<LF>FAKE LOG LINE<CR><ESC><DEL><0x85><U+2028>é'` | `test_a_path_outside_the_secret_routes_is_escaped_in_the_log` |

### Error after the response started (`tests/test_headers.py`)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| `raise` replaced by `pass` in the `started` branch (the error is swallowed and a second response is sent) | `Failed: DID NOT RAISE <class 'RuntimeError'>` | `test_an_error_after_the_response_started_is_raised_not_answered_twice` |

### Peer fallback in `client_ip` (`tests/test_limits.py`)

| Planted bug | Red output (reason) | Test |
|---|---|---|
| A trusted header that is not an address returns the raw peer | `AssertionError: assert '::ffff:1.2.3.4' == '1.2.3.4'` and `assert '2001:db8:1:2...bbb:cccc:dddd' == '2001:db8:1:2::/64'` | `test_an_ipv4_mapped_in_ipv6_is_the_plain_ipv4` (rows `garbage` and `not an ip`) |
| The peer is never normalized (the final `return` is the raw peer) | red, among them `assert '::ffff:198.51.100.7' == '198.51.100.7'`, `assert [201] == [429]` (mapped peer and plain IPv4 in separate buckets) | the same test, `test_a_mapped_ipv4_and_the_plain_one_share_a_bucket`, `test_two_mapped_ipv4_addresses_have_their_own_buckets` |
| A peer that is free text is the key (the code before the fix) | `AssertionError: assert 'not an address' == 'unknown'` | the same test (row `not an address`) |
