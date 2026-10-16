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
- Spec tests 7 (password), 10 (creation limit) and 11 (headers) belong to lot 3 and are not
  covered here.

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
