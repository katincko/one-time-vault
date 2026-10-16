# Negative proofs, lot 1 (storage layer)

Each row: bug planted in `src/`, suite run against real Redis 7.4 (first failure shown), bug removed, suite green.

| Planted bug | Red output (reason) | Test |
|---|---|---|
| Lua reveal replaced by `HGET` then `DEL` as separate commands | `Stats(delivered=50, ...)`, `assert not ['50 deliveries']` (Valkey 8.0 too) | `test_race.py::test_at_most_one_delivery_and_counter_capped` |
| Wrong-attempt counter as read then write instead of Lua | `Stats(delivered=1, wrong_replies=1, key_left=True, ...)`, `['delivered but still stored']` | `test_race.py::test_at_most_one_delivery_and_counter_capped` |
| `EXPIRE` removed from create | `assert 0 < -1` on `PTTL` | `test_storage.py::test_ttl_is_set_and_secret_vanishes_in_real_redis` |
| `DEL` removed from reveal | `Revealed(payload=b'cipher') == NotFound()` | `test_storage.py::test_second_read_fails` |
| Last wrong attempt no longer destroys (`>=` to `>`) | `assert 1 == 0` on `EXISTS` | `test_storage.py::test_five_wrong_passwords_destroy_the_secret` |

The race harness is also kept alive in the suite: `test_race_harness_catches_a_non_atomic_storage`
runs it against a deliberately naive storage and requires it to report the violations.
