"""Lua scripts. Every state change of a secret is one script, so it is one atomic step.

Secret layout: a hash at one key with fields `payload`, `attempts` and, only for password
protected secrets, `verifier`. The key TTL is the expiry. The verifier comparison is NOT done
here: Lua never sees the candidate, Python compares in constant time.
"""

# KEYS[1] secret key; ARGV[1] payload, ARGV[2] verifier ("" = no password), ARGV[3] ttl seconds.
# Returns 1 if created, 0 if the id is already taken (never overwrites).
CREATE = """
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end
redis.call('HSET', KEYS[1], 'payload', ARGV[1], 'attempts', 0)
if ARGV[2] ~= '' then
  redis.call('HSET', KEYS[1], 'verifier', ARGV[2])
end
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
return 1
"""

# KEYS[1] secret key. Returns false if absent, "" if public, else the stored verifier.
PEEK_VERIFIER = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return false
end
local v = redis.call('HGET', KEYS[1], 'verifier')
if not v then
  return ''
end
return v
"""

# KEYS[1] secret key; ARGV[1] "1" if the caller already proved the password.
# Returns false if absent, 0 if password protected and not proven (nothing touched),
# else the payload, deleted in the same step (at most one delivery).
REVEAL = """
local payload = redis.call('HGET', KEYS[1], 'payload')
if not payload then
  return false
end
if ARGV[1] ~= '1' and redis.call('HEXISTS', KEYS[1], 'verifier') == 1 then
  return 0
end
redis.call('DEL', KEYS[1])
return payload
"""

# KEYS[1] secret key; ARGV[1] max attempts. Returns -1 if absent, else the attempts left;
# 0 means this was the last one and the secret is gone.
FAIL = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return -1
end
local n = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
local max = tonumber(ARGV[1])
if n >= max then
  redis.call('DEL', KEYS[1])
  return 0
end
return max - n
"""
