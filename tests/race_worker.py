"""One reader process for test_race_processes.py. Not a test.

Protocol on stdin/stdout, one JSON object per line. Each process owns its connection.
  argv: <redis url> <safe|naive>
  out : {"ready": true}   after the connection is warm
  in  : {"id": ..., "candidates": ["right"|"wrong"|null, ...], "start_at": <epoch seconds>}
  out : {"results": ["Revealed", ...]}
Exits at end of input.
"""

import asyncio
import json
import sys
import time

from redis.asyncio import Redis

from naive_storage import NaiveStorage
from one_time_vault import SecretStorage
from race_common import V

PICK = {"right": V, "wrong": b"wrong", None: None}


async def main(url: str, mode: str) -> None:
    redis = Redis.from_url(url, max_connections=200, socket_connect_timeout=30)
    store: SecretStorage = NaiveStorage(redis) if mode == "naive" else SecretStorage(redis)
    await asyncio.gather(*(redis.ping() for _ in range(20)))
    print(json.dumps({"ready": True}), flush=True)
    while line := await asyncio.to_thread(sys.stdin.readline):
        job = json.loads(line)
        cands = [PICK[c] for c in job["candidates"]]
        await asyncio.sleep(max(0.0, job["start_at"] - time.time()))
        results = await asyncio.gather(*(store.open(job["id"], c) for c in cands))
        print(json.dumps({"results": [type(r).__name__ for r in results]}), flush=True)
    await redis.aclose()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2]))
