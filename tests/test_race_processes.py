"""Concurrency proof across OS processes: every reader process has its own connection.

Several event loops and sockets hit the same secret at the same instant (a start time shared
through the clock), which asyncio inside one process cannot reproduce. A naive storage in the
same harness must be caught, so the harness cannot silently go blind.
"""

import asyncio
import json
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from redis.asyncio import Redis

from one_time_vault import SecretStorage
from race_common import SCENARIOS, Stats, V, candidates, check_expectations, violations

WORKER = str(Path(__file__).with_name("race_worker.py"))
PROCESSES = 6
READERS_PER_PROCESS = 8
ROUNDS = 4
TIMEOUT = 60


async def _json_line(proc: asyncio.subprocess.Process) -> dict[str, list[str] | bool]:
    assert proc.stdout is not None
    raw = await asyncio.wait_for(proc.stdout.readline(), TIMEOUT)
    assert raw, "worker exited early"
    out: dict[str, list[str] | bool] = json.loads(raw)
    return out


@asynccontextmanager
async def _workers(url: str, mode: str) -> AsyncIterator[list[asyncio.subprocess.Process]]:
    procs = [
        await asyncio.create_subprocess_exec(
            sys.executable,
            WORKER,
            url,
            mode,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        for _ in range(PROCESSES)
    ]
    try:
        for p in procs:
            assert (await _json_line(p)) == {"ready": True}
        yield procs
    finally:
        for p in procs:
            assert p.stdin is not None
            p.stdin.close()
        await asyncio.gather(*(p.wait() for p in procs))


async def _round(
    redis: Redis, procs: list[asyncio.subprocess.Process], *, protected: bool, right_share: float
) -> Stats:
    await redis.flushall()
    sid = await SecretStorage(redis).create(b"cipher", 60, verifier=V if protected else None)
    cands = candidates(
        PROCESSES * READERS_PER_PROCESS, protected=protected, right_share=right_share
    )
    start_at = time.time() + 0.3
    for i, p in enumerate(procs):
        chunk = cands[i * READERS_PER_PROCESS : (i + 1) * READERS_PER_PROCESS]
        labels = [None if c is None else ("right" if c == V else "wrong") for c in chunk]
        assert p.stdin is not None
        p.stdin.write(json.dumps({"id": sid, "candidates": labels, "start_at": start_at}).encode())
        p.stdin.write(b"\n")
    await asyncio.gather(*(p.stdin.drain() for p in procs if p.stdin))
    kinds: list[str] = []
    for p in procs:
        results = (await _json_line(p))["results"]
        assert isinstance(results, list)
        kinds.extend(results)
    key = f"ovv:s:{sid}"
    key_left = await redis.exists(key) == 1
    return Stats(
        delivered=kinds.count("Revealed"),
        wrong_replies=kinds.count("WrongPassword"),
        key_left=key_left,
        attempts_in_key=int(await redis.hget(key, "attempts") or 0) if key_left else 0,
    )


async def test_one_delivery_across_processes(server_url: str, redis: Redis) -> None:
    async with _workers(server_url, "safe") as procs:
        for _, protected, share in SCENARIOS:
            for _ in range(ROUNDS):
                stats = await _round(redis, procs, protected=protected, right_share=share)
                check_expectations(stats, protected=protected, right_share=share)


async def test_process_harness_catches_a_non_atomic_storage(server_url: str, redis: Redis) -> None:
    seen: set[str] = set()
    async with _workers(server_url, "naive") as procs:
        for _, protected, share in SCENARIOS:
            for _ in range(ROUNDS):
                stats = await _round(redis, procs, protected=protected, right_share=share)
                seen.update(violations(stats))
    assert any("deliveries" in v for v in seen), seen
    assert any("counted attempts" in v for v in seen), seen
