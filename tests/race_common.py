"""Shared by the asyncio race harness and the multi-process one."""

import random
from dataclasses import dataclass

from one_time_vault import MAX_ATTEMPTS

READERS = 50
ROUNDS = 15
V = b"verifier-bytes-0123456789abcdef"

# (name, protected, share of readers with the right password)
SCENARIOS = [
    ("public", False, 0.0),
    ("protected, all right", True, 1.0),
    ("protected, mixed", True, 0.5),
    ("protected, mostly wrong", True, 0.02),
    ("protected, all wrong", True, 0.0),
]


def candidates(n: int, *, protected: bool, right_share: float) -> list[bytes | None]:
    return [
        (V if random.random() < right_share else b"wrong") if protected else None for _ in range(n)
    ]


@dataclass
class Stats:
    delivered: int
    wrong_replies: int
    key_left: bool
    attempts_in_key: int


def violations(stats: Stats) -> list[str]:
    bad = []
    if stats.delivered > 1:
        bad.append(f"{stats.delivered} deliveries")
    if stats.wrong_replies > MAX_ATTEMPTS:
        bad.append(f"{stats.wrong_replies} counted attempts")
    if stats.attempts_in_key >= MAX_ATTEMPTS:
        bad.append("counter reached the limit but the key survived")
    if stats.delivered and stats.key_left:
        bad.append("delivered but still stored")
    return bad


def check_expectations(stats: Stats, *, protected: bool, right_share: float) -> None:
    assert not violations(stats), stats
    if protected and right_share == 0.0:
        assert stats.delivered == 0
        assert stats.wrong_replies == MAX_ATTEMPTS
        assert not stats.key_left
    if not protected or right_share == 1.0:
        assert stats.delivered == 1
