#!/usr/bin/env python3
"""Standard-library-only, offline algorithms teaching lab.

All datasets are synthetic. Educational reference: not production routing,
cryptography, intrusion detection, or an automated blocking tool.
Run: python Algorithms/labs/algorithm_lab.py
Demo: python Algorithms/labs/algorithm_lab.py --demo
"""

from __future__ import annotations

import hashlib
import heapq
import math
import sys
import unittest
import zlib
from bisect import bisect_left
from collections import deque
from typing import Mapping

Graph = Mapping[str, Mapping[str, float]]

GRAPH: dict[str, dict[str, float]] = {
    "A": {"B": 2, "C": 5},
    "B": {"C": 1, "D": 4},
    "C": {"D": 2},
    "D": {},
}
ADMISSIBLE_HEURISTIC = {"A": 4, "B": 3, "C": 2, "D": 0}


def _checked_neighbors(graph: Graph, vertex: str):
    for neighbor, weight in graph.get(vertex, {}).items():
        if not math.isfinite(weight) or weight < 0:
            raise ValueError("Shortest-path lab requires finite nonnegative weights")
        yield neighbor, weight


def _reconstruct(previous: dict[str, str], source: str, target: str):
    if source == target:
        return [source]
    if target not in previous:
        return []
    path = [target]
    while path[-1] != source:
        path.append(previous[path[-1]])
    return list(reversed(path))


def dijkstra(graph: Graph, source: str, target: str):
    """Return (distance, path); unreachable -> (inf, [])."""
    distances = {source: 0.0}
    previous: dict[str, str] = {}
    heap = [(0.0, source)]
    while heap:
        cost, vertex = heapq.heappop(heap)
        if cost != distances[vertex]:
            continue  # stale candidate after a better route was found
        if vertex == target:
            return cost, _reconstruct(previous, source, target)
        for neighbor, weight in _checked_neighbors(graph, vertex):
            candidate = cost + weight
            if candidate < distances.get(neighbor, math.inf):
                distances[neighbor] = candidate
                previous[neighbor] = vertex
                heapq.heappush(heap, (candidate, neighbor))
    return math.inf, []


def a_star(graph: Graph, source: str, target: str, heuristic: Mapping[str, float]):
    """Toy A* implementation; optimality requires an admissible heuristic.

    No permanent closed set: improved distances can be reconsidered.
    """
    dist = {source: 0.0}
    previous: dict[str, str] = {}
    heap = [(heuristic[source], 0.0, source)]
    while heap:
        _, cost, vertex = heapq.heappop(heap)
        if cost != dist[vertex]:
            continue
        if vertex == target:
            return cost, _reconstruct(previous, source, target)
        for neighbor, weight in _checked_neighbors(graph, vertex):
            new_cost = cost + weight
            if new_cost < dist.get(neighbor, math.inf):
                dist[neighbor] = new_cost
                previous[neighbor] = vertex
                estimate = heuristic[neighbor]
                if not math.isfinite(estimate) or estimate < 0:
                    raise ValueError("Heuristic must be finite and nonnegative")
                heapq.heappush(heap, (new_cost + estimate, new_cost, neighbor))
    return math.inf, []


def binary_lower_bound(sorted_values: list[int], target: int):
    """First index i where sorted_values[i] >= target."""
    low, high = 0, len(sorted_values)
    while low < high:
        mid = low + (high - low) // 2
        if sorted_values[mid] < target:
            low = mid + 1
        else:
            high = mid
    return low


def sliding_counts(events: list[tuple[int, str]], window: int):
    """Number of events in (t-window, t] for each input event.

    Input is sorted ascending by integer event-time seconds.
    This toy example does not handle out-of-order data.
    """
    if window <= 0:
        raise ValueError("window must be positive")
    if any(events[i][0] > events[i + 1][0] for i in range(len(events) - 1)):
        raise ValueError("events must be sorted")
    recent: deque[int] = deque()
    result = []
    for event_time, _ in events:
        recent.append(event_time)
        while recent and recent[0] <= event_time - window:
            recent.popleft()
        result.append((event_time, len(recent)))
    return result


def ewma(values: list[float], alpha: float):
    """Return exponentially weighted baselines, first value as initial state."""
    if not (0 < alpha <= 1):
        raise ValueError("alpha must be in (0, 1]")
    if not values:
        return []
    baselines = [float(values[0])]
    for value in values[1:]:
        baselines.append(alpha * value + (1 - alpha) * baselines[-1])
    return baselines


class TokenBucket:
    """Deterministic toy rate limiter driven by provided times, not wall clock."""

    def __init__(self, rate_per_second: float, capacity: float):
        if not (rate_per_second > 0 and capacity > 0):
            raise ValueError("Rate and capacity must be positive")
        self.rate = rate_per_second
        self.capacity = capacity
        self.tokens = capacity
        self.last_time = 0.0

    def allow(self, now: float, cost: float = 1.0):
        if now < self.last_time or cost <= 0:
            raise ValueError("Nonmonotonic time or nonpositive cost")
        self.tokens = min(self.capacity, self.tokens + (now - self.last_time) * self.rate)
        self.last_time = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


def compression_and_hash(data: bytes):
    """Return lossless roundtrip & SHA-256 hex digest; not an authenticity proof."""
    packed = zlib.compress(data)
    assert zlib.decompress(packed) == data
    return len(data), len(packed), hashlib.sha256(data).hexdigest()


class AlgorithmLabTests(unittest.TestCase):
    def test_dijkstra_expected_path(self):
        self.assertEqual(dijkstra(GRAPH, "A", "D"), (5.0, ["A", "B", "C", "D"]))

    def test_a_star_expected_path(self):
        self.assertEqual(
            a_star(GRAPH, "A", "D", ADMISSIBLE_HEURISTIC),
            dijkstra(GRAPH, "A", "D"),
        )

    def test_unreachable(self):
        self.assertEqual(dijkstra(GRAPH, "D", "A"), (math.inf, []))

    def test_self_route(self):
        self.assertEqual(dijkstra(GRAPH, "B", "B"), (0, ["B"]))

    def test_negative_weight_rejected(self):
        with self.assertRaises(ValueError):
            dijkstra({"A": {"B": -1}, "B": {}}, "A", "B")

    def test_binary_lower_bound(self):
        values = [2, 4, 4, 7]
        for target in [0, 2, 3, 4, 5, 8]:
            self.assertEqual(binary_lower_bound(values, target), bisect_left(values, target))

    def test_binary_empty(self):
        self.assertEqual(binary_lower_bound([], 9), 0)

    def test_sliding_window_boundary(self):
        events = [(0, "a"), (5, "b"), (10, "c")]
        self.assertEqual(sliding_counts(events, 10), [(0, 1), (5, 2), (10, 2)])

    def test_sliding_input_order(self):
        with self.assertRaises(ValueError):
            sliding_counts([(10, "a"), (9, "b")], 5)

    def test_ewma(self):
        self.assertEqual(ewma([10, 10, 20], 0.5), [10.0, 10.0, 15.0])

    def test_ewma_empty(self):
        self.assertEqual(ewma([], 0.5), [])

    def test_compression_and_hash(self):
        before, after, digest = compression_and_hash(b"test " * 100)
        self.assertLess(after, before)
        self.assertEqual(len(digest), 64)
        self.assertNotEqual(digest, hashlib.sha256(b"test" * 100).hexdigest())

    def test_token_bucket(self):
        bucket = TokenBucket(rate_per_second=1, capacity=2)
        self.assertTrue(bucket.allow(0))
        self.assertTrue(bucket.allow(0))
        self.assertFalse(bucket.allow(0))
        self.assertTrue(bucket.allow(1))
        self.assertFalse(bucket.allow(1))


def demo():
    print("Dijkstra:", dijkstra(GRAPH, "A", "D"))
    print("A*:", a_star(GRAPH, "A", "D", ADMISSIBLE_HEURISTIC))
    print("Lower bound for 4:", binary_lower_bound([2, 4, 4, 7], 4))
    print("Window counts:", sliding_counts([(0, "a"), (5, "b"), (10, "c")], 10))
    print("EWMA:", ewma([10, 10, 20], 0.5))
    before, after, digest = compression_and_hash(b"synthetic event " * 100)
    print("zlib bytes:", before, "->", after, "SHA-256:", digest[:16] + "...")


if __name__ == "__main__":
    if sys.argv[1:] == ["--demo"]:
        demo()
    else:
        unittest.main(verbosity=2)
