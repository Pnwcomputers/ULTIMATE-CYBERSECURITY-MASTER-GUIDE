# Algorithm Fundamentals, Complexity & Data Structures

[Algorithm Index](./README.md) | [Offline Labs](./labs.md)

## What An Algorithm Actually Is

A useful algorithm specifies **inputs**, **preconditions**, **steps**, **outputs**, **invariants**, and **failure conditions**. For a network alert evaluator, for instance: input is a series of timestamped events; preconditions include valid timestamps and a documented event key; output is a score or alert; a failure may be missing data or an unbounded queue. The algorithm does not magically supply trustworthy data or make the resulting decision correct.

Compare these building blocks:

| Concept | Role | Example |
|---|---|---|
| Algorithm | Procedure | Dijkstra's shortest-path algorithm |
| Data structure | Organizes state | Binary heap, adjacency list, B-tree |
| Heuristic | Useful estimate; may not guarantee an optimum | A* remaining-cost estimate |
| Protocol | Communicating parties' agreed behavior | OSPF, BGP, TLS |
| Primitive | Narrow computational/security building block | SHA-256 hash; AES block cipher |
| System | Many components acting together | Maps application, search engine, SIEM |

## The Five Questions To Ask Before Selecting One

1. **Correctness:** What is the exact result being optimized or checked? Are its premises true?
2. **Scale:** How many records, edges, bytes, requests, concurrent users, and updates?
3. **Constraints:** Is memory limited? Must the response be real-time? Can output be approximate?
4. **Threat model:** Can an adversary choose inputs, induce worst-case behavior, poison labels, or observe timings?
5. **Validation:** What test case, performance measurement, and monitoring would reveal a failure?

## Understanding Big-O Without Confusing It With Benchmarks

Big-O describes an **asymptotic upper bound** (often used to discuss worst-case growth), not a guaranteed wall-clock time. Average-case and amortized analysis are separate concepts. Constants, allocation, cache locality, I/O, network delay, and adversarial inputs often dominate real outcomes.

| Growth | Intuition | Typical Illustration |
|---|---|---|
| O(1) expected | Roughly constant per operation under assumptions | Hash-table lookup with a well-behaved hash/distribution |
| O(log n) | Each step discards a large fraction of choices | Binary search on a sorted random-access array |
| O(n) | Scan each item once | Linear pattern scan or a log pass |
| O(n log n) | Split/order/merge efficiently | Comparison sorting, e.g. merge sort |
| O(n²) | Compare many pairs | Naive pairwise correlation |
| O(2^n) | Rapid combinatorial explosion | Enumerating all subsets in a naive solution |

**Example:** For a million ordered entries, binary search needs at most about 20 comparisons (plus a small endpoint convention); a linear scan may inspect the whole list. That difference disappears if obtaining a sorted view is expensive or if every lookup crosses a slow remote connection.

**Space complexity** matters too: an O(n) auxiliary index can speed lookups but consume RAM and require maintenance. A bloom filter trades exact membership for memory and controlled false positives.

## Core Data Structures Worth Recognizing

| Structure | Useful Operations | Where It Appears | Caveat |
|---|---|---|---|
| Array / list | Indexed access, sequential scan | Binary search, packet buffers | Insertion in the middle can be O(n) |
| Hash table / dictionary | Expected fast insert/search | Device inventory, log aggregation, caches | Collision behavior and memory overhead matter |
| Heap / priority queue | Remove smallest priority in O(log n) | Dijkstra, schedulers, incident priority queues | Finding arbitrary items is not inherently fast |
| Tree / B-tree family | Ordered indexing, range scans | Storage engines and database indexes | Layout and disk/page sizes affect performance |
| Graph / adjacency list | Traverse neighbors | OSPF topology, dependencies, threat graphs | Data quality and directed/undirected semantics matter |
| Trie / automaton | Shared prefixes and pattern matching | IP prefixes, IDS multi-pattern searches | Memory and encoding choices matter |
| Queue / deque | Ordered work and window management | Log pipelines, breadth-first search | Unbounded queues risk memory exhaustion |
| Probabilistic sketch | Approximate summary | Cardinality and high-volume telemetry | Know the error model; cannot replace evidence |

### Why Graph Representation Matters

For V vertices and E edges, an adjacency list uses O(V+E) storage and is natural for sparse networks; an adjacency matrix uses O(V²) but supports constant-time edge-presence checks. An algorithm expressed as O((V+E) log V) with a binary heap may perform very differently from a naive O(V²) implementation on the same topology.

## Correctness, Invariants & Test Cases

A binary-search invariant is that any valid match must remain inside the current candidate interval. If the input is not sorted in the chosen comparison order, the invariant is false and the output is unreliable.

A shortest-path invariant in standard Dijkstra is that once the smallest-distance unsettled vertex is finalized, its distance is optimal **if edge weights are nonnegative**. Negative edges break this guarantee; use an algorithm that supports the relevant weight model instead.

A detection-window invariant could state: each event belongs to precisely the intended time window and contributes at most once per event identifier. Late, duplicated, and missing events challenge this promise.

| Test Type | Example |
|---|---|
| Happy path | Shortest path through two intermediate nodes |
| Boundary | Empty list, one element, no reachable destination |
| Adversarial | Duplicate keys, ties, high-degree graph, compressed bomb |
| Property | Returned path edge costs sum to reported cost |
| Regression | New version matches a known deterministic fixture |
| Performance | Measure runtime/memory at realistic input sizes; report environment |
| Security | Validate malformed input, untrusted metadata & fail-closed decisions |

## Optimization Patterns In Everyday Systems

### Dynamic Programming

Store results for overlapping subproblems instead of recomputing. This appears in edit distance, sequence alignment, resource allocation, and some anomaly-scoring workflows. Memoization (top-down) and tabulation (bottom-up) are two common styles. Correctness still requires a valid recurrence.

### Greedy Choice

Pick a locally best option at each step. This works for tasks with a provable greedy-choice property (for example, Dijkstra with nonnegative edge weights), but not for every optimization problem. Always distinguish a proven guarantee from a heuristic.

### Divide & Conquer

Split a problem, solve parts, and combine. Merge sort is a classic example; binary search discards half of a sorted search region at each step. Divide-and-conquer does not automatically imply parallelism or optimal memory use.

### Caching & Eviction

Caching trades storage and staleness for lower latency. Least recently used (LRU) and least frequently used (LFU) are eviction policies, not substitutes for cache consistency. Time-to-live (TTL) alone does not guarantee fresh DNS, inventory, or security-policy results. Validate authorization **before returning cached sensitive results**, and partition cache keys by tenant and privilege context.

### Optimal Stopping & Human Decisions

The secretary problem's classic approximately 37% observation strategy assumes a specific mathematical model: fixed number of candidates, random order, no recall, and maximizing the probability of selecting the best. It is an illustration of decision-making under uncertainty, **not** a universally optimal hiring, purchasing, or incident-response rule.

## Security Pitfalls Of Algorithm Choice

- **Algorithmic complexity denial of service:** Inputs designed to trigger slow regex backtracking, quadratic parsing, heavy graph traversal, or expensive decompression.
- **Hash collision abuse:** A hash table with weak/unkeyed distribution under attacker-chosen keys can degrade; use language/runtime hardening and input limits.
- **Resource exhaustion:** Bound message sizes, CPU budget, recursion depth, concurrent jobs, memory, decompression expansion, and time windows.
- **Data poisoning & feedback:** Recommendation engines and anomaly baselines can learn from malicious or manipulated events.
- **Timing channels:** Secret-dependent branches, comparisons, and memory access may leak information. Use vetted constant-time crypto implementations; a Python teaching demonstration is not one.
- **Fairness & operational errors:** Score distributions, missing data, and false positives require human review and a documented appeal/rollback route.

## Mini Walkthrough: Search For An Asset

Suppose an inventory has 8 ordered asset IDs. Binary search compares the middle item, determines whether the target is to its left or right, and repeats until the item is found or the interval is empty. At most four comparisons are needed for a successful lookup in the worst case here; a naive linear scan may inspect eight. In a live asset system, indexing and update costs must also be included.

## Learn More

| Reference | Why It Matters |
|---|---|
| [Python Complexity Notes](https://wiki.python.org/moin/TimeComplexity) | Container operation costs and assumptions |
| [Python Sorting HOWTO](https://docs.python.org/3/howto/sorting.html) | Stability, keys & Timsort |
| [OWASP Denial Of Service](https://owasp.org/www-community/attacks/Denial_of_Service) | Availability impacts of expensive processing |
| [Offline Labs](./labs.md) | Verify assumptions on synthetic data |

## Related Repository Guides

| Resource | Purpose |
|---|---|
| [Data Engineering](../Data-Engineering/README.md) | Pipeline quality, indexing & orchestration |
| [AI Evaluations](../AI/ai-evaluation-and-regression-testing.md) | Evaluating model and agent behavior |
| [Network Security](../Documentation/network-segmentation-dmz-acl-vlan.md) | Practical trust boundaries and traffic controls |

---

[Algorithm Index](./README.md) | [Main Index](../README.md) | [Legal](../LEGAL.md)
