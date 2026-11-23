# Offline Algorithm Labs: Pathfinding, Search, Detection & Data Integrity

[Algorithm Index](./README.md) | [Lab Source Code](./labs/algorithm_lab.py)

## Purpose & Scope

These hands-on exercises use **synthetic data only**, the **Python 3 standard library**, and no network connections or privileged operations. The included source file is a teaching implementation, not a production router, SIEM, crypto library, or rate-limiting service.

**Prerequisites:** Python 3.10+ and a local checkout of this repository. The script uses typing annotations and data structures from the standard library. No pip install is required.

## Run The Exercises

From the repository root:

~~~bash
python3 Algorithms/labs/algorithm_lab.py
python3 Algorithms/labs/algorithm_lab.py --demo
~~~

On a system where Python is invoked as **python** rather than **python3**, replace the command accordingly. These commands run only local assertions and print toy examples. They do not send traffic, query real networks, change router configuration, or collect user data.

> [!NOTE]
> **Validation status:** The exercises include self-contained unit tests and deterministic fixtures. They should be executed in CI or locally before merging; the presence of tests is not a claim that they have already run successfully.

## Exercise 1: Dijkstra & A* On A Four-Node Network

Read [Graphs & Routing](./graphs-and-routing.md). The script stores a directed graph:

~~~text
A --2--> B --1--> C --2--> D
|         |                  ^
+---5---->C                  |
          +--------4-------->D
~~~

Note: the ASCII diagram depicts the same listed edge weights but can make the A→C and B→D edges appear visually close. **Use the explicit graph dictionary** in the source as the authoritative topology.

**Predict:** What is the cheapest A → D path? A → B → C → D with weight 5. Dijkstra must reject negative weights. A* should return the same optimum using the supplied heuristic, which is a valid lower bound for these synthetic nodes.

**Try:** Increase B → C from 1 to 10; rerun the tests. Which route is now optimal? Adjust the expected result deliberately and show both the path and total. Then test an unreachable destination. Do not change OSPF costs on a production router for this exercise.

## Exercise 2: Binary Search & Ordered Records

Read [Search & Indexing](./search-sorting-and-indexing.md). The lab implements a **lower-bound** binary search and compares it against Python's bisect_left:

~~~text
ordered = [2, 4, 4, 7]
target = 4
expected lower-bound index = 1
~~~

**Try:** Test an absent target, repeated values, and an empty list. Then intentionally provide an unsorted list. The routine has no way to infer the missing precondition: this illustrates why testing must establish **sortedness** rather than treating every returned integer as valid.

**Security application:** ordered asset identifiers, bounded lookup in a locally cached reference set, or locating the earliest event meeting a timestamp condition. In a production database, study the query plan and actual index rather than assuming it literally invokes this function.

## Exercise 3: Sliding Windows & Baselines

Read [Detection & Streaming](./detection-and-recommendations.md).

The window-count lab uses invented event times 0, 5 and 10 seconds, with window 10:

| Event Time | Events In (t-10, t] |
|---|---:|
| 0 | 1 |
| 5 | 2 |
| 10 | 2 |

The event exactly at 0 has exited the window by time 10. This **open-left, closed-right** convention is explicit. Change the event ordering to trigger the validation error; real streaming engines must use watermarks or other event-time policies for late data.

**EWMA demonstration:** For values [10, 10, 20] and alpha 0.5, the baselines are [10, 10, 15]. With alpha 0.1, the third baseline is 11; with alpha 0.9, it is 19.

**Try:** Model an innocent scheduled backup that causes an event spike. Would the baseline alone justify an emergency block? It would not. Attach context and investigate false positives.

## Exercise 4: Token Bucket Rate Limiting

A token bucket has a **refill rate** and a **burst capacity**.

Default fixture: capacity 2, rate 1 token/second. Two requests at time 0 are allowed, the third at 0 is rejected, one at 1 is allowed, and an additional request at time 1 is rejected.

**Try:** Increase capacity while keeping the rate constant. Observe that bursts become larger but sustained allowance stays bounded. Then model many users behind one NAT: why can a single-IP limiter block innocent requests? Review identity, distributed coordination and failure policy before transferring the idea to a production system.

## Exercise 5: Compression & SHA-256

The lab compresses a repeated **synthetic** byte string using Python zlib, checks that decompression returns identical bytes, and computes SHA-256. The test asserts that the repetitive input compresses smaller under this selected fixture.

**Try:** Replace the input with a short string and observe why the compressed size can be larger due to headers and overhead. Replace it with high-entropy random bytes and explain why little gain is expected. Use strictly bounded sample sizes.

**Trust question:** If a threat actor controls both a download and its advertised digest, does a match prove the file came from a trustworthy publisher? **No.** See [Compression, Hashing & Cryptography](./compression-hashing-and-crypto.md) and [Applied Cryptography](../Cryptography/applied-crypto.md).

## Exercise 6: Build A Detection Evaluation Table

Without accessing any real user or client logs, invent 1,000 events: 10 positive and 990 negative. Suppose a detector finds 9 positives but also flags 20 negatives. Compute:

| Metric | Calculation |
|---|---|
| Precision | 9 / (9 + 20) ≈ 31.0% |
| Recall | 9 / (9 + 1) = 90% |
| False-positive rate | 20 / 990 ≈ 2.02% |

This illustrates how base rate affects operator workload even when recall is high. Change the threshold in your hypothetical detector; record precision, recall, operating costs and missed detections.

## Reproducibility Checklist

- Record interpreter version (**python3 --version**) and exact commit SHA.
- Run the included tests on a clean checkout; archive success/failure output.
- Run the demo and check Dijkstra and A* both report the same expected path.
- Explain whether measurements are **theoretical complexity** or actual observed wall-clock performance.
- Separate clean synthetic results from claims about real product/router implementations.
- Keep test data private, synthetic and clearly labeled; do not introduce production secrets.
- Require review and rollback controls before turning a toy score into a blocking rule.

## Extension Ideas

| Extension | What You Would Measure |
|---|---|
| BFS vs Dijkstra | Hop count vs weighted cost on the same graph |
| A* heuristics | Number of nodes expanded with zero vs admissible spatial heuristic |
| Merge sort vs Python sort | Stability, performance, memory at increasing dataset sizes |
| Bloom filter | Approximate false-positive rate with different bit sizes/hash counts |
| Aho–Corasick matcher | Many patterns scanned once; normalization effects |
| Rate-limit keys | Fairness for multiple users on one IP |
| Compression safety | Expansion limit behavior on a deliberately **small, bounded** fixture |
| Anomaly thresholds | Precision, recall and base-rate impact |

## References & Related Repository Work

| Resource | Why It Helps |
|---|---|
| [Python unittest](https://docs.python.org/3/library/unittest.html) | Run deterministic tests |
| [Python bisect](https://docs.python.org/3/library/bisect.html) | Reference sorted lookup |
| [Python heapq](https://docs.python.org/3/library/heapq.html) | Priority queues |
| [Wireshark Investigation](../Documentation/wireshark-defensive-investigations.md) | Cross-check real-world network evidence |
| [Wazuh/Snort/nzyme Architecture](../IncidentResponse/IDS%26IPS/unified-network-visibility-architecture.md) | Apply validated detection ideas to a real sensor stack |

---

[Algorithm Index](./README.md) | [Main Index](../README.md) | [Legal](../LEGAL.md)
