# Search, Sorting, Indexing & Information Retrieval

[Algorithm Index](./README.md) | [Foundations](./foundations-and-complexity.md) | [Offline Labs](./labs.md)

## Search Is More Than One Algorithm

Looking up a contact, querying a SOC index, finding a matching log entry, and ranking a web page are different problems. **Finding**, **filtering**, **ordering**, and **ranking** may occur in one workflow but often rely on different data structures and algorithms.

## Binary Search: Repeatedly Halve A Sorted Range

Given a sorted array and compatible comparison function, binary search compares the middle element to the target and discards the impossible half. Each step reduces the remaining candidate range, giving **O(log n)** comparisons and O(1) auxiliary space for an iterative implementation.

Example sorted asset IDs: 10, 14, 21, 29, 35, 47, 53.

To find 47: inspect 29 (search right); inspect 47 (found). When no match exists, search ends with an empty interval.

~~~text
low = 0
high = length(items)          # half-open interval [low, high)
while low < high:
    mid = low + (high - low) // 2
    if items[mid] < target:
        low = mid + 1
    else:
        high = mid
# low is first index whose item is >= target, if any
~~~

This is a **lower-bound** algorithm, useful for duplicate keys and locating ranges. It works only if the array is already sorted under the same ordering. For random access storage, a phone directory *could* use a binary-search-like index, but modern contact applications and databases have different indexing structures.

**Python cross-check:** The standard-library [bisect](https://docs.python.org/3/library/bisect.html) module implements bisection over sorted sequences.

## Database Indexes: B-Trees, Hashing & Inverted Indexes

| Index Family | Useful Queries | Trade-Off |
|---|---|---|
| B-tree/B+tree family | Exact values, ordered ranges, prefix scans, sorting | O(log n)-style navigation, write and storage overhead; implementation differs |
| Hash index | Equality under compatible engine rules | Does not inherently support ordered range lookup |
| Inverted index | Which documents contain token/domain/IP/string? | Tokenization, updates and memory/disk cost |
| Bitmap index | Filtering low-cardinality fields | May be inefficient for high-update/high-cardinality workloads |
| Trie / prefix tree | Longest-prefix IP routing, prefix matching | Node overhead and normalization |
| Vector/ANN index | Approximate semantic nearest neighbors | Recall/latency trade-offs; not exact keyword matching |

A SQL **WHERE** clause does not reveal which algorithm the database engine uses. Consult **EXPLAIN**, storage engine and query plan; some queries intentionally scan tables or combine multiple indexes.

### Search Engine Workflow

1. Collect/crawl documents or events from an authorized source.
2. Parse, normalize and tokenize; preserve the original evidence.
3. Build an inverted index mapping terms to document IDs and positions.
4. Retrieve candidate documents matching a query.
5. Score/rank using terms, statistics, freshness, links, embeddings, or other features.
6. Apply privacy, authorization, and presentation policies before returning results.

A search for suspicious domains might first retrieve logs by indexed hostname token, then filter by time, host and event context. A missing or mis-tokenized field can make events invisible even when they exist in storage.

## PageRank: Links Form A Weighted Voting Network

PageRank estimates importance in a directed hyperlink graph. In the classic random-surfer model, a page gains weight from pages linking to it, adjusted by how those linking pages distribute their outgoing influence. A simplified update is:

**PR(p) = (1 - d)/N + d × sum(PR(q)/outdegree(q))** over pages q linking to p, for N pages and damping d (often illustrated as 0.85). Production implementations handle dangling pages and convergence carefully.

**Illustration:** If a respected page links to only a few places, its contribution per link is larger than if it links to thousands. **But raw in-degree or number of backlinks is not the whole algorithm**, and links are not verified statements of truth or security.

- **Google Search** has many ranking systems and factors; historical PageRank is not a complete model of current ranking.
- **Security uses:** find influential infrastructure nodes, detect suspicious link farms, prioritize investigation of related domains, or reason about software dependency importance.
- **Threats & limits:** link spam, graph manipulation, incomplete crawls, privacy considerations and source trust. A high PageRank score does not prove legitimacy.
- **Related methods:** HITS (hubs/authorities), personalized PageRank, centrality measures and community detection answer different graph questions.

References: [Original Page & Brin research](https://research.google/pubs/the-anatomy-of-a-large-scale-hypertextual-web-search-engine/), [Google's ranking systems overview](https://developers.google.com/search/docs/appearance/ranking-systems-guide).

## Sorting: Stable Order Matters For Incident Timelines

### Merge Sort

Split an input into halves, recursively sort the halves, and merge them. Standard comparison merge sort takes **O(n log n)** time in worst case, and typical array implementations require O(n) additional space. A merge sort can be stable if equal elements retain their prior relative order.

### Timsort

Timsort is an **adaptive, stable merge-based algorithm** that detects preexisting ordered runs and merges them. It is used for Python's list sorting. Do not assume every spreadsheet, inbox, e-commerce filter, database ORDER BY, or language runtime uses Timsort; implementations vary and may take advantage of indexes or specialized algorithms.

Python's list sort and sorted() are stable: when two events have equal timestamps, their preexisting order is preserved. For reproducible incident reports, define explicit secondary keys instead of relying on ingestion order.

~~~python
events = [
    {"time": "2026-11-22T10:00:00Z", "id": "evt-B"},
    {"time": "2026-11-22T09:59:59Z", "id": "evt-C"},
    {"time": "2026-11-22T10:00:00Z", "id": "evt-A"},
]
timeline = sorted(events, key=lambda e: (e["time"], e["id"]))
assert [e["id"] for e in timeline] == ["evt-C", "evt-A", "evt-B"]
~~~

Note: lexically sorting strings as UTC timestamps is safe only when their format and timezone are **normalized** consistently. Real logs require time parsing, offsets and uncertainty handling.

### Comparison Table

| Algorithm | Typical Time | Guarantee / Limitation |
|---|---|---|
| Merge sort | O(n log n) | Worst-case bound; generally O(n) extra space for arrays |
| Timsort | O(n) best for sufficiently ordered inputs; O(n log n) worst | Stable, adaptive; practical memory needs vary |
| Quicksort | O(n log n) expected with suitable pivot strategy | Naive worst-case O(n²); generally not stable |
| Heapsort | O(n log n) | Can sort in place; generally not stable |
| Counting/radix sort | Linear-ish in n and domain/digit parameters | Special key/range assumptions; not generic comparison sorting |

## Top-k, Streaming & Approximate Search

Security dashboards often need the **top 20 source IPs** or **top 10 most common failure codes**, not a total sort of millions of events. Use a frequency dictionary and a bounded heap when the task supports streaming; record whether counts are exact. Algorithms such as Count-Min Sketch estimate counts with bounded memory but introduce error. HyperLogLog estimates unique counts; its output is not an exact forensic inventory.

**Bloom filters** test probable set membership using a bit array and multiple hash-derived positions. With correct construction they give **no false negatives for items inserted**, but may give false positives. Deletion is not supported by a standard Bloom filter; a counting variant has different behavior. Corrupt state, incorrect normalization, or cross-dataset misuse breaks those assurances.

## SOC & OSINT Examples

| Question | Candidate Technique | Validation |
|---|---|---|
| Find events for one device | B-tree or inverted index | Normalize identity, timestamp, tenant & retention |
| Find matching strings across signatures | Trie/automaton matching | Inspect encoded/fragmented data and parser output |
| Find the newest 100 failed logins | Ordered index or top-k | Define timezone and tie-breaking |
| Find related domains | Graph traversal, PageRank or community detection | Avoid assuming that graph proximity means maliciousness |
| Match suspicious binaries | Cryptographic digest lookup | Trusted reference and file bytes required |
| Spot repeated query patterns | Hashing, frequency counters, sketches | Distinguish NAT/shared users from an individual |

Read [Wireshark Defensive Investigations](../Documentation/wireshark-defensive-investigations.md), [OSINT Index](../OSINT/README.md), and [Data Engineering](../Data-Engineering/README.md) for application-specific workflows.

## Sources & Further Reading

| Reference | Detail |
|---|---|
| [Python bisect](https://docs.python.org/3/library/bisect.html) | Sorted insertion/search boundaries |
| [Python Sorting HOWTO](https://docs.python.org/3/howto/sorting.html) | Stability & Timsort |
| [CPython listsort notes](https://github.com/python/cpython/blob/main/Objects/listsort.txt) | Implementation-level background |
| [Google Search: How It Works](https://developers.google.com/search/docs/fundamentals/how-search-works) | Crawling, indexing and serving |

---

[Algorithm Index](./README.md) | [Main Index](../README.md) | [Legal](../LEGAL.md)
