# Pathfinding, Routing & Graph Algorithms

[Algorithm Index](./README.md) | [Foundations](./foundations-and-complexity.md) | [Offline Labs](./labs.md)

## Why Routes Are Graph Problems

Represent intersections, routers, services, or dependencies as **vertices** (nodes), and connections as **edges**. Edges may have a weight: distance, configured administrative cost, latency estimate, financial cost, or risk score. A path's total weight is often the sum of its edges. **The shortest weighted path is not necessarily the fastest real-world path.** That depends on how weights were chosen and how quickly measurements change.

A road network may be directed, have one-way restrictions, turn costs, road closures, and changing travel-time estimates. Consumer navigation platforms can use A*, bidirectional search, contraction hierarchies, traffic prediction, and proprietary optimization; do not attribute a product's entire routing engine to one textbook algorithm.

## Hands-On Graph: Choosing A Route

Consider this **invented, directed** weighted graph (all weights are nonnegative):

| Edge | Cost |
|---|---:|
| A → B | 2 |
| A → C | 5 |
| B → C | 1 |
| B → D | 4 |
| C → D | 2 |

From A to D, the path A → B → C → D has total cost **5**. A → B → D costs 6; A → C → D costs 7.

### Dijkstra's Algorithm

Dijkstra computes shortest paths from one source to all reachable vertices when edge weights are nonnegative.

1. Initialize distance(A)=0, all other distances=infinity.
2. Select the unsettled node with the smallest currently known distance.
3. **Relax** each outgoing edge: if distance(u)+weight(u,v) improves distance(v), update distance(v) and remember predecessor u.
4. Continue until the destination is finalized (single-target use) or the queue is exhausted.
5. Reconstruct the path by following predecessors backward.

Trace: initialize (A 0, B ∞, C ∞, D ∞); settle A → B 2, C 5; settle B → C 3, D 6; settle C → D 5; settle D at 5. A binary-heap/adjacency-list implementation is often described as **O((V+E) log V)**; alternative data structures or dense graphs produce different bounds.

~~~text
dijkstra(graph, source):
    distance[source] = 0
    heap.push((0, source))
    while heap not empty:
        cost, node = heap.pop_min()
        if cost != distance[node]: continue  # stale entry
        for next, weight in graph[node]:
            require weight >= 0
            if cost + weight < distance[next]:
                distance[next] = cost + weight
                predecessor[next] = node
                heap.push((distance[next], next))
    return distance, predecessor
~~~

**Watch for:** unreachable destinations, zero-weight edges, ties, stale priority-queue entries, overflow in fixed-width integers, and weight changes during computation. The example in [labs](./labs.md) checks total cost and the path against expected output.

### A* Search

A* orders candidate vertices by **f(n) = g(n) + h(n)**, where g(n) is the best known cost so far and h(n) estimates the remaining cost to the goal.

- If h(n)=0, A* becomes Dijkstra's prioritization (in the standard formulation).
- An **admissible heuristic** does not overestimate the remaining optimal cost. For common graph-search A* variants, a **consistent heuristic** also helps guarantee optimality without needing to reopen finalized nodes.
- An overestimating heuristic can produce a faster-looking but **suboptimal** result; do not promise optimality without specifying the assumptions.
- Manhattan distance is useful for a four-direction grid with uniform step costs; Euclidean distance can work for spatial models where it is a valid lower bound.
- If an edge represents live congestion or time-dependent travel, a simple static heuristic/cost model may not be sufficient.

**Cybersecurity connection:** A* is an instructive way to reason about lowest-cost paths through a service-dependency or attack graph. This is **model-based analysis**, not a vulnerability exploit; the graph needs trustworthy edges and correctly interpreted costs.

### BFS, DFS & Other Graph Tools

| Algorithm | When To Use | Important Limitation |
|---|---|---|
| Breadth-first search (BFS) | Unweighted shortest path by hop count, reachability | Ignores unequal edge costs; O(V+E) on adjacency lists |
| Depth-first search (DFS) | Dependency traversal, cycle identification, components | Its first discovered path is not generally shortest |
| Dijkstra | Single-source shortest weighted paths | Requires nonnegative edge weights |
| A* | Target-oriented shortest path with useful heuristic | Optimality needs heuristic/implementation assumptions |
| Bellman–Ford | Negative-weight edges and reachable negative-cycle detection | O(VE); not appropriate for negative-cycle shortest paths |
| Floyd–Warshall | All-pairs shortest paths on small/dense graphs | O(V³) time, O(V²) space |
| Topological sort | Order tasks in a directed acyclic graph (DAG) | Cycles mean no topological order exists |
| Minimum spanning tree (Prim/Kruskal) | Lowest-total-weight tree connecting an undirected graph | **Not** the same as shortest path between selected nodes |

## Routing Protocols Are Not Interchangeable Algorithms

### OSPF: Link-State Routing & SPF

**Open Shortest Path First (OSPF)** is an interior gateway protocol (IGP). Routers in an OSPF area exchange and maintain link-state information, build an area-scoped link-state database, and compute a shortest-path tree using a Dijkstra-based shortest-path-first procedure. They then derive forwarding entries, potentially including equal-cost multipath routes.

The edges' **OSPF interface costs** are administrative/configuration metrics, not continuous measurements of latency. A route with a lower sum of OSPF costs need not have lower observed delay. Area boundaries, summarization, reachability, equal-cost paths, and protocol rules affect the installed forwarding result.

**Practical trace:**
1. Verify neighbors and adjacency states and the network's intended area design.
2. Inspect link-state database changes, interface cost assignments, and relevant route tables.
3. Identify a topology change, calculate expected SPF impact, and compare the observed forwarding result.
4. Correlate with telemetry before describing the event as malicious.

**Security checks:** protect management access; configure appropriate OSPF authentication where supported, apply routing boundaries, and monitor unexpected adjacency/link-state changes. Even a mathematically correct SPF tree cannot compensate for forged or incorrectly trusted topology information.

**Further reading:** [OSPFv2 RFC 2328](https://www.rfc-editor.org/rfc/rfc2328.html), [OSPFv3 RFC 5340](https://www.rfc-editor.org/rfc/rfc5340.html).

### BGP: Path-Vector Policy, Not Dijkstra

**Border Gateway Protocol (BGP)** is an inter-domain **path-vector** routing protocol with policy-driven route selection, attributes, and AS-path information. A BGP best-path decision is **not** Dijkstra over the public Internet. Nor is a BGP AS-path a guaranteed measurement of geographic distance, congestion, or hop latency.

**Security implications:** route leaks and origin hijacks can redirect traffic. Protections include route filtering, max-prefix, monitoring, RPKI route origin validation (ROV) and operational coordination; ROV validates origin authorization, **not** an entire AS path or end-to-end trust.

References: [BGP-4 RFC 4271](https://www.rfc-editor.org/rfc/rfc4271.html), [RPKI Origin Validation RFC 6811](https://www.rfc-editor.org/rfc/rfc6811.html).

### Other Routing Concepts

| Concept | Where It Helps | Distinction |
|---|---|---|
| IS-IS | Link-state interior routing | Also uses SPF-family computations, separate protocol and database |
| ECMP | Load distribution across equal-cost next hops | Selection/hash policy varies; doesn't guarantee equal latency |
| Anycast | Multiple sites advertise a shared address/prefix | Routing policy affects which site receives traffic |
| SDN path computation | Controller-aware topology and constraints | Controller state can be stale or incomplete |
| Spanning Tree Protocol (STP) | Preventing Layer 2 switching loops | Not a shortest-latency routing solution |

## Defensive Lab: Understand A Path Change

Use a four-node graph with weighted edges and compare calculated shortest paths before and after increasing one edge's cost. Record expected route changes. Then compare the abstract model with observations from an **authorized** network:
- router configuration/route tables, not assumptions about the vendor's implementation;
- interface errors, traffic volume, latency, and packet loss;
- [Wireshark / packet inspection](../Documentation/wireshark-defensive-investigations.md), recognizing a span/tap cannot see every routed path;
- [segmentation/ACLs](../Documentation/network-segmentation-dmz-acl-vlan.md) and [Snort monitoring](../IncidentResponse/IDS%26IPS/snort.md).

**Safety:** Do not alter routing cost or neighbor authentication in a production network just to reproduce a lab. Use an isolated simulated topology, saved snapshots, and a rollback plan.

## References & Related Guides

| Resource | Coverage |
|---|---|
| [RFC 2328 §16](https://www.rfc-editor.org/rfc/rfc2328.html#section-16) | OSPF's SPF calculation |
| [RFC 4271](https://www.rfc-editor.org/rfc/rfc4271.html) | BGP protocol |
| [LAN TAPs, SPAN & Monitoring](../Documentation/network-taps-and-packet-visibility.md) | Observe traffic without assuming full visibility |
| [Network Security Architecture](../Documentation/network-segmentation-dmz-acl-vlan.md) | VLAN, ACL, DMZ and switching |
| [Incident Response](../IncidentResponse/README.md) | Investigate routing-related anomalies |

---

[Algorithm Index](./README.md) | [Main Index](../README.md) | [Legal](../LEGAL.md)
