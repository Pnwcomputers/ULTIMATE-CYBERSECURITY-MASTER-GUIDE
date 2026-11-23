# Detection, Streaming, Recommendation & Decision Algorithms

[Algorithm Index](./README.md) | [Foundations](./foundations-and-complexity.md) | [Offline Labs](./labs.md)

## From Raw Events To A Defensible Decision

A security system rarely uses just one algorithm. Consider a network IDS and SIEM pipeline:

~~~text
SPAN/TAP or endpoint sensor
    → parse/normalize → match signatures/features
    → window and correlate → assign confidence/severity
    → enrich with asset context → alert → human validation
~~~

**Where an algorithm runs matters:** encrypted payloads may not be visible, dropped packets may bias counts, application-layer parsing may fail, sensors may observe different VLANs or channels, and missing endpoint data cannot be reconstructed from a single capture. Review [LAN TAPs & SPAN](../Documentation/network-taps-and-packet-visibility.md), [Wireshark](../Documentation/wireshark-defensive-investigations.md), and [Unified Network Visibility](../IncidentResponse/IDS%26IPS/unified-network-visibility-architecture.md).

## 1. String & Multi-Pattern Matching

| Algorithm | Idea | Security Application | Caution |
|---|---|---|---|
| Naive substring search | Compare each possible text position | Toy rule matcher | O(nm) for text length n and pattern length m in simple formulation |
| Knuth–Morris–Pratt (KMP) | Precompute prefix/failure transitions | Single-pattern searches | O(n+m), but not always the fastest practical choice |
| Boyer–Moore family | Skip ahead using mismatch information | Fast substring matching | Preprocessing and alphabet/content dependent |
| Aho–Corasick | Trie plus failure links matches many patterns in one pass | Malware signatures, URL strings, IDS content matching | Requires consistent normalization; performance & memory depend on patterns and outputs |
| Regex / finite automaton | Match a language/pattern | SIEM and IDS rules | Backtracking implementations can be vulnerable to catastrophic runtime; RE2-style restricted engines differ |
| Cryptographic digest match | Compute file hash and lookup known value | Evidence deduplication, known-file detection | Exact hashes cannot detect modified variants |

**Aho–Corasick outline:** construct a trie of all patterns; add failure links pointing to the longest matching suffix state; process each input byte/character through transitions; report completed matches. With suitable representation, the scan is linear in the input length plus matches after preprocessing. It does **not** understand protocol semantics, IP fragments, encoding or TLS decryption unless the surrounding engine handles them.

**Real tool note:** Suricata exposes configurable multi-pattern matchers including Aho–Corasick variants and Hyperscan where available. Do not assume a specific Snort 3 or Suricata deployment uses one matcher without checking its actual build and configuration. Reference: [Suricata Performance Tuning](https://docs.suricata.io/en/latest/performance/tuning-considerations.html).

### Signature Matching vs Behavioral Detection

A rule such as "alert when a test string appears" is deterministic but may miss new variants; a threshold such as "more than 20 failures from one synthetic actor within 5 minutes" is behavioral but may fire for legitimate outages. Both need scope, event definitions, baselines, and tuning. Never equate a single match with a confirmed compromise.

## 2. Windows, Counters & Time-Series Anomalies

**Sliding windows** count events in the most recent duration. A fixed-time bucket (for example 12:00–12:05) may behave differently from a truly sliding five-minute interval (12:01–12:06). Define whether boundaries are inclusive/exclusive, whether timestamps are event time or ingest time, and how late events are handled.

**Exponential weighted moving average (EWMA):**

~~~text
baseline_t = alpha * value_t + (1-alpha) * baseline_(t-1)
~~~

With 0 < alpha <= 1, larger alpha responds quickly but is noisy; smaller alpha smooths transients but may hide sudden changes. An EWMA baseline by itself is **not** a threat classifier. Detect deviations against a documented threshold, expected variability, and maintenance/change calendars.

Other useful tools:

| Technique | Use | Failure Mode |
|---|---|---|
| Median / median absolute deviation | Robust outlier screening | Fails with seasonal/unrepresentative samples |
| z-score | Basic standardized deviation | Assumes meaningful mean/variance; heavy tails break expectations |
| CUSUM | Accumulate evidence of persistent shifts | Drift/reset/threshold choice important |
| Change-point detection | Detect distribution changes | Distinguish telemetry changes from new attacks |
| Correlation graph | Connect alerts by entity/time | Shared NAT, DHCP, clock skew and identity changes confuse attribution |
| Count-Min Sketch | Approximate high-volume counts | One-sided count error under its assumptions; not exact evidence |
| HyperLogLog | Estimate distinct entities | Approximation, so retain source events for investigations |

**Example:** A 5-minute increase in deauthentication management frames can be a useful wireless anomaly, but RF loss, channel hopping and legitimate station transitions may change observed counts. Validate with [Kismet](../Wardriving/kismet.md), [nzyme](../IncidentResponse/IDS%26IPS/nzyme_wids.md), and [802.11 Detection](../Documentation/wifi-deauthentication-detection.md); corroboration matters more than a dramatic threshold.

## 3. Rate Limiting & Queueing

A **token bucket** stores up to a configured number of tokens and refills them at a specified rate. A request spends a token (or a cost-weighted number); requests without available tokens are limited or queued according to policy.

- **Burst capacity:** Allow short surges without changing the average sustained allowance.
- **Refill rate:** Governs longer-run permitted throughput.
- **Key selection:** Per IP, user, device, endpoint or tenant; NAT and shared accounts complicate identity.
- **Distributed deployments:** Correct cross-node accounting, clock use and eventual consistency matter.
- **Fail behavior:** Decide what happens during backing-store outages; fail-closed may harm availability while fail-open may allow abuse.

Contrast this with a **leaky bucket** that smooths departures, a **fixed window** with boundary bursts, and a **sliding-window log/counter** with memory/accuracy trade-offs. Rate limiting can reduce automated abuse but is not a full defense against distributed denial of service.

### Threat-Hunting Scenario

An authentication service shows a spike in failures. A responsible workflow is: verify timestamp normalization; group by user and source IP; account for shared gateways; inspect outcome ratios; compare expected service activity; review allow/deny controls; rate-limit only under approved change control; measure collateral impact; and retain original logs.

## 4. Recommendations & Personalized Feeds

**Collaborative filtering** predicts preferences from relationships among users/items:
- **User-based** methods find people with similar historical behavior.
- **Item-based** methods compare items commonly consumed together.
- **Matrix factorization** learns low-dimensional latent factors from a sparse interaction matrix.

**Content-based ranking** uses item/user features; **hybrid systems** combine methods, business rules, freshness, exploration, and diversity. There is no reason to assert that a streaming platform always uses the same algorithm or that a click is proof of approval.

| Challenge | Why It Matters |
|---|---|
| Cold start | Little interaction history for a new user or item |
| Sparsity | Most users interact with only a small fraction of items |
| Feedback loops | Early ranking changes what gets watched and labeled |
| Privacy | Behavioral data can reveal sensitive preferences |
| Poisoning & manipulation | Bots/fake interactions distort popularity and similarity |
| Fairness | Exposure may overfavor already popular items |
| Evaluation | Offline relevance scores do not directly prove real-world value or safety |

**Cybersecurity crossover:** similar techniques can rank alerts by correlated attributes or recommend relevant triage playbooks. These recommendations are decision aids, **not evidence** that one source is malicious or one action is safe.

## 5. Classification, Scores & False Positives

Threat-detection models commonly produce scores; a **threshold** converts a score into an action. Before relying on it, define:

| Metric | What It Answers |
|---|---|
| Precision = TP/(TP+FP) | Of all flagged observations, how many were truly positive? |
| Recall = TP/(TP+FN) | Of all actual positives, how many did the detector identify? |
| False-positive rate = FP/(FP+TN) | Of actual negatives, how many were incorrectly flagged? |
| Latency | How quickly is an event detected, queued, enriched and investigated? |
| Coverage | Which assets, interfaces, packet classes and event types are observable? |
| Drift | Did the traffic distribution or labeling process change? |

**Base-rate example:** If only 1 in 1,000 events is malicious, even a detector with 99% recall and 1% false-positive rate produces far more false positives than true positives. Evaluate confusion matrices using the real class prevalence, not just accuracy.

**Safe automation:** begin with alerts only; tune and review with synthetic test events. If considering automated firewall actions, add human approval, time limits, exceptions, audit logs, monitoring and rollback. Never block hosts based solely on an unvalidated experimental anomaly score.

## 6. Threat Modeling The Detection Algorithm Itself

1. **Inputs:** Who controls them? Could untrusted headers or URLs trigger expensive parsing?
2. **Normalization:** Are casing, Unicode, encodings, clock offsets and fragmented packets normalized consistently?
3. **Algorithms:** Is worst-case runtime bounded? Could pattern order or input size cause backtracking?
4. **Data quality:** What events are missing due to sampling, dropped packets, sensors, retention or encryption?
5. **Decisions:** Are confidence and severity distinct? Can responders override or appeal?
6. **Privacy & access:** Are tenant separation, minimization and evidence retention enforced?
7. **Evaluation:** Are detection rules tested with benign and malicious **synthetic** cases? Do you measure false positives?
8. **Operation:** Are drift, stale reference sets, deployment changes and version rollbacks monitored?

## Practice Labs & Investigations

| Lab | Demonstrated Concept | Validation Question |
|---|---|---|
| Synthetic event counter | Sliding window | Do events exactly at a boundary enter the intended window? |
| Synthetic baseline | EWMA | How does alpha change drift sensitivity? |
| Token bucket simulator | Burst allowance | How do burst and refill settings differ? |
| Known-good signature text | Exact substring matching | How do encodings and tokenization change results? |
| Recommendation toy matrix | Item similarity | Which users are underrepresented and which interactions are spoofable? |
| Correlated IDS alerts | Entity/temporal join | Are two alerts actually about the same host across DHCP changes? |

The [offline lab guide](./labs.md) provides runnable examples for some of these concepts. For production-grade IDS operation, use the existing [Wazuh Guide](../IncidentResponse/SIEM/wazuh.md), [Snort 3 Guide](../IncidentResponse/IDS%26IPS/snort.md), [nzyme Guide](../IncidentResponse/IDS%26IPS/nzyme_wids.md), and [NetAlertX](../Documentation/netalertx-device-discovery-monitoring.md).

## Sources & See Also

| Reference | What To Verify |
|---|---|
| [Suricata Documentation](https://docs.suricata.io/en/latest/) | Multi-pattern matching & parser pipeline |
| [Python re Documentation](https://docs.python.org/3/library/re.html) | Regex execution specifics; untrusted patterns need review |
| [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) | Governance, measurement and model risk |
| [Wazuh](../IncidentResponse/SIEM/README.md) | Correlated event monitoring |
| [AI Evaluation Guide](../AI/ai-evaluation-and-regression-testing.md) | Robust validation and regression tests |

---

[Algorithm Index](./README.md) | [Main Index](../README.md) | [Legal](../LEGAL.md)
