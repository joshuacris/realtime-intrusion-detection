# Architecture Decisions & Engineering Challenges

A living record of *why* this system is built the way it is — the decisions, the
alternatives considered, and the trade-offs — plus the notable problems hit and
how they were solved. Companion to [PLAN.md](PLAN.md) (the *what*) and
[SETUP.md](SETUP.md) (the *how to run*).

The through-line: **optimize each layer for its actual constraint** — C++ where
speed/control matter (the packet hot path), Kafka where decoupling/replay/scale
matter (the pipeline), JSON + Docker Compose where iteration speed matters (dev
experience) — while noting the production-grade alternative for real scale.

---

## Design Decisions

### D1 — Implementation language: C++ (hot path)
**Chosen:** C++17 for the flow extractor and streaming services.
**Alternatives:** Python, Go, Rust.
- **Python** — fine for offline ML/preprocessing, but interpreter + GIL make it
  far too slow for per-packet work. It's exactly what we're replacing.
- **Go** — great for services/concurrency and far easier than C++, but GC pauses
  and slower tight loops; a reasonable alternative with less "hot-path" signal.
- **Rust** — arguably ideal (safety + speed), but steeper curve and the author
  knows C, not Rust.
**Rationale:** maximum control over memory/layout for the hot path, leverages
existing C knowledge, and is the strongest "performance-critical systems" signal.

### D2 — Packet capture: libpcap (file + live)
**Chosen:** libpcap.
**Alternatives:** DPDK, PF_RING, AF_PACKET, XDP/eBPF.
- Kernel-bypass stacks (DPDK/PF_RING/XDP) hit 100 Gbps line rate but are
  Linux-only, complex, and overkill for a dev box.
**Rationale:** one portable API for both pcap files and live interfaces; right
abstraction level. The gap to line-rate is acknowledged, not pretended away.

### D3 — Packet parsing: hand-written byte parsing
**Chosen:** manual header parsing (offsets + `memcpy`, `ntohs/ntohl`).
**Alternatives:** PcapPlusPlus, libtins.
**Rationale:** zero dependencies, full control, and far more educational for the
layered protocol model. Trade-off: a library would avoid reinventing protocol
parsing — the choice to revisit if this were production rather than a learning
build.

### D4 — Inversion of control via `std::function` sinks
**Chosen:** `read_pcap` and the aggregator take a callback (sink) for "what to do
with each item," instead of hardcoding output.
**Rationale:** swapping file output → Kafka production was a one-line change; the
parser/aggregator never changed. Hardcoding output would have forced rewrites
each phase. (See takeaways on closures/`std::function`.)

### D5 — Flow grouping: in-memory hash map + linger lifecycle
**Chosen:** `unordered_map` keyed by a canonical 5-tuple; terminate on
FIN/RST/idle-timeout with linger-after-close.
**Alternatives:** external store (Redis/DB), LRU cache, sharded maps.
**Rationale:** for single-thread in-memory streaming, a hash map is optimal; the
FIN/RST + idle-timeout + linger lifecycle mirrors Argus/NetFlow/Zeek. Horizontal
scale is handled downstream by Kafka partitioning, not by sharding the map.

### D6 — Serialization: JSON (JSON Lines)
**Chosen:** JSON via nlohmann-json.
**Alternatives:** Protobuf, Avro (+ Schema Registry), MessagePack, FlatBuffers.
- Protobuf/Avro are 3–5× smaller, faster, and schema-enforced (prevents
  producer/consumer drift) — the production-grade Kafka choice.
**Rationale:** human-readable + debuggable + zero schema friction, ideal while
learning and inspecting messages in the Kafka UI. Conscious trade of efficiency
(~740 B/msg, parse CPU) for dev speed; a later perf pass could switch hot topics
to Avro/Protobuf.

### D7 — Message bus: Apache Kafka
**Chosen:** Kafka (single-node, KRaft).
**Alternatives:** RabbitMQ, Redis Streams, NATS/JetStream, Pulsar, direct gRPC,
cloud queues (Kinesis/SQS/Pub-Sub).
- **RabbitMQ** — rich routing but messages delete on consume (no replay), lower
  throughput; queue/RPC-oriented, not a replayable log.
- **Redis Streams** — light + fast, weaker durability/ecosystem.
- **NATS/JetStream** — simple + fast, less ubiquitous.
- **Pulsar** — strong competitor, heavier to operate.
- **Direct gRPC** — tight coupling; no buffering/backpressure/replay (defeats the
  purpose).
- **Cloud queues** — managed but vendor lock-in, not locally runnable.
**Rationale:** Kafka's durable, replayable **log** + **partition-based horizontal
scaling** are exactly the four things this pipeline needs — decoupling,
backpressure, replay, scale-out — and it's the industry standard.

### D8 — Kafka without ZooKeeper (KRaft)
**Chosen:** KRaft mode.
**Rationale:** modern Kafka's built-in metadata mode; one fewer service to run
and the current standard. ZooKeeper would add a container for no benefit here.

### D9 — Single broker (not 3+)
**Chosen:** one broker.
**Rationale:** multi-broker buys fault tolerance only across *physical machines*;
on one laptop, 3 brokers die together — zero real redundancy at triple the cost.
The scaling story here is **consumer-side** (partitions + consumer groups), which
works on a single broker. Multi-broker is a ~10-line change if a replication
demo is ever wanted.

### D10 — Local orchestration: Docker Compose
**Chosen:** Docker Compose for local dev (k8s deferred to Phase 5).
**Alternatives:** native Kafka install; Kubernetes from day one.
**Rationale:** isolated + reproducible + one-command up; native install is fiddly
Java setup, k8s-from-start is overkill until the deployment phase.

### D11 — Config via environment variables
**Chosen:** env vars (e.g. `KAFKA_BROKERS`).
**Rationale:** 12-factor; the standard way to parameterize containerized apps
without recompiling — sets up cleanly for Phase 5 (k8s).

### D12 — Pipeline shape: separate encoder service
**Chosen:** extractor emits raw flows → a *separate* consumer encodes
model-ready vectors.
**Alternative:** encode inside the extractor.
**Rationale:** decoupling lets the raw-flow stream feed multiple consumers (e.g.,
an audit logger), and lets encoding scale/restart independently — the entire
point of a message bus. Doing it all in one process would re-couple the stages.

### D13 — Feature scope: match the model's inputs, not the UNSW CSV
**Chosen:** produce the 40 features the trained model consumes; prioritize
matching *model inputs* over byte-matching the original CSV.
**Rationale:** the dataset's 49 features were built by Argus + Bro + custom
scripts; byte-exact reproduction from a pcap is a research problem. Scoping to
model inputs made Phase 1 achievable and directly unblocks inference. Divergences
from Argus (window encoding, jitter/loss formulas) are documented, not hidden.

### D14 — Tree model uses RAW features (no scaling/log at serving)
**Chosen:** for XGBoost, one-hot encode categoricals + pass raw numerics.
**Rationale:** trees split on raw thresholds, so scaling/log-transform is
pointless for them — and it means we don't need the fitted `StandardScaler` at
serving time. (The LR/MLP path *would* need it — relevant to the optional NN
track, Phase 6.)

### D15 — One source of truth for feature order (train/serve contract)
**Chosen:** `feature_schema.h` defines the canonical 58-feature order, reused by
the encoder now and the Phase 3 ONNX export.
**Rationale:** if serving order ≠ training order, every prediction is silently
wrong (training/serving skew). Centralizing the order eliminates that class of
bug.

### D16 — Model serving: export to ONNX + ONNX Runtime
**Chosen:** export the trained XGBoost to ONNX; load/run it in the C++ server via
ONNX Runtime.
**Alternatives:** native libxgboost C API; Treelite (compile trees to C); embed a
Python interpreter.
**Rationale:** ONNX decouples the *model* from the *server* — the C++ code speaks
one format, so XGBoost today and a JAX/Keras NN later (Phase 6) use the same code
path. Native/ Treelite are tree-only (no path to the NN track); embedding Python
reintroduces the interpreter we're eliminating. ONNX is the industry-standard
interchange format with a clean C++ API.

### D17 — Train on the UNSW CSV, then MEASURE the train/serve skew
**Chosen (Option A):** train XGBoost on the UNSW CSV (Argus/Bro features, all 58)
as the baseline, then empirically test distribution skew by scoring our own
extractor's flows and checking the known attacker subnet (175.45.176.0/24) is
flagged. Mitigate only if it actually fails.
**Alternatives:** (B) train only on the low-skew features we reproduce faithfully
(drop swin/dwin/tcprtt/synack/ackdat/sjit/djit/sloss/dloss → ~49 features);
(C) label our own flows via the UNSW ground-truth event file and train on our
features (eliminates skew, but a sub-project + needs a GT file we lack).
**Rationale:** the UNSW CSV is the ONLY labeled data we have — our raw pcap flows
are unlabeled — so training on our own features isn't free. Trees are partly
robust to scale shift (they split on thresholds), so skew may not bite; the
honest engineering move is to MEASURE it (we have a free coarse ground truth in
the documented attacker subnet) rather than assume it. Escalation path if the
measurement shows misclassification: B (cheap, big consistency win) then C
(principled, heavy). This is the training/serving-skew risk first flagged in the
1.4 validation, now made testable.

### D20 — Alert API via gRPC server-streaming, not REST/WebSocket/raw Kafka
**Chosen:** expose alerts through a gRPC `AlertStream` service (server-streaming
RPC defined in `alerts.proto`); clients subscribe and the server pushes alerts.
**Alternatives:** let external clients read Kafka directly; REST + polling;
WebSocket.
**Rationale:** Kafka is the internal bus — external subscribers shouldn't couple
to it (offsets, no contract, not client/firewall friendly). REST polling isn't
real-time; WebSocket lacks a typed schema/codegen. gRPC gives a typed `.proto`
contract, native server-push streaming, HTTP/2 efficiency, and cross-language
codegen (verified C++ server ↔ Python client). It's the standard for typed
streaming APIs.

### D21 — gRPC + Protobuf from Homebrew, not vcpkg
**Chosen:** `brew install grpc` (prebuilt; pulls protobuf, abseil, etc.); CMake
`find_package(gRPC CONFIG)` + protoc codegen via `add_custom_command`.
**Alternative:** vcpkg grpc/protobuf.
**Rationale:** same as D18 (ONNX Runtime) — vcpkg would build grpc + protobuf +
abseil + re2 + c-ares from source (20–40 min, fragile). Brew bottles install in
seconds. Pattern: heavyweight C++ libs with good brew bottles → brew; small/
niche libs (librdkafka, hiredis, nlohmann) → vcpkg.

### D19 — Alert dedup with Redis (shared TTL store), not an in-process map
**Chosen:** dedup alerts via Redis `SET key 1 NX EX 60` (atomic check-and-claim
with auto-expiry); key = `alert:src:dst:proto`.
**Alternatives:** an in-process `unordered_map` with manual TTL; a Bloom filter;
a relational DB.
**Rationale:** dedup state must be SHARED — when inference scales to multiple
instances (Phase 5), a per-process map would let each instance re-alert. Redis
is in-memory (µs ops, off the hot path), has native TTL (the 60s window is free,
no cleanup code), and is shared across instances. `SET NX EX` is a single atomic
round-trip that's race-safe across instances (only one wins the NX). FAIL-OPEN
on Redis failure (emit rather than drop — a duplicate alert beats a missed
attack). Result: 1,591 raw attacks → 79 unique alerts (95% reduction).

### D18 — ONNX Runtime from Homebrew, not vcpkg
**Chosen:** install ONNX Runtime via Homebrew (prebuilt bottle 1.27); find it in
CMake with `find_library` (like libpcap).
**Alternative:** vcpkg `onnxruntime` port.
**Rationale:** the vcpkg port builds ONNX Runtime FROM SOURCE — enormous, slow
(10–30+ min), and fragile on arm64. The Homebrew bottle is prebuilt and installs
in seconds. The C++ Kafka client stays on vcpkg (no good bottle); ONNX Runtime
on brew. Mixed sourcing is fine — pick the fastest reliable source per dep. The
new target is guarded in CMake so the project still builds if it's absent.

### D17 (update) — skew measured: it does NOT break the model
The empirical test from D17 ran in 3.2: scoring our OWN extractor's flows with
the CSV-trained model flagged **100% of alerts from the documented attacker
subnet (175.45.176.x)** and produced **0 false positives on 20,762 normal-host
flows**. So Option A held — the train/serve distribution skew did not degrade
class separation in practice (trees' threshold robustness + the lab data's clean
attack/normal split). No escalation to B/C needed for now; revisit if real-world
traffic proves messier.

### D22 — Metrics via prometheus-cpp + pull-based scraping
**Chosen:** instrument C++ services with `prometheus-cpp` (each runs an embedded
`/metrics` HTTP endpoint); Prometheus scrapes them on an interval.
**Alternatives:** push-based metrics (statsd / Prometheus pushgateway); a
hand-rolled metrics endpoint; logs-only.
**Rationale:** pull/scrape is the cloud-native default — services don't need to
know where Prometheus is, targets are managed centrally, and it maps directly
onto Kubernetes service discovery (Phase 5). prometheus-cpp gives counters/
gauges/histograms + the exposer out of the box. (Pushgateway is for short-lived
batch jobs — which is why our batch-style flow_extractor isn't scraped; the
long-running services are.)

### D23 — Prometheus + Grafana + kafka-exporter as compose services
**Chosen:** run the observability stack as prebuilt Docker images, configured by
mounted files (`infra/prometheus.yml`, Grafana provisioning); Kafka lag via the
`danielqsj/kafka-exporter` image rather than computing lag in our code.
**Rationale:** same containerized-infra pattern as Kafka/Redis — reproducible,
no host installs. A dedicated exporter is the standard way to get broker/
consumer-group lag into Prometheus without coupling it to our app. Services on
the host are scraped via `host.docker.internal`.

### D24 — Histogram for latency (not gauge/summary)
**Chosen:** `ids_inference_latency_seconds` as a Prometheus **histogram** with
explicit buckets (1µs–5ms).
**Rationale:** histograms store bucket counts, so Prometheus' `histogram_quantile`
computes p50/p99 across instances and time windows cheaply — without storing
every sample. (A gauge loses the distribution; a "summary" computes quantiles
client-side and can't be aggregated across instances.)

---

## Major Challenges & Resolutions

### C1 — Dual-tap capture duplication (the biggest)
Every packet appears twice (~1 ms apart), doubling counts and making `sloss`
look like ~50%. Hard because the copies differ in TTL (by 1), so naive dedup
misses them and the symptom points at the wrong layer. **Diagnosed** with
tcpdump (same SYN, TTL 32 then 31 → two tap points one hop apart). **Solved**
with a 5 ms signature dedup (direction+seq+len+flags, TTL excluded) — safe
because TCP's min RTO (~200 ms) means nothing legitimate repeats in 5 ms.

### C2 — Ghost flows
Erasing a flow on close let the *duplicate of its closing packet* spawn a new
phantom flow (17.5k bogus "REQ"). **Solved** with linger-after-close: closed
flows stay in the table to absorb stragglers; only a fresh pure SYN reclaims the
slot (the Argus/NetFlow/Zeek approach). 40,666 → 23,004 true flows.

### C3 — Feature derivability
The 49-feature dataset was tool-generated (Argus + Bro). **Resolved** by the
scoping decision D13 — target the 40 model-input features, document divergences.

### C4 — Kafka listeners (host vs in-network)
Host clients and in-container clients must reach the same broker by different
addresses, or one talks to itself. **Solved** with two advertised listeners
(`HOST://localhost:9092`, `DOCKER://kafka:29092`). Also had to set internal-topic
replication factors to 1 or single-node Kafka won't start.

### C5 — Train/serve skew risk
Feature-order mismatch silently corrupts predictions. **Solved** by D15
(single-source-of-truth schema).

### C6 — Low-level C/C++ correctness traps
Unaligned reads (→ `memcpy`), byte order (→ `ntohs/ntohl`), variable header
lengths (→ read IHL/data-offset, never hardcode), unsigned underflow (→ clamp),
sequence-number wraparound (→ signed-difference compare), integer division
truncation (→ cast to double).

### C7 — Tooling / process
The `~/.zshrc` recursion incident (→ route config/CLI changes through the user);
macOS lacking `timeout` (→ background + poll + `pkill -INT`); IDE squiggles vs
the real build (→ `compile_commands.json`); consumer-group rebalance race in load
testing (→ test parallelism under continuous load, not one-shot batches).