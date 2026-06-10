# Project Upgrade Plan: Real-Time Distributed Intrusion Detection

Current state: offline ML benchmarking (sklearn notebooks, UNSW-NB15 CSV data).
Target state: production-grade, real-time intrusion detection system with C++ hot paths, Kafka-backed streaming, ONNX inference, and Kubernetes deployment.

---

## Target Architecture

```
Live traffic (pcap / UNSW-NB15 replay)
        ↓
[Phase 1] C++ packet parser (libpcap → flow features)
        ↓
[Phase 2] Kafka topic: raw-flows
        ↓
[Phase 2] C++ feature extraction worker
        ↓
[Phase 2] Kafka topic: model-ready-features
        ↓
[Phase 3] ONNX Runtime inference server (C++, XGBoost → ONNX)
        ↓
[Phase 3] Redis (alert dedup + result caching)
        ↓
[Phase 4] gRPC alert stream
        ↓
[Phase 5] Kubernetes (HPA on inference pods) + Prometheus/Grafana
```

---

## Phase 1 — C++ Feature Extraction (Foundation)

**Goal:** Replace offline CSV preprocessing with a live C++ pipeline that parses packets and computes UNSW-NB15-style flow features in real time.

**Why start here:** This is the most authentic C++ use case, most technically differentiating, and everything downstream depends on it.

### Tasks

- [x] **1.1** Set up a `cpp/` directory with a CMake build system ✅ DONE
  - Dependencies: `libpcap`, `librdkafka` (for later), `nlohmann/json`
  - Use `vcpkg` or `conan` for dependency management

- [x] **1.2** Write a pcap reader (`pcap_reader.cpp`) ✅ DONE
  - Reads UNSW-NB15 raw pcap files (we have `data/1.pcap`, 954MB, Linux SLL link type)
  - Emits packet structs: `{src_ip, dst_ip, src_port, dst_port, proto, timestamp, payload_len, flags, ttl, tcp_window}`

- [ ] **1.3** Write a flow aggregator (`flow_aggregator.cpp`) — IN PROGRESS
  - Groups packets into bidirectional flows (5-tuple key: src/dst IP, src/dst port, proto)
  - **Scope (revised):** compute the **40 raw features the trained model uses** (not the original 49 — labels & original-only fields excluded). See Progress Log + feature tiers below.
    - Duration, byte counts (`sbytes`, `dbytes`), packet counts (`spkts`, `dpkts`)
    - Service detection (HTTP, FTP, DNS, etc.)
    - TCP flags (SYN, FIN, RST counts)
    - Load, loss, jitter features
  - Exports completed flows as JSON
  - **Sub-steps:**
    - [x] **1.3a** Extend `Packet` with `ttl` + `tcp_window` ✅ DONE
    - [x] **1.3b** Define `FlowKey` (canonical 5-tuple) + `FlowState` + hash functor (`flow.h`) ✅ DONE
    - [x] **1.3c** Aggregator loop: group packets → flows (counts/bytes/timestamps) ✅ DONE
    - [x] **1.3d** Flow termination (FIN/RST/timeout) + emit completed flows as JSON ✅ DONE
    - [x] **1.3e** Derived features: loads, means, rate, jitter, interpkt, handshake RTT ✅ DONE
    - [ ] **1.3f** TCP state machine + port→service map
    - [ ] **1.3g** Sliding-window `ct_*` family (recent-flow buffer)
    - [ ] **1.3h** DPI stubs (HTTP/FTP features → 0 for now)

- [ ] **1.4** Validate output against `data/processed/training_full.csv`
  - Run the C++ extractor on the raw UNSW-NB15 CSVs and diff features against the preprocessed output
  - Target: feature values within 1% of the Python preprocessing pipeline

- [ ] **1.5** Benchmark throughput
  - Measure flows/sec on a single core
  - Target: >10k flows/sec (real network sensors run at 100k+; show you know the gap)

---

## Phase 2 — Kafka Streaming Pipeline

**Goal:** Decouple packet ingestion from inference with a Kafka message bus. Enables replay, backpressure, and horizontal scaling.

### Tasks

- [ ] **2.1** Spin up Kafka locally via Docker Compose
  - Services: Zookeeper, Kafka broker, Kafka UI (for visibility)
  - File: `infra/docker-compose.yml`

- [ ] **2.2** Create two Kafka topics
  - `raw-flows`: output from C++ flow aggregator (JSON/protobuf per flow)
  - `scored-flows`: output from inference server (flow + prediction + confidence)

- [ ] **2.3** Add Kafka producer to `flow_aggregator.cpp`
  - Use `librdkafka` C++ client
  - Publish completed flows to `raw-flows` topic
  - Tune: batch size, linger time, compression (snappy) for throughput

- [ ] **2.4** Write a Kafka consumer in C++ (`feature_consumer.cpp`)
  - Consumes from `raw-flows`
  - Applies the same log-transform and encoding as `src/preprocessing/preprocessing.py`
  - Publishes model-ready feature vectors to an inference request queue

- [ ] **2.5** Load test the pipeline
  - Replay the 163K UNSW-NB15 records as fast as possible
  - Measure end-to-end latency from packet ingestion to Kafka publish
  - Target: saturate a single Kafka partition at >50k msg/sec

---

## Phase 3 — ONNX Inference Server

**Goal:** Export the trained XGBoost model to ONNX and serve it from a C++ inference server using ONNX Runtime. Replaces ad-hoc Python `predict()` calls.

### Tasks

- [ ] **3.1** Export XGBoost to ONNX (Python)
  - Use `sklearn-onnx` / `onnxmltools` to convert the trained model from `notebooks/xgboost.ipynb`
  - Validate: run ONNX predictions against original sklearn predictions on the test set
  - Target: identical predictions (ONNX vs. sklearn) on all 55,945 test records
  - Save to `models/xgboost_intrusion.onnx`

- [ ] **3.2** Write a C++ inference server (`inference_server.cpp`)
  - Loads the ONNX model at startup via ONNX Runtime C++ API
  - Consumes feature vectors from the Kafka consumer (Phase 2)
  - Runs batched inference (batch size = 32–128 for throughput)
  - Publishes `{flow_id, label, confidence, latency_us}` to `scored-flows` Kafka topic

- [ ] **3.3** Add Redis alert deduplication
  - For each predicted attack, check Redis for a recent alert on the same src_ip/dst_ip/proto key
  - TTL: 60 seconds (suppress duplicate alerts within a time window)
  - Use `hiredis` C++ client

- [ ] **3.4** Benchmark inference throughput and latency
  - Target: p99 inference latency <1ms per flow at batch size 64
  - Target: >50k scored flows/sec on a single inference server instance

- [ ] **3.5** Expose a gRPC alert stream
  - Define a `.proto` schema: `AlertStream` service, `FlowAlert` message
  - Stream predicted attacks to subscribers in real time
  - Python test client that prints alerts to stdout

---

## Phase 4 — Observability

**Goal:** Instrument the pipeline so you can measure and demonstrate performance — the thing that turns architecture into quantifiable resume bullets.

### Tasks

- [ ] **4.1** Instrument the C++ pipeline with Prometheus metrics
  - Use `prometheus-cpp` library
  - Expose: `flows_ingested_total`, `inference_latency_seconds` (histogram), `alerts_fired_total`, `kafka_lag_messages`

- [ ] **4.2** Add a Grafana dashboard
  - Panels: flows/sec, p50/p99 inference latency, alert rate, Kafka consumer lag
  - File: `infra/grafana/dashboard.json`

- [ ] **4.3** Add structured logging
  - JSON logs with: `flow_id`, `timestamp`, `prediction`, `confidence`, `latency_us`
  - Pipe to a log file or stdout for easy grepping

---

## Phase 5 — Kubernetes Deployment

**Goal:** Deploy the full pipeline on Kubernetes with autoscaling inference pods. This is the infra story that rounds out the resume.

### Tasks

- [ ] **5.1** Containerize all components
  - `Dockerfile.flow-extractor` — C++ flow aggregator binary
  - `Dockerfile.inference-server` — C++ ONNX inference server
  - `Dockerfile.feature-consumer` — C++ Kafka consumer/preprocessor
  - Use multi-stage builds: build in `gcc` image, copy binary to `debian:slim`

- [ ] **5.2** Write Helm charts
  - Chart per component: `flow-extractor`, `feature-consumer`, `inference-server`
  - Values: replica count, Kafka broker URL, Redis URL, ONNX model path

- [ ] **5.3** Configure Horizontal Pod Autoscaler (HPA) on inference pods
  - Scale on Kafka consumer lag (via KEDA — Kubernetes Event-Driven Autoscaler)
  - Min replicas: 1, Max replicas: 10
  - Target: lag < 1000 messages per partition

- [ ] **5.4** Deploy locally with `minikube` or `kind`
  - Full stack: Kafka, Zookeeper, Redis, flow-extractor, feature-consumer, inference-server
  - Load test: replay 163K records and watch HPA scale inference pods

- [ ] **5.5** Set up GitHub Actions CI/CD
  - On push to `main`: build Docker images, run ONNX validation test, push to GHCR
  - On tag: deploy to the k8s cluster

---

## Suggested Build Order

| Week | Focus |
|------|-------|
| 1–2 | Phase 1: C++ flow extractor + CMake setup |
| 3   | Phase 2: Kafka Docker Compose + C++ producer |
| 4   | Phase 3: ONNX export + C++ inference server |
| 5   | Phase 3 cont.: Redis dedup + gRPC stream |
| 6   | Phase 4: Prometheus + Grafana |
| 7–8 | Phase 5: Dockerfiles + Helm + k8s + HPA |

---

## Key Libraries & Tools

| Component | Library |
|-----------|---------|
| Packet parsing | `libpcap` |
| Kafka client (C++) | `librdkafka` |
| ONNX inference | `onnxruntime` C++ API |
| Redis client (C++) | `hiredis` |
| gRPC | `grpc` + `protobuf` |
| Prometheus metrics | `prometheus-cpp` |
| C++ build | `CMake` + `vcpkg` |
| Container orchestration | `Kubernetes` + `Helm` + `KEDA` |
| CI/CD | GitHub Actions |
| Local k8s | `minikube` or `kind` |

---

## Progress Log

Durable record of what's been built (in case chat logs are lost). Newest first.

### 2026-06-09 — Task 1.3e: derived features
- Added 12 derived features to the JSON output (now **26 fields/flow**):
  - Ratios (from counters): `smean`, `dmean`, `sload`/`dload` (bits/s), `rate` (pkts/s).
  - Timing (new per-direction state in [flow.h](cpp/src/flow.h) FlowState):
    `sinpkt`/`dinpkt` (mean gap, ms), `sjit`/`djit` (jitter = mean |Δgap|, ms).
  - Handshake (SYN / SYN-ACK / ACK timestamps): `synack`, `ackdat`, `tcprtt` (s).
- [flow_aggregator.cpp](cpp/src/flow_aggregator.cpp) maintains inter-arrival,
  jitter, and handshake-timestamp accumulators in `add_packet`; computation done
  at emit time in [flow_json.h](cpp/src/flow_json.h). All divisions guarded.
- **Validated** the math against a real HTTP flow (smean/sload/rate/tcprtt all
  matched hand calc). 17,662/40,666 flows have a full handshake; median
  tcprtt 0.72 ms. Run unchanged: 1.8M pkts → 40,666 flows in ~1.9s.

### 2026-06-09 — Task 1.3d: flow termination + JSON export
- `FlowAggregator` now takes a `FlowSink` callback + idle timeout (default 60s).
  Flows complete on: TCP **RST** (either side), TCP **FIN on both sides**, or
  **idle timeout** (periodic sweep, every 500k pkts), and `flush()` emits all
  remaining flows at EOF. Emitted via sink, then erased (bounds memory for the
  live stream).
- New [cpp/src/flow_json.h](cpp/src/flow_json.h): `flow_to_json()` →
  nlohmann::json with UNSW field names (srcip/sport/dstip/dsport/proto/dur/
  spkts/dpkts/sbytes/dbytes/sttl/dttl/swin/dwin). [main.cpp](cpp/src/main.cpp)
  writes **JSON Lines** to `flows.jsonl` (or argv[2]).
- TCP flag constants added to [flow.h](cpp/src/flow.h). `*.jsonl` gitignored.
- Added `CMAKE_EXPORT_COMPILE_COMMANDS ON` → build/compile_commands.json (fixes
  VS Code IntelliSense header resolution; user points c_cpp_properties at it).
- **Result on `data/1.pcap`:** 1,800,166 pkts → **40,666 flows** in ~1.9s, all
  valid JSON. (Count rose from 22,969 in 1.3c because terminating flows now
  splits reused 5-tuples into separate connections — correct NIDS behavior.)
  Breakdown: tcp 35,334 · udp 5,330 · icmp 2; 226 no-reply (scan-like) flows.

### 2026-06-08 — Task 1.3c: aggregator loop
- New [cpp/src/flow_aggregator.h](cpp/src/flow_aggregator.h) +
  [.cpp](cpp/src/flow_aggregator.cpp): `FlowAggregator` **class** (private
  `unordered_map<FlowKey,FlowState,FlowKeyHash>`, exposed via `add_packet()`,
  `flow_count()`, `flows()`). `add_packet` get-or-creates the FlowState via
  `flows_[key]` (reference), sets the source/initiator on the first packet, then
  splits each packet into s*/d* counters by direction.
- Added `ip_total_len` to `Packet` (IP datagram bytes) → used for sbytes/dbytes.
  (Byte semantics = IP-layer bytes; may revisit vs Argus for exactness, fine for
  model-input matching.)
- [main.cpp](cpp/src/main.cpp) now streams packets into the aggregator and prints
  a sample of flows (structured-binding loop).
- **Result on `data/1.pcap`:** 1,800,166 packets → **22,969 flows** in ~1.1s.
  Bidirectional grouping verified (one flow holds both spkts & dpkts);
  attack flows visible (e.g. 175.45.176.3 → spkts=2/dpkts=0, no reply = scan).

### 2026-06-08 — Task 1.3a + 1.3b: flow types
- **1.3a:** Added `ttl` (IP header byte 8) and `tcp_window` (TCP bytes 14–15) to
  `Packet` in [cpp/src/packet.h](cpp/src/packet.h); populated in
  [cpp/src/pcap_reader.cpp](cpp/src/pcap_reader.cpp). These feed sttl/dttl/swin/dwin.
- **1.3b:** New [cpp/src/flow.h](cpp/src/flow.h) defining:
  - `FlowKey` — canonical (direction-independent) 5-tuple + `operator==`;
    `make_flow_key()` orders endpoints (smaller first) so A→B and B→A collapse
    to one key. Verified: both directions hash to the same bucket (map size 1).
  - `FlowKeyHash` — hash functor using the hash_combine (golden-ratio) recipe.
  - `FlowState` — running per-flow accumulators (init_ip/port, first/last ts,
    s/d pkts, s/d bytes, sttl/dttl, swin/dwin, s/d flag OR) + `is_from_source()`.
- Builds clean. flow.h validated via throwaway include + `clang++`.

### 2026-06-07 — Task 1.2: pcap reader
- Built [cpp/src/pcap_reader.cpp](cpp/src/pcap_reader.cpp) (+`.h`) and
  [cpp/src/packet.h](cpp/src/packet.h): opens a pcap with libpcap, detects link
  type (our capture is **Linux SLL / 16-byte header**, not Ethernet), peels
  SLL → IPv4 → TCP/UDP/ICMP by hand, emits `Packet` structs via a
  `std::function` callback.
- Driver [cpp/src/main.cpp](cpp/src/main.cpp) takes a pcap path, counts packets.
- **Result on `data/1.pcap`:** parsed **1,800,166 packets in ~1.6s** (~1.1M
  pkts/sec, 1 core). TCP 1,772,972 · UDP 27,125 · ICMP 69.
- **Validated against `tcpdump`:** skipped protocols (OSPF, ARP) and ICMP length
  (336B) match exactly. Traffic is real UNSW-NB15 (attacker 175.45.176.0 →
  victim 149.171.126.x).

### 2026-06-07 — Task 1.1: build system
- Created `cpp/` with [CMakeLists.txt](cpp/CMakeLists.txt) (CMake + vcpkg
  toolchain) and [vcpkg.json](cpp/vcpkg.json) (deps: `nlohmann-json`; libpcap via
  Homebrew). Target `flow_extractor`. C++17, `-Wall -Wextra`.
- vcpkg installed at `~/Desktop/vcpkg`. Build: `cmake -B build -S .
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake` then
  `cmake --build build`.
- Added [.gitignore](.gitignore): ignores `cpp/build/`, data/`*.pcap`, ML
  artifacts, and the two personal notes files (CPP_TAKEAWAYS.md,
  NETWORKING_TAKEAWAYS.md).

### Feature scope decision (2026-06-07)
- Flow extractor targets the **40 raw features the trained model consumes**
  (→ 58 cols after OHE/scaling in Phase 2), NOT the original UNSW-NB15 49.
  Priority = match model inputs, not byte-exact UNSW CSV.
- Excluded (not derivable from pcap): `attack_cat`, `Label` (Label = model's
  output), and original-only fields already dropped by `preprocessing.py`
  (srcip/sport/dstip/dsport, Stime/Ltime, stcpb, dtcpb, id).
- Feature tiers — Header(6) & Aggregate(10): exact · Timing(7): computable ·
  TCP-semantics(4: state/service/sloss/dloss): approx · HTTP-FTP DPI(5): stub
  to 0 first · Sliding-window ct_*(8): recent-flow buffer.
