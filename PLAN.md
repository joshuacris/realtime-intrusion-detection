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

- [x] **1.3** Write a flow aggregator (`flow_aggregator.cpp`) ✅ DONE
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
    - [x] **1.3f** TCP state machine + port→service map + sloss/dloss ✅ DONE
    - [x] **1.3g** Sliding-window `ct_*` family (recent-flow buffer) ✅ DONE
    - [x] **1.3h** DPI stubs (HTTP/FTP features → 0 for now) ✅ DONE

- [x] **1.4** Validate output against the UNSW training CSV ✅ DONE (rescoped)
  - Categorical vocab 100% valid; core features within 0.5–4× on like-for-like
    subset; sttl/swin/payload wire-exact vs tcpdump. Argus-specific deltas
    (swin≈255 quirk, jitter/loss formulas) documented in Progress Log.

- [x] **1.5** Benchmark throughput ✅ DONE
  - Release (-O3) build: **0.43s** for 954MB / 1.80M pkts → **4.2M pkts/sec**,
    ~2.2 GB/s, ~53k flows/sec emitted, single core (M-series). Debug→Release
    speedup 3.8×. Target >10k flows/sec exceeded ~5×.

---

## Phase 2 — Kafka Streaming Pipeline

**Goal:** Decouple packet ingestion from inference with a Kafka message bus. Enables replay, backpressure, and horizontal scaling.

### Tasks

- [x] **2.1** Spin up Kafka locally via Docker Compose ✅ DONE
  - KRaft mode (NO ZooKeeper — modern single-node). Services: kafka broker +
    kafka-ui. File: `infra/docker-compose.yml`. UI at http://localhost:8080.
  - 1 broker (fault tolerance needs multiple MACHINES — N/A on one laptop;
    scaling story is consumer-side via partitions, not brokers).

- [x] **2.2** Create two Kafka topics ✅ DONE
  - `raw-flows` + `scored-flows`, 1 partition / 1 replica each, 7-day retention.
  - Reproducible script: `infra/create-topics.sh` (explicit retention.ms).

- [x] **2.3** Add Kafka producer to the extractor ✅ DONE
  - `librdkafka` (vcpkg, v2.14.1) wrapped in `cpp/src/kafka_producer.{h,cpp}`
    (RAII; async produce + delivery-report callback + flush).
  - Sink in `main.cpp` fans out to file AND/OR Kafka; broker via `KAFKA_BROKERS`
    env var; keyed by source IP. linger.ms=10, batch.size=1MiB.
  - Verified: 1.8M pkts → 23,004 flows → **23,004 delivered / 0 failed**;
    `raw-flows:0:23004` offset confirms all landed; sample message valid.
  - TODO (2.5 tuning): enable lz4/snappy compression (lz4 already built).

- [x] **2.4** Write a Kafka consumer in C++ (`feature_consumer.cpp`) ✅ DONE
  - Consumes `raw-flows` (group `feature-consumer`, auto.offset.reset=earliest,
    auto-commit → crash-resumable). New RAII `kafka_consumer.{h,cpp}`.
  - Encodes each flow to the model's 58-feature vector (21 one-hot + 37 RAW
    numerics) via `feature_schema.h` — the single source of truth for feature
    ORDER (Phase 3 ONNX export must reuse it). NOTE: tree model uses RAW
    numerics, so NO scale/log here (that's the LR/MLP path only).
  - Publishes `{5-tuple + features[]}` to new topic `model-ready-features`.
  - Graceful shutdown on SIGINT/SIGTERM (std::atomic flag); per-message
    try/catch so one bad message can't kill the service.
  - **Verified:** drained 23,004 → 23,004 delivered/0 failed/0 errors;
    sample vector = 58 wide, each one-hot group sums to 1, decodes to
    tcp/http/FIN, numerics match source flow.

- [x] **2.5** Load test the pipeline ✅ DONE
  - Producer: pcap→Kafka 23,004 flows in 0.88s; Kafka produce marginal cost
    ~0.31s (parse baseline 0.57s) → **~74k msg/s produced**. lz4 compression on.
  - Consumer: **81,721 msg/s sustained** (115,020 msgs, single-threaded:
    consume+parse+one-hot+serialize+produce). Target >50k/s exceeded.
  - Partition parallelism: raw-flows → 3 partitions; 2 consumers in one group
    split partitions (proven via `--describe`: A→(2), B→(0,1)). Work-sharing
    needs CONTINUOUS load — a finite 23k batch drains (0.29s) before the 2nd
    consumer finishes the rebalance (instructive, expected).

---

## Phase 3 — ONNX Inference Server

**Goal:** Export the trained XGBoost model to ONNX and serve it from a C++ inference server using ONNX Runtime. Replaces ad-hoc Python `predict()` calls.

### Tasks

- [x] **3.1** Export XGBoost to ONNX (Python) ✅ DONE
  - `scripts/export_onnx.py`: trains XGBoost (paper's best params, reproducible)
    on the UNSW CSV, reindexes columns to the exact `feature_schema.h` order,
    exports via `onnxmltools.convert_xgboost(model.get_booster())`.
  - Converting the BOOSTER (not the sklearn wrapper) avoids the skl2onnx↔
    onnxmltools type clash AND yields clean outputs: `label` + `probabilities`
    [N,2] tensor (col 1 = attack prob), no ZipMap — ideal for C++.
  - **PARITY: label match 100%, max prob diff 4.77e-07** on all 55,945 test rows.
    Reproduced study: test ROC-AUC 0.9698, threshold 0.69, attack F1 0.87.
  - Artifacts (gitignored `models/`): `xgboost_intrusion.onnx` (725 KB),
    `feature_order.json` (the 58-col contract), `threshold.txt` (0.69).
  - Python env: `.venv` (venv) with numpy/pandas/sklearn/xgboost/onnx/
    onnxruntime/onnxmltools (NOT tensorflow — Phase 6 only).

- [x] **3.2** Write a C++ inference server (`inference_server.cpp`) ✅ DONE
  - Loads ONNX model via ONNX Runtime C++ API (Homebrew onnxruntime 1.27, NOT
    vcpkg — see D18). New `cpp/src/onnx_model.{h,cpp}` (Env/Session/Value).
  - Consumes `model-ready-features`, micro-batches (BATCH=64, flush on idle),
    runs one Run() per batch, applies threshold (0.69 from models/threshold.txt).
  - Publishes `{5-tuple, attack_prob, label, latency_us}` to `scored-flows`.
  - **Full pipeline verified end-to-end**: pcap → raw-flows → feature_consumer →
    model-ready-features → inference_server → scored-flows (23,004 flows).
  - **D17 skew result (preliminary, very positive):** ALL 1,591 alerts came from
    the attacker subnet 175.45.176.x (71% of its flows); ZERO false positives on
    20,762 normal-host (59.166.x) flows. Training on Argus-distribution CSV does
    NOT break serving on our features. Inference latency ~12µs/flow (batched).

- [x] **3.3** Add Redis alert deduplication ✅ DONE
  - Redis added to docker-compose (redis:7-alpine). `hiredis` (vcpkg) wrapped in
    `cpp/src/redis_dedup.{h,cpp}`.
  - Per attack, atomic `SET alert:src:dst:proto 1 NX EX 60` → first in the 60s
    window fires (alert=true), repeats suppressed (alert=false). FAIL-OPEN if
    Redis is down (emit rather than drop an attack).
  - scored-flows keeps the FULL record + an `alert` flag (audit trail intact;
    3.5 gRPC will forward only alert=true).
  - **Result:** 1,591 raw attacks → **79 fired / 1,512 suppressed (95% reduction)**;
    Redis DBSIZE = 79 (matches), keys are the (attacker,victim,proto) triples.

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

## Phase 6 — Deep-Learning Inference Track (optional, post-Phase 3)

**Goal:** A parallel neural-net subsystem that revives the MLP from the study,
fixes its biggest weakness, and serves it through a different stack — yielding a
3-way "model serving" comparison: tree (ONNX/C++) vs NN (TF-Serving) vs compiled
(XLA/MLIR).

**Why separate:** TF-Serving / JAX / XLA / MLIR are neural-net + accelerator
tools. They give XGBoost (a tree model) zero benefit, so they do NOT touch the
Phase 1–3 tree/C++ hot path. They belong on a dedicated NN track or they'd be
resume-driven dead weight. Slots in after Phase 3 (needs a baseline to compare).

### Tasks

- [ ] **6.1** Reimplement the MLP in **JAX/Flax**, train with **focal loss**
  - Directly targets the Fuzzers class (weakest in the paper: 0.47–0.63 recall)
  - Same train/test split + preprocessing as the sklearn study, for a fair compare

- [ ] **6.2** Serve the trained model via **TF-Serving** (gRPC + REST)
  - Second inference backend alongside the Phase 3 ONNX/C++ path
  - Compare: latency, throughput, accuracy (esp. Fuzzers recall) vs XGBoost/ONNX

- [ ] **6.3** *(stretch)* **XLA / MLIR** ahead-of-time compilation
  - AOT-compile the model (JAX export or IREE/MLIR) to a standalone executable
  - Benchmark vs TF-Serving and ONNX — the "ML compiler / systems" dimension
  - Note: at this scale (58 features, small MLP) latency gains are marginal;
    value is demonstrating the compilation stack, not raw speedup

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

### 2026-06-21 — Phase 3.3: Redis alert dedup
- Redis service in compose; `hiredis` (vcpkg 1.3.0). New
  `cpp/src/redis_dedup.{h,cpp}`: atomic `SET key 1 NX EX 60` =
  check-and-claim; STATUS"OK"→new alert, NIL→duplicate. Fail-open if Redis down.
- inference_server: attacks deduped on (src,dst,proto); scored-flows record
  gains `alert` bool; tracks fired/suppressed.
- **Result:** 1,591 attacks → 79 fired / 1,512 suppressed (95% noise cut);
  Redis DBSIZE=79 reconciles. Config via REDIS_HOST/REDIS_PORT env.

### 2026-06-21 — Phase 3.2: C++ ONNX inference server
- ONNX Runtime via Homebrew (prebuilt 1.27, NOT vcpkg source build — D18).
  CMake find_library + guarded target (project still builds without it).
- New `cpp/src/onnx_model.{h,cpp}`: RAII wrapper over Ort::Env/Session; predict()
  scores a [n,58] batch in one Run(), returns attack prob (probabilities[:,1]).
  Hardcoded tensor names "input"/"probabilities" (avoids version-y name API);
  zero-copy input tensor over our float buffer.
- New `cpp/src/inference_server.cpp` (3rd executable): consume
  model-ready-features → micro-batch (64, idle-flush) → score → threshold (0.69)
  → produce scored-flows. SIGINT-graceful; per-message try/catch.
- **End-to-end pipeline verified** on 23,004 flows through all 5 stages.
- **D17 skew measured (preliminary):** 1,591 alerts, 100% from attacker subnet
  175.45.176.x; 0 false positives on 20,762 normal 59.166.x flows. Skew does NOT
  break the model. Inference ~12µs/flow batched. (Apparent slowness earlier was
  consumer-group join + offset-report lag, not inference — full benchmark in 3.4.)

### 2026-06-21 — Phase 3.1: XGBoost → ONNX export
- Set up Python `.venv` (no venv existed before; Python ran in conda base —
  caused a "which python got the pip install" mix-up, the exact problem venvs
  solve). Installed the ONNX-pipeline subset (not tensorflow).
- `scripts/export_onnx.py`: train (paper best params) → reindex to
  feature_schema.h order → `onnxmltools.convert_xgboost(get_booster())`.
- Debugging trail: (1) skl2onnx↔onnxmltools `FloatTensorType` class clash →
  use onnxmltools directly; (2) booster carried pandas col names → train on
  numpy so it uses f0..f57; (3) first parity read out[0]=label not
  out[1]=probabilities (max diff 0.5) → read probabilities[:,1].
- **Result:** 100% label parity, max prob diff 4.77e-07 vs native XGBoost;
  ROC-AUC 0.9698 / thr 0.69 / attack F1 0.87 (matches the study). Decision D17
  (train on CSV, measure skew later) recorded.

### 2026-06-20 — Phase 2.5: load test + tuning (PHASE 2 COMPLETE)
- Tunings: producer lz4 compression (kafka_producer.cpp); feature_consumer
  self-timed throughput (std::chrono, first→last message).
- **Producer:** parse-only baseline 0.57s; pcap→Kafka 0.88s for 23,004 →
  Kafka marginal ~0.31s ≈ **~74k msg/s**.
- **Consumer:** drained 115,020 (5 pcap replays) at **81,721 msg/s sustained**,
  single-threaded (consume→JSON parse→one-hot encode→serialize→produce).
- **Partition parallelism:** recreated raw-flows w/ 3 partitions; flows spread
  by srcip key (3793/12967/6244). 2 consumers, one group → Kafka split
  partitions A→(2), B→(0,1) (kafka-consumer-groups --describe). Finite batch
  drained by first joiner in 0.29s before rebalance → 2nd did 0 (rebalance
  race; real work-sharing needs continuous load — the Phase 5 scenario).
- Both targets (>50k msg/s) exceeded. NOTE current Kafka state: raw-flows &
  model-ready-features recreated EMPTY with 3 partitions; regenerate anytime via
  create-topics.sh + extractor.

### 2026-06-20 — Phase 2.4: feature consumer (preprocessing service)
- New topic `model-ready-features` (added to `infra/create-topics.sh`).
- New `cpp/src/kafka_consumer.{h,cpp}`: RAII consumer wrapper (group.id,
  subscribe, poll→optional<string>, auto.offset.reset=earliest, auto-commit,
  close()).
- New `cpp/src/feature_schema.h`: canonical 58-feature contract (21 one-hot +
  37 raw numerics, alphabetical order matching preprocessing.py) +
  `to_feature_vector()`. **Single source of truth for feature order** — Phase 3
  ONNX export reuses it. Tree model → raw numerics, no scale/log.
- New `cpp/src/feature_consumer.cpp` (2nd executable): consume raw-flows →
  encode → produce model-ready-features. Signal-handled graceful shutdown,
  per-message try/catch resilience. Shares kafka_{producer,consumer}.cpp.
- **Pipeline now end-to-end:** extractor → raw-flows → feature_consumer →
  model-ready-features. Verified 23,004 flows through both hops, feature
  vectors structurally + semantically correct.

### 2026-06-20 — Phase 2.1–2.3: Kafka streaming online
- **2.1** `infra/docker-compose.yml`: single-node Kafka in **KRaft** mode (no
  ZooKeeper) + provectuslabs/kafka-ui. Dual listeners (HOST localhost:9092 for
  host apps, DOCKER kafka:29092 for in-network UI) — the classic advertised-
  listener split. Named volume persists topics. UI: http://localhost:8080.
- **2.2** Topics `raw-flows` + `scored-flows` (1 partition, 1 replica, 7-day
  retention). Created via UI; reproducible `infra/create-topics.sh` mirrors it
  with explicit `--config retention.ms=604800000`.
- **2.3** librdkafka producer. New `cpp/src/kafka_producer.{h,cpp}` = RAII
  wrapper (async `produce` w/ RK_MSG_COPY, `dr_cb` delivery reports, `flush`).
  `main.cpp` sink now fans out to file and/or Kafka; broker from `KAFKA_BROKERS`
  env; messages keyed by source IP for partition affinity. linger.ms=10,
  batch.size=1MiB (compression deferred to 2.5; lz4 already pulled in by vcpkg).
  **Verified end-to-end:** 23,004 delivered / 0 failed; topic offset
  raw-flows:0:23004; sample message is a valid 44-field flow JSON.

### 2026-06-10 — Tasks 1.3f–h, 1.4, 1.5: PHASE 1 FEATURE-COMPLETE
- **1.3f** state/service/loss: `tcp_seq` added to Packet (TCP bytes 4–7);
  retransmit detection via serial-number arithmetic (`int32_t` cast handles seq
  wraparound; data segments only). `flow_state_label()` approximates Argus
  states (RST>FIN>INT>CON>REQ priority; UDP by directionality; ICMP→ECO).
  `service_name()` maps well-known ports (both endpoints checked) to the
  model's service buckets; unknown → "-".
- **CRITICAL FIX — capture duplicates:** every packet in the UNSW pcap appears
  TWICE (tap at two points one router hop apart — proven by ttl pairs 32/31).
  Dedup drops packets identical in direction/seq/len/flags within 5ms (safe:
  TCP min RTO ~200ms). Plus **linger-after-close**: closed flows stay in the
  map (`emitted` flag) to absorb straggler duplicates; only a fresh pure SYN
  reclaims the slot. Without these: ~2× counts, bogus sloss≈spkts/2, and 17.5k
  ghost "REQ" flows. After: 40,666 → **23,004 true flows**, REQ ghosts gone.
- **1.3g** `flow_history.h`: `FlowHistory` (std::deque sliding window, last 100
  connections) computes the 8 ct_* features at emit time in main's sink;
  `ct_state_ttl` via the standard (state, TTL-range) bucket rules. Sanity:
  max ct_src_ltm=37 = attacker 175.45.176.3 (RST/http scan burst). 
- **1.3h** DPI stubs (trans_depth, response_body_len, ct_flw_http_mthd,
  is_ftp_login, ct_ftp_cmd = 0) + is_sm_ips_ports (land-attack check).
  **All 40 model features now emitted** (44 JSON fields incl. 4 debug IDs).
- **1.4 validation** (vs `data/UNSW_NB15_training-set copy.csv`, now local):
  categorical vocab 100% subset of UNSW's; like-for-like subset (tcp/http/FIN)
  medians within 0.5–4× for volume/size/timing features; sttl=32/swin=5792
  **wire-exact vs tcpdump**. Documented deltas: UNSW swin/dwin≈255 (Argus
  near-constant quirk), Argus jitter/loss formulas differ, tcprtt magnitude is
  slice-dependent (ours hand-verified), ct_* context differs on shuffled CSV.
- **1.5 benchmark** (single core, Apple Silicon, best of 3):
  Debug 1.64s vs **Release (-O3) 0.43s = 3.8×** — outputs verified identical.
  **4.2M pkts/sec, ~2.2 GB/s, 954MB→23k flows in 0.43s, ~53k flows/sec.**
  Targets: >10k flows/sec ✅ (5×), sensor-grade 100k pkts/sec ✅ (42×).
- New: `cpp/build-release/` (Release build dir), `ACHIEVEMENTS.md` (gitignored).

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
