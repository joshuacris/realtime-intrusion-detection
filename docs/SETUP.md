# Setup & Operations

Build, run, and operate the real-time intrusion detection pipeline locally.
(For project goals and architecture, see [PLAN.md](PLAN.md).)

---

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| Docker Desktop | runs Kafka + Kafka UI | https://www.docker.com/products/docker-desktop |
| CMake ≥ 3.20 | C++ build system | `brew install cmake` |
| C++17 compiler | Apple Clang works out of the box | Xcode Command Line Tools |
| vcpkg | C++ dependency manager | clone + bootstrap, set `$VCPKG_ROOT` |
| libpcap | packet capture library | `brew install libpcap` |

`librdkafka` and `nlohmann-json` are fetched automatically by vcpkg — no manual install.

---

## Python environment (for model training / ONNX export)

The Python side (preprocessing, model export) runs in a project-local venv —
isolated from system/conda Python so there's no "which interpreter got the
install?" ambiguity.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install numpy pandas scikit-learn xgboost onnx onnxruntime onnxmltools skl2onnx
# (tensorflow/keras in requirements.txt are only for the optional Phase 6 NN track)
```

### (Re)generate the ONNX model

`models/` is gitignored, so regenerate the model from the CSVs anytime:

```bash
.venv/bin/python scripts/export_onnx.py
```
Writes `models/xgboost_intrusion.onnx`, `models/feature_order.json` (the 58-col
contract — must match `cpp/src/feature_schema.h`), and `models/threshold.txt`.
Validates 100% label parity vs native XGBoost before saving.

## Build the C++ flow extractor

From `cpp/`:

```bash
# Debug build (default; for development)
cmake -B build -S . \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
  -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Release build (-O3; for benchmarking / real runs) — ~3.8x faster
cmake -B build-release -S . \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
```

The first configure compiles vcpkg dependencies (librdkafka etc.) — a few minutes, once.

---

## Run the flow extractor

The extractor reads a pcap, builds flows, and emits them to a file and/or Kafka.

```bash
# To a JSON Lines file:
./build/flow_extractor ../data/1.pcap flows.jsonl

# To Kafka (topic raw-flows) — set the broker via env var:
KAFKA_BROKERS=localhost:9092 ./build/flow_extractor ../data/1.pcap

# Both at once:
KAFKA_BROKERS=localhost:9092 ./build/flow_extractor ../data/1.pcap flows.jsonl
```

- 2nd arg = optional output file. `KAFKA_BROKERS` env = optional Kafka output.
- Kafka must be running first (see below) and the topics must exist.

## Run the feature consumer

A long-running service that reads `raw-flows`, encodes each flow into the model's
58-feature input vector, and publishes to `model-ready-features`.

```bash
KAFKA_BROKERS=localhost:9092 ./cpp/build/feature_consumer
```
- Runs until you stop it with **Ctrl-C** (graceful: flushes + commits offsets).
- First run (new consumer group) processes all existing messages; later runs
  resume from the last committed offset.
- Watch its consumer group + lag in the UI under **Consumers**.

## Run the inference server

Reads `model-ready-features`, scores each flow with the ONNX model (micro-batched),
deduplicates alerts via Redis, and publishes verdicts to `scored-flows`.
Requires the ONNX model (`scripts/export_onnx.py`) and Redis (in the compose stack).

```bash
KAFKA_BROKERS=localhost:9092 ./cpp/build/inference_server
# optional env: MODEL_PATH, THRESHOLD, REDIS_HOST, REDIS_PORT
```
- Prints scored / attacks / fired / suppressed on Ctrl-C.
- Output records carry `attack_prob`, `label`, `alert` (true only for novel
  attacks after dedup), and `latency_us`.
- Structured per-flow JSON logs go to `LOG_FILE` (else stderr), separate from the
  stdout summary:
  ```bash
  LOG_FILE=/tmp/inference.jsonl KAFKA_BROKERS=localhost:9092 ./cpp/build/inference_server
  grep '"prediction":1' /tmp/inference.jsonl | head        # just the attacks
  ```
- `docker compose ... up -d` already starts Redis alongside Kafka; dedup
  fails-open (still emits) if Redis is down.

## Run the gRPC alert stream

Requires `brew install grpc` (C++) and `pip install grpcio grpcio-tools` (client).

```bash
# 1. Start the gateway: consumes scored-flows (alert:true) -> gRPC stream
KAFKA_BROKERS=localhost:9092 ./cpp/build/alert_gateway        # serves :50051

# 2. Generate the Python client stubs once:
.venv/bin/python -m grpc_tools.protoc -I cpp/proto \
  --python_out=scripts/gen --grpc_python_out=scripts/gen cpp/proto/alerts.proto

# 3. Run the client (optional min-probability filter):
.venv/bin/python scripts/alert_client.py 0.0
```
Alerts produced by the inference server stream live to every connected client.
(Note: backgrounded stdout block-buffers — use `python -u` to see client output
live when piping.)

---

## Kafka (Docker Compose)

Single-node Kafka in **KRaft** mode (no ZooKeeper) + a web UI. Config:
[infra/docker-compose.yml](infra/docker-compose.yml).

### Start

```bash
docker compose -f infra/docker-compose.yml up -d
```
- `-d` = detached (background). First run downloads the images (~1 min).
- **Web UI:** http://localhost:8080
- **Broker (from host apps):** `localhost:9092`

### Create the topics (once per fresh volume)

```bash
./infra/create-topics.sh
```
Creates `raw-flows` and `scored-flows` (1 partition, 1 replica, 7-day retention).
Safe to re-run. You can also create them by hand in the UI (Topics → Add a Topic).

### Verify

```bash
# message count (high-watermark offset) of a topic
docker exec kafka /opt/kafka/bin/kafka-get-offsets.sh \
  --bootstrap-server localhost:9092 --topic raw-flows

# peek one message
docker exec kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic raw-flows --from-beginning --max-messages 1
```
Or just browse in the UI: **Topics → raw-flows → Messages**.

---

## Load testing (reproduce the benchmarks)

All Kafka admin tools run inside the container via `docker exec kafka <tool>`.
macOS has no `timeout`, so long-running services are backgrounded (`&`) and
stopped with `pkill -INT feature_consumer` (graceful). Use the **Release** build
(`build-release`) for benchmarks.

```bash
KT=/opt/kafka/bin/kafka-topics.sh
GO=/opt/kafka/bin/kafka-get-offsets.sh
CG=/opt/kafka/bin/kafka-consumer-groups.sh
B=localhost:9092

# --- Producer throughput ---
docker exec kafka $KT --bootstrap-server $B --delete --topic raw-flows
docker exec kafka $KT --bootstrap-server $B --create --topic raw-flows --partitions 1 --replication-factor 1
/usr/bin/time -p env KAFKA_BROKERS=$B ./cpp/build-release/flow_extractor data/1.pcap   # pcap->kafka
/usr/bin/time -p ./cpp/build-release/flow_extractor data/1.pcap                        # parse-only baseline
# producer rate ≈ 23004 / (kafka_real − parse_real)

# --- Consumer throughput (inflate, rewind, run) ---
for i in 1 2 3 4 5; do KAFKA_BROKERS=$B ./cpp/build-release/flow_extractor data/1.pcap >/dev/null 2>&1; done
docker exec kafka $CG --bootstrap-server $B --group feature-consumer --reset-offsets --to-earliest --topic raw-flows --execute
KAFKA_BROKERS=$B ./cpp/build-release/feature_consumer    # prints "sustained: N msg/s" on Ctrl-C

# --- Partition parallelism ---
docker exec kafka $CG --bootstrap-server $B --delete --group feature-consumer
docker exec kafka $KT --bootstrap-server $B --delete --topic raw-flows
docker exec kafka $KT --bootstrap-server $B --create --topic raw-flows --partitions 3 --replication-factor 1
KAFKA_BROKERS=$B ./cpp/build-release/flow_extractor data/1.pcap
KAFKA_BROKERS=$B ./cpp/build-release/feature_consumer &   # consumer A
KAFKA_BROKERS=$B ./cpp/build-release/feature_consumer &   # consumer B
docker exec kafka $CG --bootstrap-server $B --group feature-consumer --describe --members --verbose
pkill -INT feature_consumer
```

Reference results (single core, Apple Silicon, Release): producer ~74k msg/s,
consumer ~82k msg/s sustained. See ACHIEVEMENTS.md (gitignored) for context.

## Reproduce the full pipeline & Phase 3 results

End-to-end data flow:
```
pcap → flow_extractor → raw-flows → feature_consumer → model-ready-features
     → inference_server (ONNX + Redis dedup) → scored-flows → alert_gateway (gRPC) → clients
```

### Prerequisites (once)
```bash
docker compose -f infra/docker-compose.yml up -d   # Kafka + Redis + UI
bash infra/create-topics.sh                          # raw-flows, model-ready-features, scored-flows
.venv/bin/python scripts/export_onnx.py              # writes models/xgboost_intrusion.onnx
# build (Debug for dev, build-release for benchmarks) — see "Build" above
```
The flow_extractor exits on its own after the pcap; the three services
(feature_consumer, inference_server, alert_gateway) run until **Ctrl-C**. Run
each in its own terminal and Ctrl-C once it has drained (watch its progress
counter, or the topic offsets / Kafka UI).

### Run it (one terminal per service)
```bash
B=localhost:9092
# T1 — produce flows (exits when done): ~23,004 flows
KAFKA_BROKERS=$B ./cpp/build/flow_extractor data/1.pcap
# T2 — encode features (Ctrl-C when drained)
KAFKA_BROKERS=$B ./cpp/build/feature_consumer
# T3 — score + dedup (Ctrl-C when drained)
KAFKA_BROKERS=$B ./cpp/build/inference_server
# T4 — gRPC alert gateway (stays up)
KAFKA_BROKERS=$B ./cpp/build/alert_gateway
# T5 — alert client (stays up; prints alerts live)
.venv/bin/python -u scripts/alert_client.py 0.0
```
Tip: to re-run a stage from scratch, rewind its consumer group
(`kafka-consumer-groups.sh --reset-offsets --to-earliest --group <g> --topic <t> --execute`)
and `docker exec redis redis-cli FLUSHALL` so dedup fires again.

### Reproduce the specific results

**3.1 — ONNX parity** (`.venv/bin/python scripts/export_onnx.py`):
```
native test ROC-AUC: 0.9698
best threshold: 0.69
PARITY  label match: 100.0000%   max prob diff: 4.77e-07
```

**3.2 — skew validation** (dump scored-flows, check attacker vs normal):
```bash
docker exec kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 \
  --topic scored-flows --from-beginning --max-messages 23004 --timeout-ms 15000 > /tmp/scored.jsonl
.venv/bin/python - <<'PY'
import json; rows=[json.loads(l) for l in open('/tmp/scored.jsonl')]
atk=[r for r in rows if r['srcip'].startswith('175.45.176.') or r['dstip'].startswith('175.45.176.')]
nrm=[r for r in rows if r['srcip'].startswith('59.166.') or r['dstip'].startswith('59.166.')]
print('attacker flagged:', sum(r['label'] for r in atk), '/', len(atk))
print('normal   flagged:', sum(r['label'] for r in nrm), '/', len(nrm))
PY
# expected: ALL alerts on attacker subnet; 0 on normal hosts
```

**3.3 — Redis dedup** (inference_server shutdown line):
```
shutting down: scored 23004, attacks 1591 (fired 79, suppressed 1512 by dedup), errors 0
# docker exec redis redis-cli DBSIZE  -> 79 (matches fired)
```

**3.4 — inference benchmark** (Release build):
```bash
docker exec kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 \
  --topic model-ready-features --from-beginning --max-messages 2000 --timeout-ms 15000 > /tmp/mrf.jsonl
./cpp/build-release/bench_inference models/xgboost_intrusion.onnx 64 5000 /tmp/mrf.jsonl
# expected: throughput ~78k flows/s; per-flow p99 ~30us (<1ms target)
```

**3.5 — gRPC alert stream** (gateway + client up, then produce/inject alerts):
```bash
# inject a test alert into scored-flows; the connected client prints it:
echo '{"srcip":"175.45.176.2","sport":13284,"dstip":"149.171.126.16","dsport":80,"proto":"tcp","attack_prob":0.99,"label":1,"alert":true,"latency_us":12}' \
  | docker exec -i kafka /opt/kafka/bin/kafka-console-producer.sh --bootstrap-server localhost:9092 --topic scored-flows
# client shows: ALERT 175.45.176.2:13284 -> 149.171.126.16:80 tcp prob=0.990 ...
# (alert:false messages are filtered out)
```

## Observability (metrics + dashboards)

The stack: each C++ service exposes Prometheus metrics at `/metrics`; Prometheus
scrapes them; Grafana visualizes. **Metrics are pull-based — they only exist
while the service is running.** Prometheus, Grafana, and kafka-exporter come up
with `docker compose up -d`.

| What | URL |
|------|-----|
| Grafana dashboard "IDS Pipeline" | http://localhost:3000/d/ids-pipeline (anon admin) |
| Prometheus UI (Graph / Status→Targets) | http://localhost:9090 |
| inference_server metrics | http://localhost:9103/metrics (while running) |
| feature_consumer metrics | http://localhost:9102/metrics (while running) |
| kafka-exporter (lag) | http://localhost:9308/metrics |

> ⚠️ Paste-safety: interactive zsh does NOT treat `#` as a comment — an inline
> `# ...` becomes arguments and errors. Either omit comments when pasting, or run
> `setopt interactive_comments` once. Also: run START and STOP blocks
> **separately** — pasting them together runs the stop immediately and kills the
> services before any traffic flows.

### See metrics for a single run
Start a service (it serves `/metrics` while running):
```bash
KAFKA_BROKERS=localhost:9092 ./cpp/build/inference_server
```
In another terminal, view and query the metrics:
```bash
curl -s localhost:9103/metrics | grep ids_
curl -s 'localhost:9090/api/v1/query?query=ids_scored_total'
```
Stop it with Ctrl-C, or: `pkill -INT inference_server`

### See LIVE graphs (continuous traffic)
`rate()` / percentiles need ongoing traffic. **START** (services + a replay loop,
all backgrounded):
```bash
B=localhost:9092
docker exec redis redis-cli FLUSHALL
KAFKA_BROKERS=$B ./cpp/build/feature_consumer &
KAFKA_BROKERS=$B ./cpp/build/inference_server &
for i in $(seq 1 30); do KAFKA_BROKERS=$B ./cpp/build/flow_extractor data/1.pcap >/dev/null 2>&1; done &
```
Open http://localhost:3000/d/ids-pipeline and watch the panels move. **STOP**
later (run as a separate step, one pattern per call):
```bash
pkill -INT flow_extractor
pkill -INT inference_server
pkill -INT feature_consumer
```
Reference live values seen: ~7k flows/s, p99 latency ~34µs, alert fire/suppress
oscillating with the 60s dedup window (flush Redis first to see `fired/s` spike).

### Useful PromQL
```promql
rate(ids_scored_total[1m])                                                     # flows/sec
histogram_quantile(0.99, sum(rate(ids_inference_latency_seconds_bucket[1m])) by (le))  # p99 latency
rate(ids_alerts_fired_total[1m])                                               # alert rate
sum(kafka_consumergroup_lag) by (consumergroup)                                # consumer lag
```

### If Grafana fails to start after changing a datasource
Changing a provisioned datasource's `uid` conflicts with Grafana's stored copy.
Recreate the container (it has no volume, so this resets its DB cleanly):
```bash
docker compose -f infra/docker-compose.yml up -d --force-recreate grafana
```

## Kubernetes (Phase 5)

### Build the container image
One consolidated multi-stage image holds all core binaries (built for Linux) +
the ONNX model. Requires Docker; the first build is slow (vcpkg from source).
```bash
docker build -f Dockerfile -t ids:dev .          # ~15-20 min first time
docker images ids:dev                             # ~223 MB
```
Sanity-check a binary in the container (Kafka will refuse against compose-Kafka
due to its localhost advertised listener — that's expected; it works in-cluster):
```bash
docker run --rm -e REDIS_HOST=host.docker.internal ids:dev /usr/local/bin/inference_server
# look for: "inference_server: ... (model /models/xgboost_intrusion.onnx, threshold 0.69, dedup on)"
docker run --rm --entrypoint ldd ids:dev /usr/local/bin/inference_server | grep "not found" || echo "libs ok"
```

### Deploy to a local cluster (kind + Helm + KEDA)
```bash
kind create cluster --name ids
kind load docker-image ids:dev --name ids                 # load local image into the cluster
helm repo add kedacore https://kedacore.github.io/charts && helm repo update
helm install keda kedacore/keda -n keda --create-namespace --wait
helm install ids infra/helm/ids                            # kafka, redis, services, ScaledObject
kubectl get pods                                           # all should reach Running
```
Observe / autoscaling:
```bash
kubectl get scaledobject,hpa                               # KEDA + HPA
kubectl get deploy inference-server -w                     # watch replica count
KPOD=$(kubectl get pod -l app=kafka -o jsonpath='{.items[0].metadata.name}')
kubectl exec $KPOD -- /opt/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server localhost:9092 --describe --group inference-server   # ground-truth lag
```
Note: KEDA verifiably scales inference 0→1 on lag; a clean 1→10 ramp is an open
follow-up (consumer too fast + a KEDA scaler lag-report quirk in kind). Teardown:
```bash
helm uninstall ids; helm uninstall keda -n keda; kind delete cluster --name ids
```

## Shutting down & resuming (e.g. rebooting your Mac)

**Your data is safe across reboots** — topics and messages live in the Docker
named volume `infra_kafka-data`, which persists on disk. Only the running
containers stop.

### Before shutdown (optional — Kafka also recovers fine from a hard stop)

```bash
docker compose -f infra/docker-compose.yml stop    # keeps containers; resume with `start`
# or
docker compose -f infra/docker-compose.yml down    # removes containers, KEEPS volume; resume with `up -d`
```

### When you come back

1. Launch Docker Desktop.
2. `docker compose -f infra/docker-compose.yml start`  (if you used `stop`)
   or `docker compose -f infra/docker-compose.yml up -d`  (if you used `down`)
3. Verify `raw-flows` still shows its messages (UI or `kafka-get-offsets.sh`).

### ⚠️ Destructive — wipes all topics/messages

```bash
docker compose -f infra/docker-compose.yml down -v   # the -v deletes the volume
```
Only use for a clean slate. To recover afterward, just rerun:
```bash
./infra/create-topics.sh
KAFKA_BROKERS=localhost:9092 ./cpp/build/flow_extractor data/1.pcap
```
Everything is reproducible from the pcap — no data is truly lost.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `kafka delivered: 0  failed: N` | Broker not running or wrong `KAFKA_BROKERS`. Check `docker compose ps`. |
| Kafka UI can't reach cluster | Broker still warming up (~15s) or advertised-listener misconfig. |
| IntelliSense "cannot open librdkafka/..." | Cosmetic. Point VS Code at `cpp/build/compile_commands.json` (set `compileCommands` in `.vscode/c_cpp_properties.json`). The CMake build itself is unaffected. |
| Topics missing after restart | You ran `down -v` (wiped volume). Rerun `./infra/create-topics.sh`. |
| Port 9092/8080 already in use | Another process/old container. `docker compose down` then `up -d`. |