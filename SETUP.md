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
- `docker compose ... up -d` already starts Redis alongside Kafka; dedup
  fails-open (still emits) if Redis is down.

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