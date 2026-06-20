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