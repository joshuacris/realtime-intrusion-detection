#!/usr/bin/env bash
# infra/create-topics.sh — create the Kafka topics this pipeline uses.
# Safe to re-run: --if-not-exists makes existing topics a no-op.
#
# Usage:  ./infra/create-topics.sh   (Kafka must be up via docker compose)

set -euo pipefail   # -e: stop on first error  -u: error on unset var
                    # -o pipefail: a pipeline fails if ANY stage fails

BROKER="localhost:9092"                 # the broker's HOST listener (from compose)
KT="/opt/kafka/bin/kafka-topics.sh"     # Kafka's topic admin tool, inside the container
RETENTION_MS=604800000                  # 7 days (7*24*60*60*1000) — set explicitly,
                                        # don't rely on the broker default

# raw-flows: the flow extractor publishes finished flows here.
docker exec kafka "$KT" --bootstrap-server "$BROKER" --create --if-not-exists \
  --topic raw-flows --partitions 1 --replication-factor 1 \
  --config retention.ms="$RETENTION_MS"

# scored-flows: the inference service will publish {flow + prediction} here (Phase 3).
docker exec kafka "$KT" --bootstrap-server "$BROKER" --create --if-not-exists \
  --topic scored-flows --partitions 1 --replication-factor 1 \
  --config retention.ms="$RETENTION_MS"

echo "--- topics now present: ---"
docker exec kafka "$KT" --bootstrap-server "$BROKER" --list
