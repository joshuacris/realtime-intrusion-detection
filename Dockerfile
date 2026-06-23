# Consolidated image: builds all CORE pipeline binaries once and ships them in
# one runtime image. Each k8s Deployment picks its binary via `command:`.
# (alert_gateway/gRPC is intentionally NOT built here — see DECISIONS D27 — to
# avoid a heavy gRPC-from-source build in Linux; it stays a local service.)
#
# Both stages use debian:bookworm so glibc matches between build and runtime.

# ---------- Stage 1: build ----------
FROM debian:bookworm AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build git curl zip unzip tar pkg-config \
      ca-certificates python3 autoconf automake libtool libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

# vcpkg (cached layer) for librdkafka / hiredis / nlohmann-json / prometheus-cpp.
RUN git clone --depth 1 https://github.com/microsoft/vcpkg /opt/vcpkg \
 && /opt/vcpkg/bootstrap-vcpkg.sh -disableMetrics
ENV VCPKG_ROOT=/opt/vcpkg

# ONNX Runtime: Microsoft's prebuilt Linux arm64 tarball (no source build).
ARG ORT_VERSION=1.20.1
RUN curl -fsSL \
      https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-aarch64-${ORT_VERSION}.tgz \
      -o /tmp/ort.tgz \
 && mkdir -p /opt/onnxruntime \
 && tar -xzf /tmp/ort.tgz -C /opt/onnxruntime --strip-components=1 \
 && rm /tmp/ort.tgz

WORKDIR /app/cpp
# Manifest first (caches the slow vcpkg dependency build across source edits).
COPY cpp/vcpkg.json ./
COPY cpp/CMakeLists.txt ./
COPY cpp/src ./src
COPY cpp/proto ./proto

# Point CMake at the ONNX Runtime tarball (pre-sets the cache vars our
# find_path/find_library look for). gRPC is absent -> alert_gateway is skipped.
RUN cmake -B build -S . \
      -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
      -DCMAKE_BUILD_TYPE=Release \
      -DONNXRUNTIME_INCLUDE_DIR=/opt/onnxruntime/include \
      -DONNXRUNTIME_LIB=/opt/onnxruntime/lib/libonnxruntime.so \
 && cmake --build build --target flow_extractor feature_consumer inference_server

# ---------- Stage 2: runtime ----------
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl3 zlib1g libpcap0.8 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Binaries
COPY --from=build /app/cpp/build/flow_extractor    /usr/local/bin/
COPY --from=build /app/cpp/build/feature_consumer  /usr/local/bin/
COPY --from=build /app/cpp/build/inference_server  /usr/local/bin/
# ONNX Runtime shared lib (dynamic) + register it on the loader path
COPY --from=build /opt/onnxruntime/lib/libonnxruntime.so* /usr/local/lib/
RUN ldconfig
# Bake in the trained model so the inference image is self-contained
COPY models/xgboost_intrusion.onnx /models/xgboost_intrusion.onnx
COPY models/threshold.txt          /models/threshold.txt

ENV KAFKA_BROKERS=kafka:9092 \
    REDIS_HOST=redis \
    MODEL_PATH=/models/xgboost_intrusion.onnx
WORKDIR /
# Default to the inference server; k8s overrides `command:` per Deployment.
CMD ["/usr/local/bin/inference_server"]