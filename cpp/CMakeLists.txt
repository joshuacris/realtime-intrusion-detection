cmake_minimum_required(VERSION 3.20)
project(intrusion_detection CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # build/compile_commands.json for IDEs

add_compile_options(-Wall -Wextra)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")   # Homebrew on Apple Silicon

# --- Dependencies ---
find_library(PCAP_LIBRARY NAMES pcap REQUIRED
  HINTS /opt/homebrew/lib /opt/homebrew/Cellar/libpcap/1.10.6/lib)
find_path(PCAP_INCLUDE_DIR NAMES pcap.h REQUIRED
  HINTS /opt/homebrew/include /opt/homebrew/Cellar/libpcap/1.10.6/include)

find_package(nlohmann_json REQUIRED)
find_package(RdKafka CONFIG REQUIRED)      # RdKafka::rdkafka++ (C++ wrapper)
find_package(hiredis CONFIG REQUIRED)
find_package(prometheus-cpp CONFIG REQUIRED)

# Shared include root: headers are referenced as "<component>/<name>.hpp".
add_library(ids_common INTERFACE)
target_include_directories(ids_common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# --- flow_extractor: pcap -> flows -> Kafka(raw-flows) ---
add_executable(flow_extractor
  apps/flow_extractor.cpp
  src/net/pcap_reader.cpp
  src/flow/aggregator.cpp
  src/messaging/kafka_producer.cpp
)
target_include_directories(flow_extractor PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(flow_extractor PRIVATE
  ids_common
  ${PCAP_LIBRARY}
  nlohmann_json::nlohmann_json
  RdKafka::rdkafka++
)

# --- feature_consumer: raw-flows -> encode -> model-ready-features ---
add_executable(feature_consumer
  apps/feature_consumer.cpp
  src/messaging/kafka_consumer.cpp
  src/messaging/kafka_producer.cpp
)
target_link_libraries(feature_consumer PRIVATE
  ids_common
  nlohmann_json::nlohmann_json
  RdKafka::rdkafka++
  prometheus-cpp::pull
)

# --- inference_server + bench_inference (ONNX Runtime from Homebrew) ---
# Guarded so the rest of the project still builds without onnxruntime installed.
find_path(ONNXRUNTIME_INCLUDE_DIR onnxruntime_cxx_api.h
  HINTS /opt/homebrew/include/onnxruntime /opt/homebrew/include)
find_library(ONNXRUNTIME_LIB onnxruntime HINTS /opt/homebrew/lib)

if(ONNXRUNTIME_INCLUDE_DIR AND ONNXRUNTIME_LIB)
  add_executable(inference_server
    apps/inference_server.cpp
    src/model/onnx_model.cpp
    src/messaging/kafka_consumer.cpp
    src/messaging/kafka_producer.cpp
    src/dedup/redis_dedup.cpp
  )
  target_include_directories(inference_server PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_link_libraries(inference_server PRIVATE
    ids_common
    nlohmann_json::nlohmann_json
    RdKafka::rdkafka++
    hiredis::hiredis
    prometheus-cpp::pull
    ${ONNXRUNTIME_LIB}
  )

  add_executable(bench_inference
    apps/bench_inference.cpp
    src/model/onnx_model.cpp
  )
  target_include_directories(bench_inference PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_link_libraries(bench_inference PRIVATE
    ids_common
    nlohmann_json::nlohmann_json
    ${ONNXRUNTIME_LIB}
  )
else()
  message(STATUS "onnxruntime not found — skipping inference_server "
                 "(run: brew install onnxruntime)")
endif()

# --- alert_gateway (gRPC + protobuf from Homebrew) ---
# Guarded so the project still builds without grpc installed.
find_package(Protobuf CONFIG QUIET)
find_package(gRPC CONFIG QUIET)
find_package(Threads REQUIRED)

if(gRPC_FOUND AND Protobuf_FOUND)
  # Generate C++ from alerts.proto at build time.
  set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/proto/alerts.proto)
  set(PROTO_GEN  ${CMAKE_CURRENT_BINARY_DIR}/generated)
  file(MAKE_DIRECTORY ${PROTO_GEN})
  set(PB_SRC   ${PROTO_GEN}/alerts.pb.cc)
  set(GRPC_SRC ${PROTO_GEN}/alerts.grpc.pb.cc)

  add_custom_command(
    OUTPUT ${PB_SRC} ${PROTO_GEN}/alerts.pb.h
           ${GRPC_SRC} ${PROTO_GEN}/alerts.grpc.pb.h
    COMMAND protobuf::protoc
    ARGS --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/proto
         --cpp_out=${PROTO_GEN}
         --grpc_out=${PROTO_GEN}
         --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
         ${PROTO_FILE}
    DEPENDS ${PROTO_FILE}
    COMMENT "protoc: generating alerts.pb / alerts.grpc.pb")

  add_executable(alert_gateway
    apps/alert_gateway.cpp
    src/messaging/kafka_consumer.cpp
    ${PB_SRC} ${GRPC_SRC}
  )
  target_include_directories(alert_gateway PRIVATE ${PROTO_GEN})
  target_link_libraries(alert_gateway PRIVATE
    ids_common
    nlohmann_json::nlohmann_json
    RdKafka::rdkafka++
    gRPC::grpc++
    protobuf::libprotobuf
    Threads::Threads
  )
else()
  message(STATUS "gRPC/Protobuf not found — skipping alert_gateway "
                 "(run: brew install grpc)")
endif()
