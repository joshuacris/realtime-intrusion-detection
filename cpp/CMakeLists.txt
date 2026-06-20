# Minimum CMake version required to parse this file
cmake_minimum_required(VERSION 3.20)

# Names this project. Sets the CXX (C++) language.
# Like: "this workspace is called intrusion_detection and it uses C++"
project(intrusion_detection CXX)

# Use the C++17 standard and fail loudly if the compiler doesn't support it.
# Equivalent to passing -std=c++17 to clang++ manually.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Emit build/compile_commands.json — a machine-readable index of how each file
# is compiled (incl. all -I include paths). VS Code's C++ extension reads it to
# resolve headers like <nlohmann/json.hpp>, fixing IntelliSense squiggles.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Enable useful warnings — same as -Wall -Wextra in a raw compile command
add_compile_options(-Wall -Wextra)

# Build type default: if you don't specify, make it a debug build
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Tell CMake where Homebrew installs libraries on Apple Silicon (M1/M2/M3).
# Without this, CMake won't find libpcap even though brew installed it.
list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")

# --- Dependencies ---

# libpcap: the packet capture library (already installed via brew)
# find_library() searches for a compiled library file (.dylib / .a)
# find_path()    searches for the header files (.h)
find_library(PCAP_LIBRARY NAMES pcap REQUIRED
  HINTS /opt/homebrew/lib /opt/homebrew/Cellar/libpcap/1.10.6/lib)
find_path(PCAP_INCLUDE_DIR NAMES pcap.h REQUIRED
  HINTS /opt/homebrew/include /opt/homebrew/Cellar/libpcap/1.10.6/include)

# nlohmann-json: header-only JSON library, installed via vcpkg
# find_package() looks for a CMake config file that vcpkg generates
find_package(nlohmann_json REQUIRED)

# librdkafka: the Kafka client. vcpkg exports CMake targets:
#   RdKafka::rdkafka    (C library)
#   RdKafka::rdkafka++  (C++ wrapper — what we #include and use)
find_package(RdKafka CONFIG REQUIRED)

# --- Build targets ---

# Create an executable called "flow_extractor" from our source files.
# Every .cpp (translation unit) gets compiled separately, then linked.
# Headers (.h) are NOT listed here — they're pulled in via #include.
add_executable(flow_extractor
  src/main.cpp
  src/pcap_reader.cpp
  src/flow_aggregator.cpp
  src/kafka_producer.cpp
)

# Tell the compiler where to find header files for this target.
# Equivalent to: -I/opt/homebrew/Cellar/libpcap/.../include
target_include_directories(flow_extractor PRIVATE ${PCAP_INCLUDE_DIR})

# Link against the libraries we found above.
# Equivalent to: -lpcap  and  linking the nlohmann_json headers
target_link_libraries(flow_extractor PRIVATE
  ${PCAP_LIBRARY}
  nlohmann_json::nlohmann_json
  RdKafka::rdkafka++
)

# Second executable: the feature consumer (reads raw-flows, encodes, publishes
# model-ready-features). Shares the Kafka wrappers; needs no libpcap.
add_executable(feature_consumer
  src/feature_consumer.cpp
  src/kafka_consumer.cpp
  src/kafka_producer.cpp
)
target_link_libraries(feature_consumer PRIVATE
  nlohmann_json::nlohmann_json
  RdKafka::rdkafka++
)
