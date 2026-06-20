#pragma once

#include <librdkafka/rdkafkacpp.h>
#include <string>
#include <memory>
#include <optional>   // std::optional

// ===================================================================
// KafkaConsumer — RAII wrapper around librdkafka's C++ consumer.
//
// Joins a consumer GROUP and subscribes to one topic. poll() returns the next
// message payload (or nothing on timeout). Offsets auto-commit, so a restarted
// consumer resumes where it left off.
// ===================================================================
class KafkaConsumer {
public:
    KafkaConsumer(const std::string& brokers,
                  const std::string& group_id,
                  const std::string& topic);
    ~KafkaConsumer();

    // Wait up to timeout_ms for the next message. Returns its payload as a
    // string, or std::nullopt on timeout / end-of-partition (i.e. "nothing
    // right now"). std::optional = "a value, or nothing" (like Python's None).
    std::optional<std::string> poll(int timeout_ms);

    // Leave the group cleanly (commits final offsets). Call before exit.
    void close();

private:
    std::unique_ptr<RdKafka::KafkaConsumer> consumer_;
    bool closed_ = false;
};