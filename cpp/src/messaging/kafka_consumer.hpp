#pragma once

#include <librdkafka/rdkafkacpp.h>
#include <string>
#include <memory>
#include <optional>

namespace ids {

// RAII wrapper around librdkafka's C++ consumer: joins a group, subscribes to one
// topic, auto-commits offsets so a restart resumes where it left off.
class KafkaConsumer {
public:
    KafkaConsumer(const std::string& brokers,
                  const std::string& group_id,
                  const std::string& topic);
    ~KafkaConsumer();

    // Wait up to timeout_ms for the next message. nullopt = timeout / end-of-log.
    std::optional<std::string> poll(int timeout_ms);

    // Leave the group cleanly (commits final offsets). Call before exit.
    void close();

private:
    std::unique_ptr<RdKafka::KafkaConsumer> consumer_;
    bool closed_{false};
};

}  // namespace ids
