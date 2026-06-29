#pragma once

#include <librdkafka/rdkafkacpp.h>
#include <string>
#include <memory>
#include <cstdint>

namespace ids {

// RAII wrapper around librdkafka's C++ producer: setup is hidden behind send()
// and flush(), and Kafka handles are released in the destructor.
class KafkaProducer {
public:
    KafkaProducer(const std::string& brokers, const std::string& topic);
    ~KafkaProducer();

    // Queue one message (asynchronous). `key` selects the partition.
    void send(const std::string& key, const std::string& value);

    // Block until every queued message has been delivered. Call before exit.
    void flush();

    uint64_t delivered() const { return dr_.delivered; }
    uint64_t failed()    const { return dr_.failed; }

private:
    struct DR : public RdKafka::DeliveryReportCb {
        uint64_t delivered{0};
        uint64_t failed{0};
        void dr_cb(RdKafka::Message& msg) override {
            if (msg.err() == RdKafka::ERR_NO_ERROR) delivered++;
            else                                    failed++;
        }
    };

    // Declaration order matters: members destroy in reverse, so producer_ (last)
    // is destroyed before dr_, which the producer holds a pointer to.
    DR          dr_;
    std::string topic_;
    std::unique_ptr<RdKafka::Producer> producer_;
};

}  // namespace ids
