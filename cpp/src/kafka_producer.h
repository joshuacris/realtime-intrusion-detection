#pragma once

#include <librdkafka/rdkafkacpp.h>   // the C++ Kafka client (namespace RdKafka)
#include <string>
#include <memory>
#include <cstdint>

// ===================================================================
// KafkaProducer — a thin RAII wrapper around librdkafka's C++ producer.
//
// Hides all the Kafka setup behind two operations: send() and flush().
// "RAII" = the object owns its resources and cleans them up in its
// destructor, so callers never manage Kafka handles by hand.
// ===================================================================
class KafkaProducer {
public:
    // brokers: e.g. "localhost:9092"   topic: e.g. "raw-flows"
    KafkaProducer(const std::string& brokers, const std::string& topic);
    ~KafkaProducer();

    // Queue one message (asynchronous, non-blocking in the common case).
    // `key` decides the partition (same key -> same partition -> ordered).
    void send(const std::string& key, const std::string& value);

    // Block until every queued message has been delivered. Call before exit.
    void flush();

    uint64_t delivered() const { return dr_.delivered; }
    uint64_t failed()    const { return dr_.failed; }

private:
    // Delivery-report callback. librdkafka invokes dr_cb() once per message
    // after the broker acknowledges it (or it errors). We just tally counts.
    struct DR : public RdKafka::DeliveryReportCb {
        uint64_t delivered = 0;
        uint64_t failed    = 0;
        void dr_cb(RdKafka::Message& msg) override {
            if (msg.err() == RdKafka::ERR_NO_ERROR) delivered++;
            else                                    failed++;
        }
    };

    // DECLARATION ORDER MATTERS: members are destroyed in REVERSE order, so
    // producer_ (declared last) is destroyed FIRST — before dr_, which the
    // producer holds a pointer to. dr_ must outlive the producer.
    DR          dr_;
    std::string topic_;
    std::unique_ptr<RdKafka::Producer> producer_;
};