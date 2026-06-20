#include "kafka_producer.h"
#include <stdexcept>   // std::runtime_error

KafkaProducer::KafkaProducer(const std::string& brokers, const std::string& topic)
    : topic_(topic) {
    std::string errstr;   // librdkafka writes human-readable errors here

    // Conf = a configuration object. CONF_GLOBAL settings apply to the whole
    // producer. We wrap it in unique_ptr so it's freed automatically; the
    // producer copies what it needs out of it at create() time.
    std::unique_ptr<RdKafka::Conf> conf(
        RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL));

    // Where the broker is. set() returns CONF_OK on success.
    if (conf->set("bootstrap.servers", brokers, errstr) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("kafka bootstrap.servers: " + errstr);

    // Register our delivery-report callback object. librdkafka stores this
    // POINTER, so &dr_ must outlive the producer (it does — see header note).
    if (conf->set("dr_cb", &dr_, errstr) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("kafka dr_cb: " + errstr);

    // Throughput tuning: gather messages for up to 10ms into batches up to 1MB,
    // then ship them lz4-compressed (smaller on wire+disk for a little CPU).
    conf->set("linger.ms",       "10",      errstr);
    conf->set("batch.size",      "1048576", errstr);   // 1 MiB
    conf->set("compression.type","lz4",     errstr);   // codec bundled by vcpkg

    // Create the producer. Returns nullptr on failure (note: this does NOT
    // connect yet — connection is lazy; a down broker shows up as failed
    // deliveries later, not an error here).
    producer_.reset(RdKafka::Producer::create(conf.get(), errstr));
    if (!producer_)
        throw std::runtime_error("kafka producer create: " + errstr);
}

KafkaProducer::~KafkaProducer() {
    // Safety net: flush anything still queued so we don't drop the tail even
    // if the caller forgot to flush().
    if (producer_) producer_->flush(10000 /* ms */);
}

void KafkaProducer::send(const std::string& key, const std::string& value) {
    // produce() queues the message; it does NOT block on the network.
    while (true) {
        RdKafka::ErrorCode err = producer_->produce(
            topic_,
            RdKafka::Topic::PARTITION_UA,        // UA = unassigned: pick partition from key
            RdKafka::Producer::RK_MSG_COPY,      // copy payload; we may reuse our buffer now
            const_cast<char*>(value.data()),     // produce() wants void*; COPY won't modify it
            value.size(),
            key.data(), key.size(),              // key drives partition selection
            0,                                   // timestamp 0 = "now"
            nullptr);                            // per-message opaque (unused)

        if (err == RdKafka::ERR_NO_ERROR) {
            break;
        } else if (err == RdKafka::ERR__QUEUE_FULL) {
            // Local send queue is full (we're producing faster than the network
            // drains). Give librdkafka 100ms to make progress, then retry.
            producer_->poll(100);
            continue;
        } else {
            // Other (rare) synchronous error: count it and move on.
            dr_.failed++;
            break;
        }
    }

    // Serve delivery-report callbacks for already-sent messages, non-blocking.
    producer_->poll(0);
}

void KafkaProducer::flush() {
    // Block up to 10s until all queued messages are delivered (or fail).
    producer_->flush(10000);
}