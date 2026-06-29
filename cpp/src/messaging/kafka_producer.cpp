#include "messaging/kafka_producer.hpp"
#include <stdexcept>

namespace ids {

KafkaProducer::KafkaProducer(const std::string& brokers, const std::string& topic)
    : topic_{topic} {
    std::string errstr;

    std::unique_ptr<RdKafka::Conf> conf{
        RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL)};

    if (conf->set("bootstrap.servers", brokers, errstr) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("kafka bootstrap.servers: " + errstr);

    // librdkafka stores this pointer, so &dr_ must outlive the producer.
    if (conf->set("dr_cb", &dr_, errstr) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("kafka dr_cb: " + errstr);

    // Batch for up to 10ms / 1MiB, then ship lz4-compressed.
    conf->set("linger.ms",        "10",      errstr);
    conf->set("batch.size",       "1048576", errstr);
    conf->set("compression.type", "lz4",     errstr);

    producer_.reset(RdKafka::Producer::create(conf.get(), errstr));
    if (!producer_)
        throw std::runtime_error("kafka producer create: " + errstr);
}

KafkaProducer::~KafkaProducer() {
    if (producer_) producer_->flush(10000);
}

void KafkaProducer::send(const std::string& key, const std::string& value) {
    while (true) {
        const RdKafka::ErrorCode err{producer_->produce(
            topic_,
            RdKafka::Topic::PARTITION_UA,    // pick partition from key
            RdKafka::Producer::RK_MSG_COPY,
            const_cast<char*>(value.data()),
            value.size(),
            key.data(), key.size(),
            0,
            nullptr)};

        if (err == RdKafka::ERR_NO_ERROR) {
            break;
        } else if (err == RdKafka::ERR__QUEUE_FULL) {
            producer_->poll(100);            // let the queue drain, then retry
            continue;
        } else {
            dr_.failed++;
            break;
        }
    }
    producer_->poll(0);                      // serve delivery reports, non-blocking
}

void KafkaProducer::flush() {
    producer_->flush(10000);
}

}  // namespace ids
