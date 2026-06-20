#include "kafka_consumer.h"
#include <stdexcept>

KafkaConsumer::KafkaConsumer(const std::string& brokers,
                             const std::string& group_id,
                             const std::string& topic) {
    std::string errstr;
    std::unique_ptr<RdKafka::Conf> conf(
        RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL));

    if (conf->set("bootstrap.servers", brokers, errstr) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("consumer bootstrap.servers: " + errstr);

    // group.id: which consumer group we belong to. Kafka tracks this group's
    // committed offsets, so members of one group split the topic between them
    // and the group resumes from its last position after a restart.
    if (conf->set("group.id", group_id, errstr) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("consumer group.id: " + errstr);

    // For a BRAND-NEW group with no committed offset, start at the beginning of
    // the log (process all existing messages). An existing group ignores this
    // and resumes from its committed offset instead.
    if (conf->set("auto.offset.reset", "earliest", errstr) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("consumer auto.offset.reset: " + errstr);

    // (enable.auto.commit defaults to true: librdkafka periodically saves our
    //  progress so a restart resumes where we left off.)

    consumer_.reset(RdKafka::KafkaConsumer::create(conf.get(), errstr));
    if (!consumer_)
        throw std::runtime_error("consumer create: " + errstr);

    // Tell Kafka which topic(s) we want; it assigns us partitions.
    RdKafka::ErrorCode err = consumer_->subscribe({topic});
    if (err != RdKafka::ERR_NO_ERROR)
        throw std::runtime_error("consumer subscribe: " + RdKafka::err2str(err));
}

KafkaConsumer::~KafkaConsumer() {
    close();   // idempotent (guarded by closed_)
}

std::optional<std::string> KafkaConsumer::poll(int timeout_ms) {
    // consume() returns a heap Message we must delete. unique_ptr handles that
    // even on early return. The Message also carries error/status codes.
    std::unique_ptr<RdKafka::Message> msg(consumer_->consume(timeout_ms));

    switch (msg->err()) {
        case RdKafka::ERR_NO_ERROR:
            // A real message. payload() is void*; build a string from its bytes.
            return std::string(static_cast<const char*>(msg->payload()),
                               msg->len());

        case RdKafka::ERR__TIMED_OUT:       // no message arrived within timeout
        case RdKafka::ERR__PARTITION_EOF:   // caught up to the end of the log
            return std::nullopt;

        default:
            // Real error — log and treat as "nothing this round".
            fprintf(stderr, "consume error: %s\n", msg->errstr().c_str());
            return std::nullopt;
    }
}

void KafkaConsumer::close() {
    if (closed_) return;
    if (consumer_) consumer_->close();   // commits final offsets, leaves group
    closed_ = true;
}