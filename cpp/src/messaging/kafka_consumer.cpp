#include "messaging/kafka_consumer.hpp"
#include <stdexcept>
#include <cstdio>

namespace ids {

KafkaConsumer::KafkaConsumer(const std::string& brokers,
                             const std::string& group_id,
                             const std::string& topic) {
    std::string errstr;
    std::unique_ptr<RdKafka::Conf> conf{
        RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL)};

    if (conf->set("bootstrap.servers", brokers, errstr) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("consumer bootstrap.servers: " + errstr);

    // group.id: members of one group split the topic and resume from the group's
    // committed offset after a restart.
    if (conf->set("group.id", group_id, errstr) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("consumer group.id: " + errstr);

    // A brand-new group with no committed offset starts at the log's beginning.
    if (conf->set("auto.offset.reset", "earliest", errstr) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("consumer auto.offset.reset: " + errstr);

    consumer_.reset(RdKafka::KafkaConsumer::create(conf.get(), errstr));
    if (!consumer_)
        throw std::runtime_error("consumer create: " + errstr);

    const RdKafka::ErrorCode err{consumer_->subscribe({topic})};
    if (err != RdKafka::ERR_NO_ERROR)
        throw std::runtime_error("consumer subscribe: " + RdKafka::err2str(err));
}

KafkaConsumer::~KafkaConsumer() {
    close();
}

std::optional<std::string> KafkaConsumer::poll(int timeout_ms) {
    // consume() returns a heap Message we must delete; unique_ptr handles that.
    std::unique_ptr<RdKafka::Message> msg{consumer_->consume(timeout_ms)};

    switch (msg->err()) {
        case RdKafka::ERR_NO_ERROR:
            return std::string(static_cast<const char*>(msg->payload()),
                               msg->len());

        case RdKafka::ERR__TIMED_OUT:
        case RdKafka::ERR__PARTITION_EOF:
            return std::nullopt;

        default:
            fprintf(stderr, "consume error: %s\n", msg->errstr().c_str());
            return std::nullopt;
    }
}

void KafkaConsumer::close() {
    if (closed_) return;
    if (consumer_) consumer_->close();
    closed_ = true;
}

}  // namespace ids
