#include "dedup/redis_dedup.hpp"
#include <cstdio>

namespace ids {

RedisDedup::RedisDedup(const std::string& host, int port, int ttl_seconds)
    : ttl_{ttl_seconds} {
    ctx_ = redisConnect(host.c_str(), port);
    if (ctx_ == nullptr || ctx_->err) {
        if (ctx_) {
            fprintf(stderr, "redis connect failed: %s\n", ctx_->errstr);
            redisFree(ctx_);
            ctx_ = nullptr;
        } else {
            fprintf(stderr, "redis connect failed: allocation error\n");
        }
    }
}

RedisDedup::~RedisDedup() {
    if (ctx_) redisFree(ctx_);
}

bool RedisDedup::is_new_alert(const std::string& key) {
    if (!ctx_) return true;   // disabled -> fail-open

    // Atomic claim: set only if absent, with a TTL. Status "OK" => we set it.
    auto* r = static_cast<redisReply*>(
        redisCommand(ctx_, "SET %s 1 NX EX %d", key.c_str(), ttl_));

    if (r == nullptr) return true;   // connection dropped mid-command -> fail-open

    const bool is_new{r->type == REDIS_REPLY_STATUS};
    freeReplyObject(r);
    return is_new;
}

}  // namespace ids
