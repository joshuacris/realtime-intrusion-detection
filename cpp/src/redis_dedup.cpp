#include "redis_dedup.h"
#include <cstdio>

RedisDedup::RedisDedup(const std::string& host, int port, int ttl_seconds)
    : ttl_(ttl_seconds) {
    ctx_ = redisConnect(host.c_str(), port);
    if (ctx_ == nullptr || ctx_->err) {
        // Couldn't connect — log and stay disabled (fail-open).
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
    if (!ctx_) return true;   // disabled -> fail-open (treat everything as new)

    // Atomic claim: set the key only if absent, with a TTL. hiredis formats the
    // args (%s, %d) for us. reply is "OK" (status) when set, nil when it existed.
    redisReply* r = static_cast<redisReply*>(
        redisCommand(ctx_, "SET %s 1 NX EX %d", key.c_str(), ttl_));

    if (r == nullptr) {
        // Connection dropped mid-command -> fail-open (don't lose the alert).
        return true;
    }
    bool is_new = (r->type == REDIS_REPLY_STATUS);   // STATUS "OK" => we set it
    freeReplyObject(r);
    return is_new;
}