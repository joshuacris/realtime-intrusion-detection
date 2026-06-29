#pragma once

#include <hiredis/hiredis.h>
#include <string>

namespace ids {

// Suppress duplicate alerts with Redis + TTL. is_new_alert(key) runs an atomic
// `SET key 1 NX EX <ttl>`: true if the key was absent (new alert -> fire), false
// if it already existed (duplicate within ttl -> suppress). Fail-open: if Redis
// is unreachable every call returns true (better a dup than a dropped attack).
class RedisDedup {
public:
    RedisDedup(const std::string& host, int port, int ttl_seconds);
    ~RedisDedup();

    bool enabled() const { return ctx_ != nullptr; }
    bool is_new_alert(const std::string& key);

private:
    redisContext* ctx_{nullptr};   // null = disabled (fail-open)
    int ttl_;
};

}  // namespace ids
