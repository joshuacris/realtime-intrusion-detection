#pragma once

#include <hiredis/hiredis.h>   // minimal C Redis client
#include <string>

// ===================================================================
// RedisDedup — suppress duplicate alerts using Redis + TTL.
//
// is_new_alert(key) does an atomic `SET key 1 NX EX <ttl>`:
//   - returns true  if the key did NOT exist (this is a NEW alert -> fire it)
//   - returns false if the key already existed (duplicate within ttl -> suppress)
//
// FAIL-OPEN: if Redis is unreachable, every call returns true (we'd rather emit
// a duplicate than silently drop an attack). enabled() reports the connection.
// ===================================================================
class RedisDedup {
public:
    RedisDedup(const std::string& host, int port, int ttl_seconds);
    ~RedisDedup();

    bool enabled() const { return ctx_ != nullptr; }
    bool is_new_alert(const std::string& key);

private:
    redisContext* ctx_ = nullptr;   // null = disabled (fail-open)
    int ttl_;
};
