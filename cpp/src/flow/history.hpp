#pragma once

#include <deque>
#include <cstdint>
#include <cstring>

namespace ids {

// Compact summary of one completed flow — the fields the ct_* features compare
// on. service/state point at static string literals, so storing the pointer is
// safe and copy-free.
struct FlowRecord {
    uint32_t src_ip{};
    uint32_t dst_ip{};
    uint16_t sport{};
    uint16_t dport{};
    const char* service{};
    const char* state{};
    uint8_t  sttl{};
    uint8_t  dttl{};
};

// The eight ct_* sliding-window features for one flow.
struct CtFeatures {
    int ct_srv_src{0};
    int ct_srv_dst{0};
    int ct_dst_ltm{0};
    int ct_src_ltm{0};
    int ct_src_dport_ltm{0};
    int ct_dst_sport_ltm{0};
    int ct_dst_src_ltm{0};
    int ct_state_ttl{0};
};

// The UNSW "last 100 connections" window behind the ct_* features: attacks show
// up in aggregate (one SSH login vs. fifty in seconds = brute force).
class FlowHistory {
public:
    static constexpr std::size_t WINDOW{100};

    // Window includes the flow itself, so every count is >= 1 (UNSW convention).
    CtFeatures observe(const FlowRecord& r) {
        recent_.push_back(r);
        if (recent_.size() > WINDOW) recent_.pop_front();

        CtFeatures ct{};
        for (const FlowRecord& o : recent_) {
            const bool same_srv{std::strcmp(o.service, r.service) == 0};
            if (same_srv && o.src_ip == r.src_ip)             ct.ct_srv_src++;
            if (same_srv && o.dst_ip == r.dst_ip)             ct.ct_srv_dst++;
            if (o.dst_ip == r.dst_ip)                         ct.ct_dst_ltm++;
            if (o.src_ip == r.src_ip)                         ct.ct_src_ltm++;
            if (o.src_ip == r.src_ip && o.dport == r.dport)   ct.ct_src_dport_ltm++;
            if (o.dst_ip == r.dst_ip && o.sport == r.sport)   ct.ct_dst_sport_ltm++;
            if (o.src_ip == r.src_ip && o.dst_ip == r.dst_ip) ct.ct_dst_src_ltm++;
        }
        ct.ct_state_ttl = state_ttl_bucket(r);
        return ct;
    }

private:
    // UNSW's ct_state_ttl: a categorical bucket keyed on (state, src-TTL, dst-TTL).
    // TTLs cluster by OS/hop count, fingerprinting normal vs. crafted traffic.
    static int state_ttl_bucket(const FlowRecord& r) {
        auto in = [](uint8_t v, std::initializer_list<uint8_t> set) {
            for (uint8_t x : set) if (v == x) return true;
            return false;
        };
        const char* s{r.state};
        if (!std::strcmp(s, "FIN") && in(r.sttl, {62, 63, 254, 255}) &&
            in(r.dttl, {252, 253}))                                   return 1;
        if (!std::strcmp(s, "INT") && in(r.sttl, {0, 62, 254}) &&
            r.dttl == 0)                                              return 2;
        if (!std::strcmp(s, "CON") && in(r.sttl, {62, 254}) &&
            in(r.dttl, {60, 252, 253}))                               return 3;
        if (!std::strcmp(s, "REQ") && r.sttl == 254 && r.dttl == 0)   return 6;
        return 0;
    }

    std::deque<FlowRecord> recent_;
};

}  // namespace ids
