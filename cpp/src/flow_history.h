#pragma once

#include <deque>
#include <cstdint>
#include <cstring>   // strcmp

// ===================================================================
// FlowHistory — the "last 100 connections" sliding window behind the
// UNSW ct_* features.
//
// Attacks reveal themselves in AGGREGATE: one SSH connection is a login,
// fifty from the same source in seconds is a brute-force. Each ct_*
// feature counts how many of the most recent connections share some
// attribute with the current one.
//
// std::deque = double-ended queue: O(1) push at the back, O(1) pop at the
// front — purpose-built for sliding windows. (A vector would shift every
// element on pop_front; a deque doesn't.)
// ===================================================================

// Compact summary of one completed flow — just the fields ct_* compare on.
// service/state point at static string literals (from flow_json.h helpers),
// so storing the pointer is safe and avoids string copies.
struct FlowRecord {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sport;
    uint16_t dport;
    const char* service;
    const char* state;
    uint8_t  sttl;
    uint8_t  dttl;
};

// The eight ct_* features for one flow.
struct CtFeatures {
    int ct_srv_src = 0;        // same service + same src ip
    int ct_srv_dst = 0;        // same service + same dst ip
    int ct_dst_ltm = 0;        // same dst ip
    int ct_src_ltm = 0;        // same src ip
    int ct_src_dport_ltm = 0;  // same src ip + same dst port
    int ct_dst_sport_ltm = 0;  // same dst ip + same src port
    int ct_dst_src_ltm = 0;    // same src ip + same dst ip
    int ct_state_ttl = 0;      // rule-based (state, ttl-range) bucket
};

class FlowHistory {
public:
    static constexpr std::size_t WINDOW = 100;   // UNSW's "last 100 connections"

    // Record this flow and return its ct_* counts (window includes the flow
    // itself, so every count is >= 1 — matching the UNSW data's convention).
    CtFeatures observe(const FlowRecord& r) {
        recent_.push_back(r);
        if (recent_.size() > WINDOW) recent_.pop_front();

        CtFeatures ct;
        for (const FlowRecord& o : recent_) {
            bool same_srv = std::strcmp(o.service, r.service) == 0;
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
    // The standard recreation of UNSW's ct_state_ttl: a categorical bucket
    // keyed on (state, source-TTL range, dest-TTL range). TTLs cluster by OS
    // and hop count, so these combos fingerprint normal vs. crafted traffic.
    static int state_ttl_bucket(const FlowRecord& r) {
        auto in = [](uint8_t v, std::initializer_list<uint8_t> set) {
            for (uint8_t x : set) if (v == x) return true;
            return false;
        };
        const char* s = r.state;
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