#include "flow_aggregator.h"
#include <utility>   // std::move
#include <cmath>     // std::fabs

namespace {
    // How many packets between idle-sweeps. Sweeping every packet would be
    // O(flows) per packet — far too slow. This bounds the cost.
    constexpr uint64_t SWEEP_EVERY_N_PKTS = 500000;
}

// Constructor. The `: sink_(...), idle_timeout_us_(...)` part is a MEMBER
// INITIALIZER LIST — it initializes members directly, before the body runs
// (more efficient than assigning inside {}). std::move avoids copying the
// std::function: we transfer ownership of the caller's sink into ours.
FlowAggregator::FlowAggregator(FlowSink sink, uint64_t idle_timeout_us)
    : sink_(std::move(sink)), idle_timeout_us_(idle_timeout_us) {}

void FlowAggregator::add_packet(const Packet& p) {
    // Track the latest timestamp (pcap time only moves forward, mostly).
    if (p.timestamp_us > now_us_) now_us_ = p.timestamp_us;

    // Throttled idle sweep: occasionally expire flows that have gone quiet.
    if (++pkts_since_sweep_ >= SWEEP_EVERY_N_PKTS) {
        sweep_idle(now_us_);
        pkts_since_sweep_ = 0;
    }

    FlowKey key = make_flow_key(p);
    FlowState& st = flows_[key];   // get-or-create (reference!)

    // First packet defines the source/initiator direction.
    if (!st.seen) {
        st.seen        = true;
        st.init_ip     = p.src_ip;
        st.init_port   = p.src_port;
        st.first_ts_us = p.timestamp_us;
        st.sttl        = p.ttl;
        st.swin        = p.tcp_window;
    }
    st.last_ts_us = p.timestamp_us;

    // Accumulate into the correct direction.
    if (st.is_from_source(p)) {
        st.spkts  += 1;
        st.sbytes += p.ip_total_len;
        st.s_flags |= p.tcp_flags;

        // Inter-arrival gap + jitter (only once we have a previous src packet).
        if (st.spkts > 1) {
            double interval = static_cast<double>(p.timestamp_us - st.s_last_ts);
            st.s_intpkt_sum += interval;
            st.s_intpkt_n   += 1;
            if (st.s_intpkt_n > 1) {                       // need 2 gaps to compare
                st.s_jit_sum += std::fabs(interval - st.s_prev_int);
                st.s_jit_n   += 1;
            }
            st.s_prev_int = interval;
        }
        st.s_last_ts = p.timestamp_us;

        // Handshake: pure SYN (SYN set, ACK clear) marks the start of setup.
        if (key.proto == 6 && (p.tcp_flags & TCP_SYN) &&
            !(p.tcp_flags & TCP_ACK) && !st.has_syn) {
            st.syn_ts = p.timestamp_us; st.has_syn = true;
        }
        // Handshake: the final ACK (ACK set, SYN clear) after we saw the SYN-ACK.
        if (key.proto == 6 && (p.tcp_flags & TCP_ACK) &&
            !(p.tcp_flags & TCP_SYN) && st.has_synack && !st.has_ack) {
            st.ack_ts = p.timestamp_us; st.has_ack = true;
        }
    } else {
        st.dpkts  += 1;
        st.dbytes += p.ip_total_len;
        st.d_flags |= p.tcp_flags;
        if (st.dpkts == 1) {           // first reply: snapshot dest ttl/window
            st.dttl = p.ttl;
            st.dwin = p.tcp_window;
        }

        if (st.dpkts > 1) {
            double interval = static_cast<double>(p.timestamp_us - st.d_last_ts);
            st.d_intpkt_sum += interval;
            st.d_intpkt_n   += 1;
            if (st.d_intpkt_n > 1) {
                st.d_jit_sum += std::fabs(interval - st.d_prev_int);
                st.d_jit_n   += 1;
            }
            st.d_prev_int = interval;
        }
        st.d_last_ts = p.timestamp_us;

        // Handshake: SYN-ACK (both SYN and ACK set) is the server's reply.
        if (key.proto == 6 && (p.tcp_flags & TCP_SYN) &&
            (p.tcp_flags & TCP_ACK) && !st.has_synack) {
            st.synack_ts = p.timestamp_us; st.has_synack = true;
        }
    }

    // ---- Explicit TCP termination ----
    // RST = abrupt reset (either side). FIN on BOTH sides = graceful close.
    if (key.proto == 6) {
        bool reset  = ((st.s_flags | st.d_flags) & TCP_RST) != 0;
        bool closed = (st.s_flags & TCP_FIN) && (st.d_flags & TCP_FIN);
        if (reset || closed) {
            emit(key, st);             // serialize while st is still valid...
            flows_.erase(key);         // ...then remove it. Do NOT touch st after.
        }
    }
}

// Walk the whole table and emit+remove flows idle longer than the timeout.
// This is the canonical "erase while iterating" pattern.
void FlowAggregator::sweep_idle(uint64_t now_us) {
    for (auto it = flows_.begin(); it != flows_.end(); /* no ++ here */) {
        // `now_us > last + timeout` (instead of `now - last > timeout`) avoids
        // unsigned underflow if timestamps are slightly out of order.
        if (now_us > it->second.last_ts_us + idle_timeout_us_) {
            emit(it->first, it->second);
            it = flows_.erase(it);     // erase() returns the NEXT valid iterator
        } else {
            ++it;                      // only advance when we DON'T erase
        }
    }
}

void FlowAggregator::flush() {
    for (const auto& [key, st] : flows_) emit(key, st);
    flows_.clear();
}

void FlowAggregator::emit(const FlowKey& key, const FlowState& st) {
    if (sink_) sink_(key, st);
}
