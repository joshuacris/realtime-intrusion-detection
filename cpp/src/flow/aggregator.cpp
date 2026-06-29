#include "flow/aggregator.hpp"
#include <utility>
#include <cmath>

namespace ids {

namespace {
// Sweeping every packet would be O(flows) per packet; this bounds the cost.
constexpr uint64_t SWEEP_EVERY_N_PKTS{500000};
}  // namespace

FlowAggregator::FlowAggregator(FlowSink sink, uint64_t idle_timeout_us)
    : sink_{std::move(sink)}, idle_timeout_us_{idle_timeout_us} {}

void FlowAggregator::add_packet(const Packet& p) {
    if (p.timestamp_us > now_us_) now_us_ = p.timestamp_us;

    if (++pkts_since_sweep_ >= SWEEP_EVERY_N_PKTS) {
        sweep_idle(now_us_);
        pkts_since_sweep_ = 0;
    }

    const FlowKey key{make_flow_key(p)};
    FlowState& st{flows_[key]};   // get-or-create reference

    // Drop the immediate byte-identical capture duplicate (within 5ms). Real
    // retransmits are >200ms apart, so this never eats genuine loss.
    if (st.seen) {
        const bool from_src{st.is_from_source(p)};
        if (from_src == st.last_from_src &&
            p.tcp_seq      == st.last_seq  &&
            p.ip_total_len == st.last_len  &&
            p.tcp_flags    == st.last_flags &&
            p.timestamp_us - st.last_pkt_ts < 5000) {
            return;
        }
        st.last_from_src = from_src;
    } else {
        st.last_from_src = true;
    }
    st.last_seq    = p.tcp_seq;
    st.last_len    = p.ip_total_len;
    st.last_flags  = p.tcp_flags;
    st.last_pkt_ts = p.timestamp_us;

    // A closed flow lingers to swallow stragglers; only a fresh pure SYN means a
    // new connection is reusing the 5-tuple, so reset the slot in place.
    if (st.emitted) {
        const bool pure_syn{(p.tcp_flags & TCP_SYN) && !(p.tcp_flags & TCP_ACK)};
        if (!pure_syn) return;
        st = FlowState{};
    }

    if (!st.seen) {
        st.seen        = true;
        st.init_ip     = p.src_ip;
        st.init_port   = p.src_port;
        st.first_ts_us = p.timestamp_us;
        st.sttl        = p.ttl;
        st.swin        = p.tcp_window;
    }
    st.last_ts_us = p.timestamp_us;

    if (st.is_from_source(p)) {
        st.spkts  += 1;
        st.sbytes += p.ip_total_len;
        st.s_flags |= p.tcp_flags;

        if (st.spkts > 1) {
            const double interval{static_cast<double>(p.timestamp_us - st.s_last_ts)};
            st.s_intpkt_sum += interval;
            st.s_intpkt_n   += 1;
            if (st.s_intpkt_n > 1) {
                st.s_jit_sum += std::fabs(interval - st.s_prev_int);
                st.s_jit_n   += 1;
            }
            st.s_prev_int = interval;
        }
        st.s_last_ts = p.timestamp_us;

        // Data segments only; signed-difference compare handles seq wraparound.
        if (key.proto == 6 && p.payload_len > 0) {
            const uint32_t seg_end{p.tcp_seq + p.payload_len};
            if (!st.s_seq_init) {
                st.s_seq_init = true;
                st.s_max_seq_end = seg_end;
            } else if (static_cast<int32_t>(p.tcp_seq - st.s_max_seq_end) < 0) {
                st.sloss += 1;
            } else {
                st.s_max_seq_end = seg_end;
            }
        }

        if (key.proto == 6 && (p.tcp_flags & TCP_SYN) &&
            !(p.tcp_flags & TCP_ACK) && !st.has_syn) {
            st.syn_ts = p.timestamp_us; st.has_syn = true;
        }
        if (key.proto == 6 && (p.tcp_flags & TCP_ACK) &&
            !(p.tcp_flags & TCP_SYN) && st.has_synack && !st.has_ack) {
            st.ack_ts = p.timestamp_us; st.has_ack = true;
        }
    } else {
        st.dpkts  += 1;
        st.dbytes += p.ip_total_len;
        st.d_flags |= p.tcp_flags;
        if (st.dpkts == 1) {
            st.dttl = p.ttl;
            st.dwin = p.tcp_window;
        }

        if (st.dpkts > 1) {
            const double interval{static_cast<double>(p.timestamp_us - st.d_last_ts)};
            st.d_intpkt_sum += interval;
            st.d_intpkt_n   += 1;
            if (st.d_intpkt_n > 1) {
                st.d_jit_sum += std::fabs(interval - st.d_prev_int);
                st.d_jit_n   += 1;
            }
            st.d_prev_int = interval;
        }
        st.d_last_ts = p.timestamp_us;

        if (key.proto == 6 && p.payload_len > 0) {
            const uint32_t seg_end{p.tcp_seq + p.payload_len};
            if (!st.d_seq_init) {
                st.d_seq_init = true;
                st.d_max_seq_end = seg_end;
            } else if (static_cast<int32_t>(p.tcp_seq - st.d_max_seq_end) < 0) {
                st.dloss += 1;
            } else {
                st.d_max_seq_end = seg_end;
            }
        }

        if (key.proto == 6 && (p.tcp_flags & TCP_SYN) &&
            (p.tcp_flags & TCP_ACK) && !st.has_synack) {
            st.synack_ts = p.timestamp_us; st.has_synack = true;
        }
    }

    // RST (either side) or FIN on both sides ends the flow.
    if (key.proto == 6 && !st.emitted) {
        const bool reset{((st.s_flags | st.d_flags) & TCP_RST) != 0};
        const bool closed{(st.s_flags & TCP_FIN) && (st.d_flags & TCP_FIN)};
        if (reset || closed) {
            emit(key, st);
            st.emitted = true;
        }
    }
}

// Emit + remove flows idle longer than the timeout (erase-while-iterating).
void FlowAggregator::sweep_idle(uint64_t now_us) {
    for (auto it = flows_.begin(); it != flows_.end(); /* advance below */) {
        if (now_us > it->second.last_ts_us + idle_timeout_us_) {
            if (!it->second.emitted) emit(it->first, it->second);
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}

void FlowAggregator::flush() {
    for (const auto& [key, st] : flows_)
        if (!st.emitted) emit(key, st);
    flows_.clear();
}

void FlowAggregator::emit(const FlowKey& key, const FlowState& st) {
    if (sink_) sink_(key, st);
}

}  // namespace ids
