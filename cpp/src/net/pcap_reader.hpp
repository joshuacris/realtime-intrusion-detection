#pragma once

#include "net/packet.hpp"
#include <functional>

namespace ids {

// Read every packet from a pcap file, invoking `on_packet` once per parsed IPv4
// TCP/UDP/ICMP packet. Returns the packet count, or -1 on a fatal error
// (missing file, unsupported link-layer type).
long read_pcap(const char* path,
               const std::function<void(const Packet&)>& on_packet);

}  // namespace ids
