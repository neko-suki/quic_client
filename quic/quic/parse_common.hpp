#pragma once

namespace quic {
struct PacketInfo {
  uint64_t packet_number;
  int tag_offset;
  std::vector<uint8_t> source_connection_id;
};
} // namespace quic
