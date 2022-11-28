#ifndef QUIC_PARSE_COMMON_HPP_
#define QUIC_PARSE_COMMON_HPP_

namespace quic {

struct PacketInfo {
  int payload_offset;
  int length;
  uint64_t packet_number;
  int payload_length;
  int tag_offset;
  std::vector<uint8_t> source_connection_id;
};

} // namespace quic

#endif // QUIC_PARSE_COMMON_HPP_