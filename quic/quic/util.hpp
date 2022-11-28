#pragma once

namespace quic {
enum class PacketType {
  Initial = 0x00,
  ZeroRTT = 0x01,
  Handshake = 0x02,
  Retry = 0x03,
  OneRTT = 0x10,
  Unknown = 0x20
};

PacketType IsLongHeaderPacket(unsigned char *packet);
} // namespace quic