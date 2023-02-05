#include "util.hpp"

#include <cstdio>

namespace quic {

PacketType GetPacketType(unsigned char *packet) {
  if (packet[0] && 0x80) {
    switch ((packet[0] & 0x30) >> 4) {
    case 0:
      return PacketType::Initial;
    case 1:
      return PacketType::ZeroRTT;
    case 2:
      return PacketType::Handshake;
    case 3:
      return PacketType::Retry;
    }
  } else {
    return PacketType::OneRTT;
  }
  return PacketType::Unknown;
}
} // namespace quic