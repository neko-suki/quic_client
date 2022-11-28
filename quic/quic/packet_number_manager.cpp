#include "packet_number_manager.hpp"

namespace quic {
uint64_t PacketNumberManager::GetPacketNumber() {
  static uint64_t packet_number = 0;
  uint64_t ret;
  {
    std::unique_lock<std::mutex> lk(mtx_);
    ret = packet_number;
    packet_number++;
  }
  return ret;
}
} // namespace quic
