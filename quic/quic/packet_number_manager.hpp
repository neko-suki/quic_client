#pragma once

#include <memory>
#include <mutex>

namespace quic {
class PacketNumberManager {
public:
  uint64_t GetPacketNumber();

private:
  std::mutex mtx_;
};

} // namespace quic