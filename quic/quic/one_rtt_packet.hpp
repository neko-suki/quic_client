#pragma once

#include <optional>
#include <vector>

#include <stdint.h>

#include "socket.hpp"

namespace quic {

class OneRttPacket {
public:
  OneRttPacket(std::vector<uint8_t> dst_id, uint64_t packet_number, std::optional<uint64_t> largest_acked);
  void AddFrame(std::vector<uint8_t> frame_binary);
  std::vector<uint8_t> GetBinary(std::vector<uint8_t> &client_app_hp,
                                 std::vector<uint8_t> &client_app_key,
                                 std::vector<uint8_t> &client_app_iv);

private:
  int CreateHeader();
  int GenerateMask();

  std::vector<uint8_t> dst_id_;
  uint64_t packet_number_;
  std::vector<uint8_t> header_;
  std::vector<uint8_t> payload_;

  std::optional<uint64_t> largest_acked_;
};

} // namespace quic