#pragma once

#include <vector>

#include <stdint.h>

#include "socket.hpp"

namespace quic {

class OneRttPacket {
public:
  OneRttPacket(std::vector<uint8_t> dst_id, uint64_t packet_number);
  void Send(Socket &sock, std::vector<uint8_t> &client_app_hp,
            std::vector<uint8_t> &client_app_key,
            std::vector<uint8_t> &client_app_iv);
  void AddFrame(std::vector<uint8_t> frame_binary);

private:
  int CreateHeader();
  std::vector<uint8_t> dst_id_;
  uint64_t packet_number_;
  std::vector<uint8_t> header_;
  std::vector<uint8_t> payload_;
};

} // namespace quic