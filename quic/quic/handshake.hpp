#pragma once

#include <stdint.h>
#include <vector>

#include "packet_protection.hpp"
#include "padding_frame.hpp"
#include "variable_length_integer.hpp"

namespace quic {

class Handshake {
public:
  Handshake();
  void CreateClientHandshake(std::vector<uint8_t> &scid,
                             std::vector<uint8_t> &dcid,
                             std::vector<uint8_t> &verify_data,
                             uint64_t packet_number);
  void Protect(std::vector<uint8_t> &client_key,
               std::vector<uint8_t> &client_iv,
               std::vector<uint8_t> &client_hp_key);
  std::vector<uint8_t> GetBinary();

private:
  void CreateCryptoFrame(std::vector<uint8_t> &verify_data);
  void CreateACKFrame(uint64_t packet_number);
  void CreatePaddingFrame();
  void CreateHeader(std::vector<uint8_t> &scid,
                    std::vector<uint8_t> &dcid);

  PacketProtection packet_protection_;
  std::vector<uint8_t> header_;
  std::vector<uint8_t> payload_;
  std::vector<uint8_t> protected_payload_;
  std::vector<uint8_t> tag_;
  uint32_t packet_number_;
  uint32_t packet_number_offset_;
};
} // namespace quic
