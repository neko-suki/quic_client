/*
    Initial Packet {
    Header Form (1) = 1,
    Fixed Bit (1) = 1,
    Long Packet Type (2) = 0,
    Reserved Bits (2),
    Packet Number Length (2),
    Version (32),
    Destination Connection ID Length (8),
    Destination Connection ID (0..160),
    Source Connection ID Length (8),
    Source Connection ID (0..160),
    Token Length (i),
    Token (..),
    Length (i),
    Packet Number (8..32),
    Packet Payload (8..),
    }
*/

#pragma once

#include <vector>

#include <openssl/aes.h>
#include <openssl/ssl.h>
#include <stdint.h>

#include "../tls/ecdh.hpp"
#include "ack_manager.hpp"
#include "crypto_frame.hpp"
#include "initial_secret_generator.hpp"
#include "packet_protection.hpp"
#include "padding_frame.hpp"
#include "ssl_common.hpp"

namespace quic {
class InitialPacket {
public:
  InitialPacket();
  void Protect(InitialSecretGenerator &initial_secret_generator);
  void CreateInitialPacket(std::vector<uint8_t> &scid,
                           std::vector<uint8_t> &dcid);
  void CreateAckPacket(std::vector<uint8_t> &scid,
                       std::vector<uint8_t> &dcid,
                       uint64_t packet_number_ack);
  std::vector<uint8_t> GetBinary();
  tls::ECDH GetECDH();
  std::vector<uint8_t> GetClientHello();

private:
  void CreateHeader(std::vector<uint8_t> &scid,
                    std::vector<uint8_t> &dcid);

  std::vector<uint8_t> header_;
  std::vector<uint8_t> payload_;
  std::vector<uint8_t> protected_payload_;
  std::vector<uint8_t> tag_;
  int packet_number_offset_;

  CryptoFrame crypto_frame_;
  PacketProtection packet_protection_;
  int packet_number_;

  ACKManager ack_manager;
};

} // namespace quic
