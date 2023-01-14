#pragma once

#include <vector>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

#include "parse_common.hpp"

namespace quic {
struct InternalPacketInfo {
  int payload_offset;
  int length;
  uint64_t packet_number;
  int payload_length;
  int tag_offset;
  std::vector<uint8_t> source_connection_id;
};

class UnprotectPacket {
public:
  struct PacketInfo
  Unprotect(unsigned char *packet, int packet_sz,
            const std::vector<uint8_t> &hp_key,
            const std::vector<uint8_t> &iv,
            const std::vector<uint8_t> &key, std::vector<uint8_t> &header,
            std::vector<uint8_t> &decoded_payload,
            const std::vector<uint8_t> dcid = std::vector<uint8_t>());

private:
  struct InternalPacketInfo
  UnprotectHeader(unsigned char packet[], int packet_sz,
                  const std::vector<uint8_t> &key,
                  const EVP_CIPHER *cipher_suite,
                  std::vector<uint8_t> &header,
                  std::vector<uint8_t> dcid = std::vector<uint8_t>());

  void UnprotectPayload(std::vector<uint8_t> &header,
                        unsigned char *payload, int payload_sz,
                        unsigned char *tag,
                        unsigned char *original_payload,
                        const std::vector<uint8_t> &iv,
                        const std::vector<uint8_t> &key,
                        uint64_t packet_number);
};
} // namespace quic
