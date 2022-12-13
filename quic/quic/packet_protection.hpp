#ifndef QUIC_PACKET_PROTECTION_HPP_
#define QUIC_PACKET_PROTECTION_HPP_

#include <vector>

#include <openssl/aes.h>
#include <openssl/ssl.h>

#include "ssl_common.hpp"

namespace quic {
class PacketProtection {
public:
  void Protect(
      std::vector<uint8_t> &header, const std::vector<uint8_t> &payload,
      const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
      const std::vector<uint8_t> &hp_key, const uint64_t packet_number,
      const int packet_number_offset,
      std::vector<uint8_t> &protected_payload, std::vector<uint8_t> &tag);

private:
  int ProtectPayload(const uint8_t header[], const size_t header_sz,
                     const uint8_t payload[], const int payload_sz,
                     uint8_t protected_payload[],
                     int *protected_payload_sz, const uint8_t key[],
                     const int key_sz, const uint8_t iv[], const int iv_sz,
                     uint8_t tag[AES_BLOCK_SIZE],
                     const uint64_t packet_number);
  int ProtectHeader(uint8_t header[], int header_sz,
                    uint8_t protected_payload[], int protected_payload_sz,
                    const uint8_t key[], int packet_number_offset);
};
} // namespace quic
#endif