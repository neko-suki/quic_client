#include "unprotect_packet.hpp"

#include <iostream>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

#include "parse_common.hpp"
#include "parse_variable_length_integer.hpp"
#include "ssl_common.hpp"

namespace quic {
struct PacketInfo UnprotectPacket::Unprotect(
    unsigned char *packet, int packet_sz,
    const std::vector<uint8_t> &hp_key, const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &key, std::vector<uint8_t> &header,
    std::vector<uint8_t> &decoded_payload,
    const std::vector<uint8_t> dcid) {
  const EVP_CIPHER *cipher_suite = EVP_aes_128_ecb();
  struct InternalPacketInfo internal_packet_info = UnprotectHeader(
      packet, packet_sz, hp_key, cipher_suite, header, dcid);

  decoded_payload.resize(internal_packet_info.payload_length);

  UnprotectPayload(header, packet + internal_packet_info.payload_offset,
                   internal_packet_info.payload_length,
                   packet + internal_packet_info.tag_offset,
                   decoded_payload.data(), iv, key,
                   internal_packet_info.packet_number);

  struct PacketInfo packet_info = {
      internal_packet_info.packet_number, internal_packet_info.tag_offset,
      internal_packet_info.source_connection_id};

  return packet_info;
}

struct InternalPacketInfo UnprotectPacket::UnprotectHeader(
    unsigned char packet[], int packet_sz, const std::vector<uint8_t> &key,
    const EVP_CIPHER *cipher_suite, std::vector<uint8_t> &header,
    std::vector<uint8_t> dcid) {
  int header_type;
  int pn_offset;
  unsigned long long length = 0;

  struct InternalPacketInfo ret;
  if ((packet[0] & 0x80) != 0) {
    // Long Header
    header_type = LONG_HEADER;

    int p = 5;
    int destination_connection_id_length;
    int source_connection_id_length;
    int token_length;
    destination_connection_id_length = packet[p++];
    p += destination_connection_id_length;
    source_connection_id_length = packet[p++];
    std::copy(packet + p, packet + p + source_connection_id_length,
              std::back_inserter(ret.source_connection_id));
    p += source_connection_id_length;

    if (((packet[0] & 0x30) >> 4) == 0) {
      // Initial Packet
      token_length = packet[p++];
      p += token_length;
    }
    length = parse_variable_length_integer(packet, p);
    pn_offset = p;
  } else {
    header_type = SHORT_HEADER;
    int p = 1 + dcid.size();
    pn_offset = p;
    length = packet_sz - pn_offset;
  }

  unsigned char sample[16];
  std::copy(packet + pn_offset + 4, packet + pn_offset + 4 + 16, sample);

  int mode = ENC;

  // server can obtained the same key from packet.
  EVP_CIPHER_CTX *evp = NULL;

  if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
    fprintf(stderr, "ERROR: header_protection EVP_CIPHER_CTX_NEW\n");
    return ret;
  }

  if (EVP_CipherInit(evp, cipher_suite, key.data(), NULL, mode) !=
      SSL_SUCCESS) {
    fprintf(stderr, "ERROR: header_protection EVP_EncryptionInit\n");
    return ret;
  }

  unsigned char mask[16] = {0};
  int mask_length;
  int sample_length = sizeof(sample);
  if (EVP_CipherUpdate(evp, mask, &mask_length, sample, sizeof(sample)) !=
      SSL_SUCCESS) {
    fprintf(stderr, "ERROR: header_protection EVP_CpiherUpdate\n");
    return ret;
  }

  if (header_type == LONG_HEADER) {
    packet[0] ^= (mask[0] & 0x0f);
  } else {
    packet[0] ^= (mask[0] & 0x1f);
  }

  int packet_number_length = (packet[0] & 0x3) + 1;

  unsigned long long packet_number = 0;
  for (int i = 0; i < packet_number_length; i++) {
    packet[pn_offset + i] ^= mask[i + 1];
    packet_number = (packet_number << 8) + packet[pn_offset + i];
  }

  EVP_CIPHER_CTX_free(evp);

  ret.payload_offset = pn_offset + packet_number_length;
  ret.length = length;
  ret.packet_number = packet_number;
  ret.payload_length = length - packet_number_length;

  ret.tag_offset = ret.payload_offset + ret.payload_length - 16;
  ret.payload_length -= 16;

  std::copy(packet, packet + ret.payload_offset,
            std::back_inserter(header));
  return ret;
}

void UnprotectPacket::UnprotectPayload(std::vector<uint8_t> &header,
                                       unsigned char *payload,
                                       int payload_sz, unsigned char *tag,
                                       unsigned char *original_payload,
                                       const std::vector<uint8_t> &iv,
                                       const std::vector<uint8_t> &key,
                                       uint64_t packet_number) {
  int original_payload_sz;
  int tag_sz = AES_BLOCK_SIZE;

  int mode = DEC;
  unsigned char nonce[12] = {0};

  for (int i = 0; i < 8; i++) {
    nonce[11 - i] = (packet_number >> (i * 8)) & 0xff;
  }

  for (int i = 0; i < 12; i++) {
    nonce[i] = nonce[i] ^ iv[i];
  }

  unsigned char *associated_data = header.data();
  size_t associated_data_size = header.size();

  EVP_CIPHER_CTX *evp = NULL;

  if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
    fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new\n");
    return;
  }

  if (EVP_CipherInit(evp, EVP_aes_128_gcm(), key.data(), nonce, mode) !=
      SSL_SUCCESS) {
    fprintf(stderr, "ERROR: EVP_EncryptInit\n");
    return;
  }

  int payloadl;
  if (EVP_CipherUpdate(evp, NULL, &payloadl, associated_data,
                       associated_data_size) != SSL_SUCCESS) {
    fprintf(stderr, "ERROR: EVP_CipherUpdate\n");
    return;
  }

  if (EVP_CipherUpdate(evp, original_payload, &original_payload_sz,
                       payload, payload_sz) != SSL_SUCCESS) {
    fprintf(stderr, "ERROR: EVP_CipherUpdate\n");
    return;
  }

  int test = EVP_CipherFinal_ex(
      evp, original_payload + original_payload_sz, &original_payload_sz);
  if (test <= 0 && ERR_get_error() != 0) {
    fprintf(stderr,
            "ERROR: EVP_CipherFinal_ex failed. test: %d, OpenSSL error: %s\n",test,
            ERR_error_string(ERR_get_error(), NULL));
    return;
  }

  EVP_CIPHER_CTX_free(evp);
  return;
}

} // namespace quic
