#include "parse_packet.hpp"

#include <iostream>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

#include "parse_common.hpp"
#include "ssl_common.hpp"

namespace quic {
/*
Handshake Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 2,
  Reserved Bits (2),
  Packet Number Length (2),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Length (i),
  Packet Number (8..32),
  Packet Payload (8..),
}
*/

struct PacketInfo UnprotectPacket::Unprotect(
    unsigned char *packet, int packet_sz,
    const std::vector<uint8_t> &hp_key, const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &key, std::vector<uint8_t> &header,
    std::vector<uint8_t> &decoded_payload,
    const std::vector<uint8_t> dcid) {
  int tag_sz = AES_BLOCK_SIZE;
  uint64_t packet_number;
  const EVP_CIPHER *cipher_suite = EVP_aes_128_ecb();

  struct PacketInfo packet_info = UnprotectHeader(
      packet, packet_sz, hp_key, cipher_suite, header, dcid);
  decoded_payload.resize(packet_info.payload_length);

  UnprotectPayload(header, packet + packet_info.payload_offset,
                   packet_info.payload_length,
                   packet + packet_info.tag_offset, decoded_payload.data(),
                   iv, key, packet_info.packet_number);

  return packet_info;
}

struct PacketInfo UnprotectPacket::UnprotectHeader(
    unsigned char packet[], int packet_sz, const std::vector<uint8_t> &key,
    const EVP_CIPHER *cipher_suite, std::vector<uint8_t> &header,
    std::vector<uint8_t> dcid) {
  header.clear();
  int header_type;
  int pn_offset;
  unsigned long long length = 0;
  unsigned char sample[16];
  struct PacketInfo ret;
  if ((packet[0] & 0x80) != 0) {
    // Long Header
    header_type = LONG_HEADER;

    int p = 5;
    int destination_connection_id_length;
    int source_connection_id_length;
    int token_length;
    if (((packet[0] & 0x30) >> 4) == 0) {
      // Initial Packet
      destination_connection_id_length = packet[p++];
      p += destination_connection_id_length;
      source_connection_id_length = packet[p++];
      std::copy(packet + p, packet + p + source_connection_id_length,
                std::back_inserter(ret.source_connection_id));
      p += source_connection_id_length;
      token_length = packet[p++];
      p += token_length;
    } else if (((packet[0] & 0x30) >> 4) == 2) {
      // Handshake Packet
      destination_connection_id_length = packet[p++];
      p += destination_connection_id_length;
      source_connection_id_length = packet[p++];
      std::copy(packet + p, packet + p + source_connection_id_length,
                std::back_inserter(ret.source_connection_id));
      p += source_connection_id_length;
    } else {
      printf("not implemented:\n");
      std::exit(1);
    }

    int msb_2bit = ((packet[p] & 0xc0)) >> 6;
    if (msb_2bit == 0) {
      // length = 1
      length = packet[p] & 0x3f;
      p++;
    } else if (msb_2bit == 1) {
      length = ((packet[p] & 0x3f) << 8) | (packet[p + 1]);
      p += 2;
    } else if (msb_2bit == 2) {
      length = ((packet[p] & 0x3f) << 24) | (packet[p + 1] << 16) |
               (packet[p + 2] << 8) | (packet[p + 3]);
      p += 4;
    } else if (msb_2bit == 3) {
      length = ((unsigned long long)(packet[p] & 0x3f) << 56) |
               ((unsigned long long)(packet[p + 1]) << 48) |
               ((unsigned long long)(packet[p + 2]) << 40) |
               (((unsigned long long)packet[p + 3]) << 32) |
               ((packet[p + 4] & 0x3f) << 24) | (packet[p + 5] << 16) |
               (packet[p + 6] << 8) | (packet[p + 7]);
      p += 8;
    }
    pn_offset = p;
  } else {
    header_type = SHORT_HEADER;
    int p = 1 + dcid.size();
    pn_offset = p;
    length = packet_sz - pn_offset;
  }

  std::copy(packet + pn_offset + 4, packet + pn_offset + 4 + 16, sample);

  int mode = ENC;
  int sample_length = sizeof(sample);

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
  if (EVP_CipherUpdate(evp, mask, &mask_length, sample, sample_length) !=
      SSL_SUCCESS) {
    fprintf(stderr, "ERROR: header_protection EVP_CpiherUpdate\n");
    return ret;
  }

  if (header_type == LONG_HEADER) {
    packet[0] ^= (mask[0] & 0x0f);
    // printf("packet[0]: %02x\n", packet[0]);
  } else { // Short Header
    packet[0] ^= (mask[0] & 0x1f);
  }

  int packet_number_length = (packet[0] & 0x3) + 1;

  unsigned long long packet_number = 0;
  for (int i = 0; i < packet_number_length; i++) {
    packet_number =
        (packet_number << 8) + (packet[pn_offset + i] ^ mask[i + 1]);
    packet[pn_offset + i] ^= mask[i + 1];
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
                                   unsigned char *payload, int payload_sz,
                                   unsigned char *tag,
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

  int tmp_len = original_payload_sz;
  unsigned char tmp_tag[AES_BLOCK_SIZE] = {0};
  if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_SET_TAG, tag_sz, tmp_tag) !=
      SSL_SUCCESS) {
    fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl(DEC)\n");
    return;
  }

  int test = EVP_CipherFinal_ex(evp, original_payload + tmp_len,
                                &original_payload_sz);
  if (test <= 0 && ERR_get_error() != 0) {
    fprintf(stderr,
            "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    return;
  }

  EVP_CIPHER_CTX_free(evp);
  return;
}

} // namespace quic
