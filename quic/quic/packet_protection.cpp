#include "packet_protection.hpp"

namespace quic {
void PacketProtection::Protect(
    std::vector<uint8_t> &header, const std::vector<uint8_t> &payload,
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &hp_key, const uint64_t packet_number,
    const int packet_number_offset,
    std::vector<uint8_t> &protected_payload, std::vector<uint8_t> &tag) {
  int protected_payload_sz;
  ProtectPayload(header.data(), header.size(), payload.data(),
                 payload.size(), protected_payload.data(),
                 &protected_payload_sz, key.data(), key.size(), iv.data(),
                 iv.size(), tag.data(), packet_number);
  ProtectHeader(header.data(), header.size(), protected_payload.data(),
                protected_payload.size(), hp_key.data(),
                packet_number_offset);
}

int PacketProtection::ProtectPayload(
    const uint8_t header[], const size_t header_sz,
    const uint8_t payload[], const int payload_sz,
    uint8_t protected_payload[], int *protected_payload_sz,
    const uint8_t key[], const int key_sz, const uint8_t iv[],
    const int iv_sz, uint8_t tag[AES_BLOCK_SIZE],
    const uint64_t packet_number) {

  // Associated data is QUIC header.
  unsigned char *associated_data = new unsigned char[header_sz];
  std::copy(header, header + header_sz, associated_data);
  int associated_data_sz = header_sz;

  // The 62 bits of the reconstructed QUIC packet number in network byte
  // order are left-padded with zeros to the size of the IV. The exclusive
  // OR of the padded packet number and the IV forms the AEAD nonce.
  unsigned char nonce[12] = {0};
  for (int i = 0; i < 8; i++) {
    nonce[11 - i] = (packet_number >> (i * 8)) & 0xff;
  }

  // client iv can be obtained
  for (int i = 0; i < 12; i++) {
    nonce[i] = nonce[i] ^ iv[i];
  }

  EVP_CIPHER_CTX *evp = NULL;
  int mode = ENC;
  int tag_sz = AES_BLOCK_SIZE;

  if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
    fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new\n");
    EVP_CIPHER_CTX_free(evp);
    return 0;
  }

  if (EVP_CipherInit(evp, EVP_aes_128_gcm(), key, nonce, mode) !=
      SSL_SUCCESS) {
    fprintf(stderr, "ERROR: EVP_EncryptInit\n");
    EVP_CIPHER_CTX_free(evp);
    return 0;
  }

  if (EVP_CipherUpdate(evp, NULL, protected_payload_sz, associated_data,
                       associated_data_sz) != SSL_SUCCESS) {
    fprintf(stderr, "ERROR: EVP_CipherUpdate\n");
    EVP_CIPHER_CTX_free(evp);
    return 0;
  }

  if (EVP_CipherUpdate(evp, protected_payload, protected_payload_sz,
                       payload, payload_sz) != SSL_SUCCESS) {
    fprintf(stderr, "ERROR: EVP_CipherUpdate\n");
    EVP_CIPHER_CTX_free(evp);
    return 0;
  }

  if (EVP_CipherFinal(evp, protected_payload, protected_payload_sz) !=
      SSL_SUCCESS) {
    fprintf(stderr, "ERROR: EVP_CipherFinal\n");
    EVP_CIPHER_CTX_free(evp);
    return 0;
  }

  if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_GET_TAG, tag_sz, tag) !=
      SSL_SUCCESS) {
    fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl(ENC)\n");
    EVP_CIPHER_CTX_free(evp);
    return 0;
  }

  EVP_CIPHER_CTX_free(evp);
  delete[] associated_data;
  return 0;
}

int PacketProtection::ProtectHeader(uint8_t header[], int header_sz,
                                    uint8_t protected_payload[],
                                    int protected_payload_sz,
                                    const uint8_t key[],
                                    int packet_number_offset) {
  int header_type;
  int packet_number_length;
  unsigned char sample[16];
  int sample_sz = 16;

  if ((header[0] & 0x80) != 0) {
    header_type = LONG_HEADER;
  } else {
    header_type = SHORT_HEADER;
  }

  packet_number_length = (0x03 & header[0]) + 1;

  int sample_begin = 4 - packet_number_length;
  for (int i = 0; i < sample_sz; i++) {
    sample[i] = protected_payload[sample_begin + i];
  }

  int mode = ENC;
  EVP_CIPHER_CTX *evp = NULL;

  if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
    fprintf(stderr, "ERROR: header_protection EVP_CIPHER_CTX_NEW\n");
    return 0;
  }

  if (EVP_CipherInit(evp, EVP_aes_128_ecb(), key, NULL, mode) !=
      SSL_SUCCESS) {
    fprintf(stderr, "ERROR: header_protection EVP_EncryptionInit\n");
    return 0;
  }

  unsigned char out[16] = {0};
  int out_length;
  if (EVP_CipherUpdate(evp, out, &out_length, sample, sample_sz) !=
      SSL_SUCCESS) {
    fprintf(stderr, "ERROR: header_protection EVP_CpiherUpdate\n");
    return 0;
  }

  if (header_type == LONG_HEADER) {
    header[0] ^= out[0] & 0x0f;
  } else {
    header[0] ^= out[0] & 0x1f;
  }

  for (int i = packet_number_offset, mask = 1;
       mask <= packet_number_length; i++, mask++) {
    header[i] ^= out[mask];
  }

  EVP_CIPHER_CTX_free(evp);

  return 0;
}

} // namespace quic
