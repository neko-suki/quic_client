#pragma once

#include <iostream>

#include <string>
#include <vector>

#include <botan-2/botan/hkdf.h>
#include <botan-2/botan/hmac.h>
#include <openssl/evp.h>

#include "../tls/hash.hpp"

namespace tls {

class HKDF {
public:
  HKDF();
  // hash_len should be byte. 256 = 32byte
  std::vector<uint8_t> Extract(size_t hash_len,
                               const std::vector<uint8_t> &salt,
                               const std::vector<uint8_t> &ikm);
  std::vector<uint8_t> ExpandLabel(std::vector<uint8_t> &secret,
                                   std::string label_string,
                                   std::vector<uint8_t> &context,
                                   size_t key_length);
  std::vector<uint8_t> DeriveSecret(size_t hash_length,
                                    std::vector<uint8_t> &secret,
                                    std::string label,
                                    std::vector<uint8_t> &message);
};
} // namespace tls
