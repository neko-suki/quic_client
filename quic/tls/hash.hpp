#ifndef TLS_HASH_HPP_
#define TLS_HASH_HPP_

#include <iostream>

#include <string>
#include <vector>

#include <botan-2/botan/hkdf.h>
#include <botan-2/botan/hmac.h>

namespace tls {

class Hash {
public:
  std::vector<uint8_t> ComputeHash(size_t hash_length,
                                   std::vector<uint8_t> &in);
};
} // namespace tls

#endif