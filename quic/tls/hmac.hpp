#pragma once

#include <openssl/ssl.h>
#include <vector>

#include "../quic/ssl_common.hpp"

namespace tls {

class HMAC {
public:
  std::vector<uint8_t> ComputeHMAC(std::vector<uint8_t> &in,
                                   std::vector<uint8_t> &key);
};
} // namespace tls
