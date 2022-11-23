#ifndef TLS_HMAC_HPP_
#define TLS_HMAC_HPP_

#include <vector>
#include <openssl/ssl.h>

#include "../quic/ssl_common.hpp"

namespace tls {

class HMAC {
public:
  std::vector<uint8_t> ComputeHMAC(std::vector<uint8_t> &in,
                                    std::vector<uint8_t> &key);
};

} // namespace tls

#endif // TLS_HMAC_HPP_