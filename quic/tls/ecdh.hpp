#ifndef TLS_ECDH_HPP_
#define TLS_ECDH_HPP_

#include <iostream>
#include <vector>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

namespace tls {

class ECDH {
public:
  bool CreateKey(void);
  std::vector<uint8_t> GetPublicKey();
  void SetPeerPublicKey(std::vector<uint8_t> &public_key_vec);
  std::vector<uint8_t> GetSecret();
private:
  EC_KEY *key;
  EC_POINT *peer;
};

} // namespace tls

#endif