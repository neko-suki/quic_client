#pragma once

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
  EC_KEY *key_;
  EC_POINT *peer_;

  EVP_PKEY *pkey_;
  EVP_PKEY_CTX *pctx_;

};

} // namespace tls
