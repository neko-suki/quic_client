#include "hmac.hpp"

namespace tls {

std::vector<uint8_t> HMAC::ComputeHMAC(std::vector<uint8_t> &in,
                                       std::vector<uint8_t> &key) {
  EVP_MAC *mac = NULL;

  mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (mac == NULL) {
    fprintf(stderr, "EVP_get_digestbyname failed.\n");
  }

  EVP_MAC_CTX *ctx = NULL;
  if ((ctx = EVP_MAC_CTX_new(mac)) == NULL) {
    fprintf(stderr, "EVP_MAC_CTX_new failed.\n");
    std::exit(1);
  }

  OSSL_PARAM params[2];
  size_t params_n = 0;
  const char *digest = "SHA256";

  params[params_n++] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digest), 0);
  params[params_n] = OSSL_PARAM_construct_end();

  if (EVP_MAC_init(ctx, key.data(), key.size(), params) !=
      SSL_SUCCESS) {
    fprintf(stderr, "HMAC_Init failed.\n");
    std::exit(1);
  }

  if (EVP_MAC_update(ctx, in.data(), in.size()) != SSL_SUCCESS) {
    fprintf(stderr, "HMAC_Update failed.\n");
    std::exit(1);
  }

  size_t len;
  std::vector<uint8_t> hmac(EVP_MAX_MD_SIZE, 0);
  if (EVP_MAC_final(ctx, hmac.data(), &len, hmac.size()) != SSL_SUCCESS) {
    fprintf(stderr, "HMAC_Final failed.\n");
  }

  hmac.resize(len);
  return hmac;
}

} // namespace tls
