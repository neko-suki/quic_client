#include "hash.hpp"

#include "tls_common.hpp"
#include <openssl/ssl.h>

namespace tls {

std::vector<uint8_t> Hash::ComputeHash(size_t hash_length,
                                       std::vector<uint8_t> &in) {
  EVP_MD_CTX *mdCtx = NULL;
  if (!(mdCtx = EVP_MD_CTX_new())) {
    printf("error\n");
    return {};
  }

  EVP_MD_CTX_init(mdCtx);
  if (EVP_DigestInit(mdCtx, EVP_sha256()) != 1) {
    fprintf(stderr, "EVP_DigestInit()failed\n");
    return {};
  }
  if (EVP_DigestUpdate(mdCtx, in.data(), in.size()) != 1) {
    fprintf(stderr, "EVP_DigestUpdate failed\n");
    return {};
  }
  unsigned int out_sz;
  std::vector<uint8_t> ret(hash_length);
  if (EVP_DigestFinal(mdCtx, ret.data(), &out_sz) != 1) {
    fprintf(stderr, "EVP_DigestFinal failed\n");
    return {};
  }
  EVP_MD_CTX_free(mdCtx);

  return ret;
}

} // namespace tls