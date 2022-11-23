#include "hmac.hpp"

namespace tls {

std::vector<uint8_t> HMAC::ComputeHMAC(std::vector<uint8_t> &in,
                                std::vector<uint8_t> &key) {
    HMAC_CTX *hctx = NULL;
    std::vector<uint8_t> hmac(EVP_MAX_MD_SIZE, 0);
    unsigned int len;
    int inl;
    const EVP_MD *md = NULL;

    md = EVP_get_digestbyname("SHA256");
    if (md == NULL) {
      fprintf(stderr, "EVP_get_digestbyname failed.\n");
    }

    if ((hctx = HMAC_CTX_new()) == NULL) {
      fprintf(stderr, "HMAC_CTX_new failed.\n");
      std::exit(1);
    }

    if (HMAC_Init_ex(hctx, key.data(), key.size(), md, NULL) != SSL_SUCCESS) {
      fprintf(stderr, "HMAC_Init failed.\n");
      std::exit(1);
    }

    if (HMAC_Update(hctx, in.data(), in.size()) != SSL_SUCCESS) {
      fprintf(stderr, "HMAC_Update failed.\n");
      std::exit(1);
    }

    if (HMAC_Final(hctx, hmac.data(), &len) != SSL_SUCCESS) {
      fprintf(stderr, "HMAC_Final failed.\n");
    }

    printf("hmac.size() = %ld, len = %d\n", hmac.size(), len);
    hmac.resize(len);
    return hmac;
}

} // namespace tls
