#include "hkdf.hpp"

#include <cstring>

#include <openssl/kdf.h>
#include <openssl/core_names.h>

namespace tls {
HKDF::HKDF() {}

std::vector<uint8_t> HKDF::Extract(size_t hash_len,
                                   const std::vector<uint8_t> &salt,
                                   const std::vector<uint8_t> &ikm) {

  EVP_KDF *kdf;
  EVP_KDF_CTX *kctx;
  OSSL_PARAM params[6], *p = params;

  kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);

  *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<unsigned char*>(ikm.data()), ikm.size());
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, nullptr, 0);
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(salt.data()), salt.size());
  int32_t mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
  *p++ = OSSL_PARAM_construct_int32(OSSL_KDF_PARAM_MODE, &mode);
  *p = OSSL_PARAM_construct_end();

  std::vector<uint8_t> ret(256/8); // TODO

  if (EVP_KDF_derive(kctx, ret.data(), ret.size(), params) <= 0){
    perror("EVP_KDF_derive");
  }
  EVP_KDF_CTX_free(kctx);

  return ret;
}

std::vector<uint8_t> HKDF::ExpandLabel(std::vector<uint8_t> &secret,
                                       std::string label_string,
                                       std::vector<uint8_t> &context,
                                       size_t key_length) {
  std::string label = {static_cast<char>((key_length & 0xff00) >> 8),
                       static_cast<char>((key_length & 0xff))};
  label_string = "tls13 " + label_string;
  label.push_back(label_string.size());
  label += label_string;
  label.push_back(context.size());

  std::copy(context.begin(), context.end(), std::back_inserter(label));

  EVP_KDF *kdf;
  EVP_KDF_CTX *kctx;
  OSSL_PARAM params[5], *p = params;

  kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);

  *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<unsigned char*>(secret.data()), secret.size());
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                         label.data(), label.size());
  int32_t mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
  *p++ = OSSL_PARAM_construct_int32(OSSL_KDF_PARAM_MODE, &mode);

  *p = OSSL_PARAM_construct_end();

  std::vector<uint8_t> ret(256/8); // TODO

  if (EVP_KDF_derive(kctx, ret.data(), ret.size(), params) <= 0){
    perror("EVP_KDF_derive");
  }
  EVP_KDF_CTX_free(kctx);

  return ret;
}

std::vector<uint8_t> HKDF::DeriveSecret(size_t hash_length,
                                        std::vector<uint8_t> &secret,
                                        std::string label,
                                        std::vector<uint8_t> &message) {
  tls::Hash hash;
  std::vector<uint8_t> transcript_hash =
      hash.ComputeHash(hash_length, message);
  std::vector<uint8_t> ret =
      ExpandLabel(secret, label, transcript_hash, hash_length);
  return ret;
}
} // namespace tls
