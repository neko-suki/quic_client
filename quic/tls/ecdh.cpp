#include "ecdh.hpp"

#include <openssl/core_names.h>

namespace tls {

bool ECDH::CreateKey(void) {
  EVP_PKEY_CTX *pctx;

  if (NULL == (key_ = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) {
    printf("Failed to create key curve\n");
    return false;
  }

  if (1 != EC_KEY_generate_key(key_)) {
    printf("Failed to generate key\n");
    return false;
  }

  EC_KEY_print_fp(stdout, key_, 0);

  // new implementation
  // https://www.openssl.org/docs/man3.1/man7/EVP_PKEY-EC.html
  pkey_ = EVP_EC_gen("prime256v1");
  printf("result of EVP_EC_GEN %x\n", pkey_);
  OSSL_PARAM params[2];
  pctx_ = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

  EVP_PKEY_keygen_init(pctx_);

  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);

  params[1] = OSSL_PARAM_construct_end();
  EVP_PKEY_CTX_set_params(pctx_, params);

  EVP_PKEY_generate(pctx_, &pkey_);

 // https://www.openssl.org/docs/man3.0/man3/BIO_s_fd.html
  BIO *out;
  out = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
  BIO_printf(out, "------------------------ Hello World ------------------\n");
  BIO_printf(out, "PublicKey\n");
  EVP_PKEY_print_public(out, pkey_, 0, NULL);
  BIO_printf(out, "PrivateKey\n");
  EVP_PKEY_print_private(out, pkey_, 0, NULL);
  BIO_free(out);

  return true;
}

std::vector<uint8_t> ECDH::GetPublicKey() {
  // internal to octet
  int size = i2o_ECPublicKey(key_, nullptr); // deprecated
  unsigned char *buf = new unsigned char[size];
  std::vector<uint8_t> ret(size);
  i2o_ECPublicKey(key_, &buf);
  buf -= size;
  std::copy(buf, buf + size, ret.begin());

  // new implementation
  size_t out_pubkey_len = 0;
  // get length
  if (!EVP_PKEY_get_octet_string_param(pkey_, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &out_pubkey_len)) {
    fprintf(stderr, "Failed to get public key\n");
    std::exit(1);
  }

  std::vector<uint8_t> ret2(out_pubkey_len);
  if (!EVP_PKEY_get_octet_string_param(pkey_, OSSL_PKEY_PARAM_PUB_KEY, ret2.data(), out_pubkey_len, &out_pubkey_len)) {
    fprintf(stderr, "Failed to get public key\n");
    std::exit(1);
  }

  BIO_dump_indent_fp(stdout, ret2.data(), out_pubkey_len, 2);
  for(int i = 0;i < out_pubkey_len;i++){
    printf("%02x", ret2[i]);
  }
  printf("\n");

  return ret;
}

void ECDH::SetPeerPublicKey(std::vector<uint8_t> &public_key_vec) {
  BN_CTX *bn_ctx = BN_CTX_new();
  EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(
      NID_X9_62_prime256v1); // TODO: Dealing with various EC_GROUP
  peer_ = EC_POINT_new(ec_group);

  if (EC_POINT_oct2point(ec_group, peer_, public_key_vec.data(),
                         public_key_vec.size(), bn_ctx)) {
  } else {
    fprintf(stdout, "EC_POINT_oct2point failed\n");
    std::exit(1);
  }
}

std::vector<uint8_t> ECDH::GetSecret() {
  int field_size;
  field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key_)); // deprecated
  if (field_size <= 0) {
    fprintf(stdout, "EC_GROUP_get_degree\n");
    std::exit(1);
  }

  size_t secret_len = (field_size + 7) / 8;

  std::vector<uint8_t> secret(secret_len);

  secret_len =
      ECDH_compute_key(secret.data(), secret_len, peer_, key_, NULL); // deprecated
  if (secret_len <= 0) {
    std::exit(1);
  }
  return secret;
}

} // namespace tls
