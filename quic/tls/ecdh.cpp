#include "ecdh.hpp"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

namespace tls {

bool ECDH::CreateKey(void) {
  // https://www.openssl.org/docs/man3.1/man7/EVP_PKEY-EC.html
  pkey_ = EVP_EC_gen("prime256v1");
  OSSL_PARAM params[2];
  //pctx_ = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  pctx_ = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);

  char param[32] = "P-256";
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, param, 0);

  params[1] = OSSL_PARAM_construct_end();
  EVP_PKEY_CTX_set_params(pctx_, params);

  EVP_PKEY_generate(pctx_, &pkey_);

 // https://www.openssl.org/docs/man3.0/man3/BIO_s_fd.html
  /*
    BIO *out;
    out = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
    BIO_printf(out, "------------------------ Hello World ------------------\n");
    BIO_printf(out, "PublicKey\n");
    EVP_PKEY_print_public(out, pkey_, 0, NULL);
    BIO_printf(out, "PrivateKey\n");
    EVP_PKEY_print_private(out, pkey_, 0, NULL);
    BIO_free(out);
  */

  return true;
}

std::vector<uint8_t> ECDH::GetPublicKey() {
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

  /*
    BIO_dump_indent_fp(stdout, ret2.data(), out_pubkey_len, 2);
    for(int i = 0;i < out_pubkey_len;i++){
      printf("%02x", ret2[i]);
    }
    printf("\n");
  */

  return ret2;
}

void ECDH::SetPeerPublicKey(std::vector<uint8_t> &public_key_vec) {
  peer_pkey_ = EVP_PKEY_new();
  int error;

  if ((error = EVP_PKEY_copy_parameters(peer_pkey_, pkey_)) < 0) {
    fprintf(stderr, "EVP_PKEY_copy_parameters failed: error %d\n", error);
    std::exit(1);
  }

  if (EVP_PKEY_set1_encoded_public_key(peer_pkey_, public_key_vec.data(),
                                      public_key_vec.size()) <= 0) {
    fprintf(stderr, "EVP_PKEY_set1_encoded_public_key failed: error %d\n", error);
    std::exit(1);
  }

  // check output
  /*
    BIO *dbg_out;
    dbg_out = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
    BIO_printf(dbg_out, "PrivateKey\n");
    EVP_PKEY_print_public(dbg_out, peer_pkey_, 0, NULL);
  */

  int nid = EVP_PKEY_get_id(pkey_);
  pctx2_ = EVP_PKEY_CTX_new(pkey_, NULL);

  EVP_PKEY_derive_init(pctx2_);

  if ((error = EVP_PKEY_derive_set_peer(pctx2_, peer_pkey_)) <= 0){
    fprintf(stderr, "EVP_PKEY_derive_set_peer failed: error %d\n", error);
    std::exit(1);
  }
}

std::vector<uint8_t> ECDH::GetSecret() {
  // new implementation
  size_t skey_len;
  int error;
  if ((error = EVP_PKEY_derive(pctx2_, NULL, &skey_len)) <= 0){
    fprintf(stdout, "Failed. get size of key: error %d\n", error);
    std::exit(1);
  }

  std::vector<uint8_t> secret(skey_len);
  if ((error = EVP_PKEY_derive(pctx2_, secret.data(), &skey_len)) <= 0){
    fprintf(stdout, "Failed. get size of key: error %d\n", error);
    std::exit(1);
  }

  return secret;
}

} // namespace tls
