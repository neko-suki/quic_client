#include "ecdh.hpp"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

namespace tls {

bool ECDH::CreateKey(void) {
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
  //pctx_ = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  pctx_ = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);

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
  return ret;

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

  return ret2;
}

void ECDH::SetPeerPublicKey(std::vector<uint8_t> &public_key_vec) {
  int error;
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


  // new implementation
  //EVP_PKEY_set_octet_string_param
  
  //https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_set_octet_string_param.html
  //EVP_PKEY_derive_set_peer(pctx_, ?);

/*
  peer_pkey_ = EVP_PKEY_new();
  peer_pkey_ = EVP_EC_gen("prime256v1");
  int nid = EVP_PKEY_get_id(pkey_);
  int type = EVP_PKEY_type(nid); 

  if (EVP_PKEY_set_type(peer_pkey_, type) == 0) {
    fprintf(stderr, "EVP_PKEY_set_type failed\n");
    std::exit(1);
  }

  BIO *out;
  out = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
  BIO_printf(out, "------------------------ Hello World2 ------------------\n");
  BIO_printf(out, "PrivateKey\n");
  EVP_PKEY_print_private(out, peer_pkey_, 0, NULL);
*/

  //peer_pkey_ = EVP_EC_gen("prime256v1");
  /*
  if (EVP_PKEY_set_octet_string_param(peer_pkey_, OSSL_PKEY_PARAM_PUB_KEY, public_key_vec.data(), public_key_vec.size()) == 0) {
    fprintf(stderr, "Failed to set public key\n");
    std::exit(1);
  }
  */

/*
  const unsigned char *p2;
  p2 = public_key_vec.data();
  peer_pkey_ = EVP_PKEY_new();
  printf("test: %x\n", peer_pkey_);
  d2i_PUBKEY(&peer_pkey_, &p2, public_key_vec.size());
  printf("test: %x\n", peer_pkey_);
*/

/*
  char error_string[256];
  ERR_error_string(error, error_string);
  printf("Error during deserialization: %s\n", error_string);
*/


/*
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey_, NULL);
  EVP_PKEY_derive_init(ctx);
  EVP_PKEY_derive_set_peer(ctx, peer_pkey_);

  size_t shared_secret_len;
  EVP_PKEY_derive(ctx, NULL, &shared_secret_len);
  std::vector<uint8_t> shared_secret(shared_secret_len);
  EVP_PKEY_derive(ctx, shared_secret.data(), &shared_secret_len);
*/

/*
  peer_pkey_ = EVP_PKEY_new();
  FILE *stream = fmemopen(public_key_vec.data(), public_key_vec.size(), "r");

	BIO *bioPubKey = BIO_new_fp(stream, BIO_NOCLOSE);
	PEM_read_bio_PUBKEY(bioPubKey, &peer_pkey_, NULL, NULL);
	BIO_free(bioPubKey);
*/

  /*
  printf("test\n");
  unsigned char *p = public_key_vec.data();
  //peer_pkey_ = EVP_PKEY_new_raw_public_key(EVP_PKEY_EC, NULL, public_key_vec.data(), public_key_vec.size());
  peer_pkey_ = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,  (unsigned char*)key_, sizeof(key_));
  printf("peer_pkey: %x\n", peer_pkey_);
  char error_string[256];
  ERR_error_string(error, error_string);
  printf("Error during deserialization: %s\n", error_string);
  */


  peer_pkey_ = EVP_PKEY_new();

  if (EVP_PKEY_copy_parameters(peer_pkey_, pkey_) < 0) {
    fprintf(stderr, "EVP_PKEY_copy_parameters failed: error %d\n", error);
    std::exit(1);
  }

  if (EVP_PKEY_set1_encoded_public_key(peer_pkey_, public_key_vec.data(),
                                      public_key_vec.size()) <= 0) {
    fprintf(stderr, "EVP_PKEY_set1_encoded_public_key failed: error %d\n", error);
    std::exit(1);
  }

// check output
  BIO *dbg_out;
  dbg_out = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
  BIO_printf(dbg_out, "------------------------ Hello World2 ------------------\n");
  BIO_printf(dbg_out, "PrivateKey\n");
  EVP_PKEY_print_public(dbg_out, peer_pkey_, 0, NULL);

  int nid = EVP_PKEY_get_id(pkey_);
  pctx2_ = EVP_PKEY_CTX_new(pkey_, NULL);

  EVP_PKEY_derive_init(pctx2_);

  if ((error = EVP_PKEY_derive_set_peer(pctx2_, peer_pkey_)) <= 0){
    fprintf(stderr, "EVP_PKEY_derive_set_peer failed: error %d\n", error);
    std::exit(1);
  }
  fprintf(stderr, "EVP_PKEY_derive_set_peer no error\n");
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

  //return secret;

  // new implementation
  size_t skey_len;
  int error;
  if ((error = EVP_PKEY_derive(pctx2_, NULL, &skey_len)) <= 0){
    fprintf(stdout, "Failed. get size of key: error %d\n", error);
    std::exit(1);
  }
  fprintf(stdout, "size of skey: %u. secret.size() : %u\n", skey_len, secret.size());



  return secret;
}

} // namespace tls
