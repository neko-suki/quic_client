#include "ecdh.hpp"

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

  // EC_KEY_print_fp(stdout, key_, 0);

  return true;
}

std::vector<uint8_t> ECDH::GetPublicKey() {
  int size = i2o_ECPublicKey(key_, nullptr);
  unsigned char *buf = new unsigned char[size];
  std::vector<uint8_t> ret(size);
  i2o_ECPublicKey(key_, &buf);
  buf -= size;
  std::copy(buf, buf + size, ret.begin());
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
  field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key_));
  if (field_size <= 0) {
    fprintf(stdout, "EC_GROUP_get_degree\n");
    std::exit(1);
  }

  size_t secret_len = (field_size + 7) / 8;

  std::vector<uint8_t> secret(secret_len);

  secret_len =
      ECDH_compute_key(secret.data(), secret_len, peer_, key_, NULL);
  if (secret_len <= 0) {
    std::exit(1);
  }
  return secret;
}

} // namespace tls
