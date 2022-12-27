#include "hkdf.hpp"

namespace tls {
HKDF::HKDF() {}

std::vector<uint8_t> HKDF::Extract(size_t hash_len,
                                   const std::vector<uint8_t> &salt,
                                   const std::vector<uint8_t> &ikm) {
  std::unique_ptr<Botan::KDF> hkdf(
      Botan::KDF::create(std::string("HKDF-Extract(HMAC(SHA-256))")));
  Botan::secure_vector<uint8_t> sret;
  /*
  secure_vector< uint8_t > Botan::KDF::derive_key	(	size_t
  key_len, const uint8_t 	secret[], size_t 	secret_len, const
  uint8_t 	salt[], size_t 	salt_len, const uint8_t 	label[] =
  nullptr, size_t 	label_len = 0 )		const
  */
  sret = hkdf->derive_key(hash_len, ikm.data(), ikm.size(), salt.data(),
                          salt.size(), nullptr, 0);
  std::vector<uint8_t> ret(sret.begin(), sret.end());
  return ret;
}

std::vector<uint8_t> HKDF::ExpandLabel(std::vector<uint8_t> &secret,
                                       std::string label_string,
                                       std::vector<uint8_t> &context,
                                       size_t key_length) {
  std::unique_ptr<Botan::KDF> hkdf(
      Botan::KDF::create(std::string("HKDF-Expand(HMAC(SHA-256))")));
  std::string label = {static_cast<char>((key_length & 0xff00) >> 8),
                       static_cast<char>((key_length & 0xff))};
  label_string = "tls13 " + label_string;
  label.push_back(label_string.size());
  label += label_string;

  label.push_back(context.size());
  std::copy(context.begin(), context.end(), std::back_inserter(label));

  Botan::secure_vector<uint8_t> key = hkdf->derive_key(
      key_length, secret.data(), secret.size(), "", label);

  // copy secure_vector to vector
  std::vector<uint8_t> ret(key.begin(), key.end());
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
} // namespace quic
