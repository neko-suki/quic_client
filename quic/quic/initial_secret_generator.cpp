#include <vector>

#include "initial_secret_generator.hpp"

namespace quic {

void InitialSecretGenerator::GenerateKey(
    const std::vector<uint8_t> &dcid) {
  const std::vector<uint8_t> initial_salt = {
      0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
      0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
  HKDF hkdf;
  secret_ = hkdf.Extract(32, initial_salt, dcid);

  std::vector<uint8_t> context; // empty
  client_secret_ = hkdf.ExpandLabel(secret_, "client in", context, 32);

  server_secret_ = hkdf.ExpandLabel(secret_, "server in", context, 32);

  client_key_ = hkdf.ExpandLabel(client_secret_, "quic key", context, 16);
  client_iv_ = hkdf.ExpandLabel(client_secret_, "quic iv", context, 12);
  client_hp_key_ =
      hkdf.ExpandLabel(client_secret_, "quic hp", context, 16);

  server_key_ = hkdf.ExpandLabel(server_secret_, "quic key", context, 16);
  server_iv_ = hkdf.ExpandLabel(server_secret_, "quic iv", context, 12);
  server_hp_key_ =
      hkdf.ExpandLabel(server_secret_, "quic hp", context, 16);
}

void InitialSecretGenerator::print_vec(std::string name,
                                       const std::vector<uint8_t> v) {
  // printf("%s: ", name.c_str());
  // for(const auto & ch : v){
  //    printf("%02x", ch);
  //}
  // printf("\n");
}

void InitialSecretGenerator::print() {
  print_vec("secret", secret_);
  print_vec("client_secret", client_secret_);
  print_vec("server_secret", server_secret_);
  print_vec("client_key", client_key_);
  print_vec("client_iv", client_iv_);
  print_vec("client_hp_key", client_hp_key_);
  print_vec("server_key", server_key_);
  print_vec("server_iv", server_iv_);
  print_vec("server_hp_key", server_hp_key_);
}

std::vector<uint8_t> InitialSecretGenerator::client_key() {
  return client_key_;
}
std::vector<uint8_t> InitialSecretGenerator::client_iv() {
  return client_iv_;
}
std::vector<uint8_t> InitialSecretGenerator::client_hp_key() {
  return client_hp_key_;
}

std::vector<uint8_t> InitialSecretGenerator::server_key() {
  return server_key_;
}
std::vector<uint8_t> InitialSecretGenerator::server_iv() {
  return server_iv_;
}
std::vector<uint8_t> InitialSecretGenerator::server_hp_key() {
  return server_hp_key_;
}

} // namespace quic
