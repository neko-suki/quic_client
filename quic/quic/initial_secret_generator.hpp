#pragma once

#include <vector>

#include "../tls/hkdf.hpp"

namespace quic {

class InitialSecretGenerator {
public:
  void GenerateKey(const std::vector<uint8_t> &dcid);
  std::vector<uint8_t> client_key();
  std::vector<uint8_t> client_iv();
  std::vector<uint8_t> client_hp_key();
  std::vector<uint8_t> server_key();
  std::vector<uint8_t> server_iv();
  std::vector<uint8_t> server_hp_key();

  void print_vec(std::string name, const std::vector<uint8_t> v);
  void print();

private:
  std::vector<uint8_t> secret_;
  std::vector<uint8_t> client_secret_;
  std::vector<uint8_t> server_secret_;
  std::vector<uint8_t> client_key_;
  std::vector<uint8_t> client_iv_;
  std::vector<uint8_t> client_hp_key_;
  std::vector<uint8_t> server_key_;
  std::vector<uint8_t> server_iv_;
  std::vector<uint8_t> server_hp_key_;
};

} // namespace quic
