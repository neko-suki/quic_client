#pragma once

#include <iostream>
#include <vector>

#include <openssl/ssl.h>

#include "hash.hpp"
#include "hkdf.hpp"

namespace tls {

class KeySchedule {
public:
  KeySchedule() {}
  void ComputeHandshakeKey(size_t hash_length,
                           std::vector<uint8_t> &hello_hash,
                           std::vector<uint8_t> &shared_secret);
  void ComputeApplicationKey(size_t hash_length,
                             std::vector<uint8_t> &handshake_hash);

  std::vector<uint8_t> GetServerHandshakeKey();
  std::vector<uint8_t> GetServerHandshakeHP();
  std::vector<uint8_t> GetServerHandshakeIV();
  std::vector<uint8_t> GetClientHandshakeKey();
  std::vector<uint8_t> GetClientHandshakeHP();
  std::vector<uint8_t> GetClientHandshakeIV();
  std::vector<uint8_t> GetFinishedKey();
  std::vector<uint8_t> GetServerFinishedKey();

  std::vector<uint8_t> GetServerAppKey();
  std::vector<uint8_t> GetServerAppHP();
  std::vector<uint8_t> GetServerAppIV();
  std::vector<uint8_t> GetClientAppKey();
  std::vector<uint8_t> GetClientAppHP();
  std::vector<uint8_t> GetClientAppIV();

  void DumpKeylog();

private:
  std::vector<uint8_t> ComputeEarlySecret(size_t hash_length);
  std::vector<uint8_t> early_secret_;
  std::vector<uint8_t> derived_secret_;
  std::vector<uint8_t> handshake_secret_;
  std::vector<uint8_t> csecret_;
  std::vector<uint8_t> ssecret_;
  std::vector<uint8_t> client_handshake_key_;
  std::vector<uint8_t> client_handshake_iv_;
  std::vector<uint8_t> client_handshake_hp_;
  std::vector<uint8_t> server_handshake_key_;
  std::vector<uint8_t> server_handshake_iv_;
  std::vector<uint8_t> server_handshake_hp_;
  std::vector<uint8_t> derived_secret_for_master_secret_;
  std::vector<uint8_t> master_secret_;
  std::vector<uint8_t> cmaster_secret_;
  std::vector<uint8_t> client_app_key_;
  std::vector<uint8_t> client_app_iv_;
  std::vector<uint8_t> client_app_hp_;
  std::vector<uint8_t> smaster_secret_;
  std::vector<uint8_t> server_app_key_;
  std::vector<uint8_t> server_app_iv_;
  std::vector<uint8_t> server_app_hp_;
  std::vector<uint8_t> finished_key_;
  std::vector<uint8_t> server_finished_key_;
  std::vector<uint8_t> hello_hash_;
};

} // namespace tls
