#include "client_hello.hpp"

namespace tls {
void ClientHello::CreateClientHello(
    std::vector<uint8_t> &initial_source_connection_id) {
  std::vector<uint8_t> tmp;

  // legacy version
  legacy_version_ = 0x0303;
  tmp.push_back(static_cast<uint8_t>((legacy_version_ & 0xff00) >> 8));
  tmp.push_back(static_cast<uint8_t>((legacy_version_ & 0xff)));

  // copy and paste from RFC9001
  uint8_t random_input[32] = {
      0xeb, 0xf8, 0xfa, 0x56, 0xf1, 0x29, 0x39, 0xb9, 0x58, 0x4a, 0x38,
      0x96, 0x47, 0x2e, 0xc4, 0x0b, 0xb8, 0x63, 0xcf, 0xd3, 0xe8, 0x68,
      0x04, 0xfe, 0x3a, 0x47, 0xf0, 0x6a, 0x2b, 0x69, 0x48, 0x4c};
  std::copy(random_input, random_input + 32, random_);
  for (int i = 0; i < 32; i++) {
    tmp.push_back(random_[i]);
  }

  // length of legacy session_id = 0
  tmp.push_back(0x00);

  // set cipher suite
  // length of ciphter suite
  cipher_suites.push_back(CipherSuite::TLS_AES_128_GCM_SHA256);
  uint8_t length[2] = {
      static_cast<uint8_t>(((2 * cipher_suites.size()) & 0x00ff00) >> 8),
      static_cast<uint8_t>(((2 * cipher_suites.size()) & 0x0000ff))};
  for (int i = 0; i < 2; i++) {
    tmp.push_back(length[i]);
  }
  // cipher suite
  for (const auto &cipher_suite : cipher_suites) {
    int val = static_cast<uint16_t>(cipher_suite);
    tmp.push_back(static_cast<uint8_t>((val & 0xff00) >> 8));
    tmp.push_back(static_cast<uint8_t>((val & 0xff)));
  }

  // length of legacy_compression_methods
  // For every TLS 1.3 ClientHello, this vector
  // MUST contain exactly one byte, set to zero,
  tmp.push_back(0x01);
  tmp.push_back(0x00);

  // Extension extensions<8..2^16-1>;
  std::vector<uint8_t> extensions;
  std::vector<uint8_t> extension = supported_versions_.GetBinary();
  std::copy(extension.begin(), extension.end(),
            std::back_inserter(extensions));

  extension = supported_group_.GetBinary();
  std::copy(extension.begin(), extension.end(),
            std::back_inserter(extensions));

  key_share_client_hello_.CreateKey();
  extension = key_share_client_hello_.GetBinary();
  std::copy(extension.begin(), extension.end(),
            std::back_inserter(extensions));

  extension = signature_algorithm_.GetBinary();
  std::copy(extension.begin(), extension.end(),
            std::back_inserter(extensions));

  extension = server_name_.GetBinary();
  std::copy(extension.begin(), extension.end(),
            std::back_inserter(extensions));

  extension = alpn_.GetBinary();
  std::copy(extension.begin(), extension.end(),
            std::back_inserter(extensions));

  quic_transport_parameter_.SetInitialSourceConnectionID(
      initial_source_connection_id);
  extension = quic_transport_parameter_.GetBinary();
  std::copy(extension.begin(), extension.end(),
            std::back_inserter(extensions));

  // length of extension
  uint8_t extension_length[2] = {
      static_cast<uint8_t>((extensions.size() & 0xff00) >> 8),
      static_cast<uint8_t>((extensions.size() & 0xff))};
  for (int i = 0; i < 2; i++) {
    tmp.push_back(extension_length[i]);
  }

  // extension
  std::copy(extensions.begin(), extensions.end(), std::back_inserter(tmp));

  // client hello
  client_hello_.push_back(0x01); // client hello
  // 24 bit length to ret
  uint8_t tmp_length[3] = {
      static_cast<uint8_t>((tmp.size() & 0xff0000) >> 16),
      static_cast<uint8_t>((tmp.size() & 0xff00) >> 8),
      static_cast<uint8_t>(tmp.size() & 0xff)};
  for (int i = 0; i < 3; i++) {
    client_hello_.push_back(tmp_length[i]);
  }

  std::copy(tmp.begin(), tmp.end(), std::back_inserter(client_hello_));
}

std::vector<uint8_t> ClientHello::GetBinary() { return client_hello_; }

ECDH ClientHello::GetECDH() { return key_share_client_hello_.GetECDH(); }

std::vector<uint8_t> ClientHello::GetClientHello() {
  return client_hello_;
}

} // namespace tls
