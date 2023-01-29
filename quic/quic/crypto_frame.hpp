/*
    CRYPTO Frame {
    Type (i) = 0x06,
    Offset (i),
    Length (i),
    Crypto Data (..),
    }
*/

#pragma once

#include <stdint.h>
#include <vector>

#include "../tls/certificate.hpp"
#include "../tls/certificate_verify.hpp"
#include "../tls/client_hello.hpp"
#include "../tls/encrypted_extensions.hpp"
#include "../tls/finished.hpp"
#include "../tls/handshake.hpp"
#include "../tls/server_hello.hpp"

#include "../tls/ecdh.hpp"
#include "quic_frame.hpp"

namespace quic {
class CryptoFrame : public QUICFrame {
public:
  CryptoFrame() : QUICFrame(QUICFrameType::CRYPTO) {}
  void CreateFrame(std::vector<uint8_t> &initial_source_connection_id);
  std::vector<uint8_t> GetBinary();
  void Parse(std::vector<uint8_t> &buf, int &p);
  std::vector<uint8_t> GetSharedKey();
  tls::ECDH GetECDH();
  std::vector<uint8_t> GetClientHello();
  std::vector<uint8_t> GetServerHello();
  std::vector<uint8_t> GetServerHandshakeBinary();
  std::vector<uint8_t> GetServerHandshakeBinaryWithoutFinished();
  std::vector<uint8_t> GetVerifyData();

private:
  tls::ClientHello client_hello_;
  std::unique_ptr<tls::ServerHello> server_hello_;
  std::unique_ptr<tls::EncryptedExtensions> encrypted_extensions_;
  std::unique_ptr<tls::Certificate> certificate_;
  std::unique_ptr<tls::CertificateVerify> certificate_verify_;
  std::unique_ptr<tls::Finished> finished_;
  std::vector<uint8_t> server_handshake_binary_;
  std::vector<uint8_t> server_handshake_binary_without_finished_;
  std::vector<uint8_t> crypto_frame_binary_;
};
} // namespace quic
