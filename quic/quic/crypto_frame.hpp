/*
    CRYPTO Frame {
    Type (i) = 0x06,
    Offset (i),
    Length (i),
    Crypto Data (..),
    }
*/

#ifndef QUIC_CRYPTO_FRAME_HPP_
#define QUIC_CRYPTO_FRAME_HPP_

#include <stdint.h>
#include <vector>

#include "../tls/client_hello.hpp"
#include "../tls/handshake.hpp"

#include "../tls/ecdh.hpp"
#include "quic_frame.hpp"

namespace quic {
class CryptoFrame : public QUICFrame {
public:
  CryptoFrame() : QUICFrame(QUICFrameType::CRYPTO) {}
  void CreateFrame(std::vector<uint8_t> &initial_source_connection_id);
  std::vector<uint8_t> GetBinary();
  void Parse(std::vector<uint8_t> &buf, int &p);
  std::vector<uint8_t> GetSharedKey(int index);
  tls::ECDH GetECDH();
  std::vector<uint8_t> GetClientHello();
  std::vector<uint8_t> GetServerHello();
  std::vector<uint8_t> GetPayload();
  std::vector<uint8_t> GetPayloadWithoutFinished();
  std::vector<uint8_t> ServerSentFinished();

private:
  tls::ClientHello client_hello_;
  std::vector<tls::Handshake> handshake_;
  std::vector<uint8_t> payload_;
  std::vector<uint8_t> payload_without_finished_;
  std::vector<uint8_t> server_sent_verified_;
  std::vector<uint8_t> crypto_frame_binary_;
};
} // namespace quic

#endif