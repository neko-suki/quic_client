/*
https://www.rfc-editor.org/rfc/rfc8446.html#section-4
enum {
          client_hello(1),
          server_hello(2),
          new_session_ticket(4),
          end_of_early_data(5),
          encrypted_extensions(8),
          certificate(11),
          certificate_request(13),
          certificate_verify(15),
          finished(20),
          key_update(24),
          message_hash(254),
          (255)
      } HandshakeType;

      struct {
          HandshakeType msg_type;    /* handshake type
          uint24 length;             /* remaining bytes in message
          select (Handshake.msg_type) {
              case client_hello:          ClientHello;
              case server_hello:          ServerHello;
              case end_of_early_data:     EndOfEarlyData;
              case encrypted_extensions:  EncryptedExtensions;
              case certificate_request:   CertificateRequest;
              case certificate:           Certificate;
              case certificate_verify:    CertificateVerify;
              case finished:              Finished;
              case new_session_ticket:    NewSessionTicket;
              case key_update:            KeyUpdate;
          };
      } Handshake;


      struct {
          ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2/
          Random random;
          opaque legacy_session_id_echo<0..32>;
          CipherSuite cipher_suite;
          uint8 legacy_compression_method = 0;
          Extension extensions<6..2^16-1>;
      } ServerHello;
*/
#pragma once

#include <memory>

#include <stdint.h>

#include "certificate.hpp"
#include "certificate_verify.hpp"
#include "client_hello.hpp"
#include "ecdh.hpp"
#include "finished.hpp"
#include "handshake_type.hpp"

namespace tls {

class Handshake;

std::unique_ptr<Handshake> HandshakeParser(std::vector<uint8_t> &buf, int &p);

class Handshake {
public:
  Handshake();
  void Parse(std::vector<uint8_t> &buf, int &p);

  HandshakeType GetMsgType();
  const Finished &GetFinished();

protected:
  HandshakeType msg_type_;

private:
  uint32_t length_; // 24 as real
  ClientHello client_hello_;
  //ServerHello server_hello_;
  //EncryptedExtensions encrypted_extensions_;
  Certificate certificate_;
  CertificateVerify certificate_verify_;
  Finished finished_;
};
} // namespace tls
