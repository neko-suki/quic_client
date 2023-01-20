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

#ifndef TLS_ENCRYPTED_EXTENSIONS_HPP_
#define TLS_ENCRYPTED_EXTENSIONS_HPP_

#include <vector>

#include <stdint.h>

#include "handshake.hpp"
#include "handshake_type.hpp"


namespace tls {

class EncryptedExtensions : public Handshake {
public:
  std::vector<uint8_t> GetBinary();
  void Parse(std::vector<uint8_t> &buf, int &p);
};

} // namespace tls
#endif // TLS_ENCRYPTED_EXTENSIONS_HPP_