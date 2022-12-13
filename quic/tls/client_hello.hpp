/*
https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2

uint16 ProtocolVersion;
opaque Random[32];

uint8 CipherSuite[2];    /* Cryptographic suite selector

struct {
    ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2
    Random random;
    opaque legacy_session_id<0..32>;
    CipherSuite cipher_suites<2..2^16-2>;
    opaque legacy_compression_methods<1..2^8-1>;
    Extension extensions<8..2^16-1>;
} ClientHello;

https://www.rfc-editor.org/rfc/rfc8446.html#appendix-B.4
CIpherCuite
              +------------------------------+-------------+
              | Description                  | Value       |
              +------------------------------+-------------+
              | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
              |                              |             |
              | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
              |                              |             |
              | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
              |                              |             |
              | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
              |                              |             |
              | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
              +------------------------------+-------------+

*/

#ifndef TLS_CLIENT_HELLO_HPP_
#define TLS_CLIENT_HELLO_HPP_

#include <algorithm>
#include <vector>

#include <iostream>

#include <stdint.h>

#include "alpn.hpp"
#include "ecdh.hpp"
#include "extension.hpp"
#include "key_share_client_hello.hpp"
#include "quic_transport_parameter.hpp"
#include "server_name.hpp"
#include "signature_algorithm.hpp"
#include "supported_groups.hpp"
#include "supported_version.hpp"
#include "tls_common.hpp"

namespace tls {

class ClientHello {
public:
  ClientHello() = default;

  void
  CreateClientHello(std::vector<uint8_t> &initial_source_connection_id);
  std::vector<uint8_t> GetBinary();

  ECDH GetECDH();

  std::vector<uint8_t> GetClientHello();

  ProtocolVersion legacy_version_;
  Random random_;
  std::vector<uint8_t> legacy_session_id;
  std::vector<CipherSuite> cipher_suites;

  SupportedVersion supported_versions_;
  NamedGroupList named_group_list_;
  KeyShareClientHello key_share_client_hello_;
  SignatureAlgorithm signature_algorithm_;
  ServerName server_name_;
  ALPN alpn_;
  QUICTransportParameter quic_transport_parameter_;

  std::vector<uint8_t> client_hello_;
};

} // namespace tls
#endif