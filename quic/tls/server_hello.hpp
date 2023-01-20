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

#ifndef TLS_SERVER_HELLO_HPP_
#define TLS_SERVER_HELLO_HPP_

#include <algorithm>
#include <vector>

#include <iostream>

#include <stdint.h>

#include "alpn.hpp"
#include "ecdh.hpp"
#include "extension.hpp"
#include "handshake.hpp"
#include "key_share_server_hello.hpp"
#include "quic_transport_parameter.hpp"
#include "server_name.hpp"
#include "supported_groups.hpp"
#include "supported_versions.hpp"
#include "tls_common.hpp"

namespace tls {

class ServerHello : public Handshake {
public:
  void Parse(std::vector<uint8_t> &buf, int &p);
  std::vector<uint8_t> GetSharedKey();
  std::vector<uint8_t> GetServerHello();

private:
  ProtocolVersion legacy_version_;
  Random random;
  std::vector<uint8_t> legacy_session_id_echo_;
  CipherSuite cipher_suite_;
  SupportedVersions supported_versions_;
  KeyShareServerHello key_share_server_hello_;
  std::vector<uint8_t> server_hello_payload_;
};

} // namespace tls
#endif