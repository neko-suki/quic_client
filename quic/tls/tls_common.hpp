#ifndef TLS_COMMON_HPP_
#define TLS_COMMON_HPP_

namespace tls {

typedef uint16_t ProtocolVersion;
typedef uint8_t Random[32];

enum class CipherSuite {
  TLS_AES_128_GCM_SHA256 = 0x1301,
  TLS_AES_128_GCM_SHA384 = 0x1302,
  TLS_CHACHA20_POLY1305_SHA256 = 0x1303
};

} // namespace tls
#endif