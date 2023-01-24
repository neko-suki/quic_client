#include "encrypted_extensions.hpp"

#include <cstdio>

namespace tls {
std::vector<uint8_t> EncryptedExtensions::GetBinary() { return {}; }

void EncryptedExtensions::Parse(std::vector<uint8_t> &buf, int &p) {
  msg_type_ = static_cast<HandshakeType>(buf[p]);
  p++;    // msg_type;
  p += 3; // skip length

  uint32_t encrypted_extension_length = p + (buf[p] << 8) | (buf[p + 1]);
  p += 2;
  while (p < encrypted_extension_length) {
    uint16_t extension_type = buf[p] << 8 | buf[p + 1];
    p += 2;
    uint16_t extension_length = buf[p] << 8 | buf[p + 1];
    p += 2;

    switch (extension_type) {
    case 0:
      // server name
      p += extension_length;
      break;
    case 16:
      // ALPN
      p += extension_length;
      break;
    case 43:
      // Supported  Version
      p += extension_length;
      break;
    case 51: {
      // key_share_server_hello
      p += extension_length;
      break;
    }
    case 57:
      // quic transport parameter
      p += extension_length;
      break;
    default:
      p += extension_length;
      break;
    }
  }
}
} // namespace tls
