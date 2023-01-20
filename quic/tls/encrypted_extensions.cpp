#include "encrypted_extensions.hpp"

#include <cstdio>

namespace tls {
std::vector<uint8_t> EncryptedExtensions::GetBinary() {
  return {};
}

void EncryptedExtensions::Parse(std::vector<uint8_t> &buf, int &p) {
  /*
      struct {
          Extension extensions<0..2^16-1>;
      } EncryptedExtensions;
  */
  int p_begin = p;
  msg_type_ = static_cast<HandshakeType>(buf[p]);
  p++; // msg_type;
  p += 3;// skip length

  uint32_t encrypted_extension_length = (buf[p] << 8) | (buf[p + 1]);
  p += 2;
  // std::cout << "EncryptedExtensions: length " <<
  // encrypted_extension_length
  //          << std::endl;
  while (p < encrypted_extension_length) {
    uint16_t extension_type = buf[p] << 8 | buf[p + 1];
    p += 2;
    // std::cout << "extention type: " << extension_type << std::endl;
    uint16_t extension_length = buf[p] << 8 | buf[p + 1];
    p += 2;
    // std::cout << "extention length: " << extension_length << std::endl;

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
      // std::cout << "Supported  Version: " << std::endl;
      p += extension_length;
      break;
    case 51: {
      int tmp = p;
      // std::cout << "key_share_server_hello" << std::endl;
      p += extension_length;
      break;
    }
    case 57:
      // quic transport parameter
      p += extension_length;
      break;
    default:
      printf("extension not implemented\n");
      p += extension_length;
      break;
    }
  }
}

} // namespace tls
