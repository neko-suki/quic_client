#include "encrypted_extensions.hpp"

namespace tls {
EncryptedExtensions::EncryptedExtensions()
    : msg_type_(static_cast<uint8_t>(HandshakeType::encrypted_extensions)) {}

std::vector<uint8_t> EncryptedExtensions::GetBinary() {
  std::vector<uint8_t> ret;
  // client hello
  ret.push_back(msg_type_);

  std::vector<uint8_t> handshake = client_hello_.GetBinary();
  uint8_t length[3] = {
      static_cast<uint8_t>((handshake.size() & 0xff0000) >> 16),
      static_cast<uint8_t>((handshake.size() & 0x00ff00) >> 8),
      static_cast<uint8_t>((handshake.size() & 0x0000ff))};
  for (int i = 0; i < 3; i++) {
    ret.push_back(length[i]);
  }
  std::copy(handshake.begin(), handshake.end(), std::back_inserter(ret));

  return ret;
}

void EncryptedExtensions::Parse(std::vector<uint8_t> &buf, int &p) {
  /*
      struct {
          Extension extensions<0..2^16-1>;
      } EncryptedExtensions;
  */
  uint32_t encrypted_extension_length = (buf[p] << 8) | (buf[p + 1]);
  p += 2;
  // std::cout << "EncryptedExtensions: length " << encrypted_extension_length
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
