#include "server_hello.hpp"

namespace tls {

void ServerHello::Parse(std::vector<uint8_t> & buf, int &p) {
    int p_begin = p;
    legacy_version_ = buf[p] << 8 | buf[p + 1];
    p += 2;
    std::copy(buf.begin(), buf.begin() + 32, random);
    p += 32;

    uint8_t legacy_session_id_echo_length = buf[p];
    p++;
    legacy_session_id_echo_.resize(legacy_session_id_echo_length);
    std::copy(buf.begin(), buf.begin() + legacy_session_id_echo_length, legacy_session_id_echo_.data());

    // cipher_suite
    uint16_t cipher_suite_value = buf[p] << 8 | buf[p + 1];
    p += 2;
    switch (cipher_suite_value) {
    case static_cast<uint16_t>(CipherSuite::TLS_AES_128_GCM_SHA256):
      cipher_suite_ = CipherSuite::TLS_AES_128_GCM_SHA256;
      break;
    case static_cast<uint16_t>(CipherSuite::TLS_CHACHA20_POLY1305_SHA256):
      cipher_suite_ = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
      break;
    default:
      break;
    }

    // skip compression method
    p++;

    uint16_t extension_length = buf[p] << 8 | buf[p + 1];
    p += 2;

    uint32_t extention_end = p + extension_length;
    while (p < extention_end) {
      uint16_t extension_type = buf[p] << 8 | buf[p + 1];
      p += 2;
      uint16_t extension_length = buf[p] << 8 | buf[p + 1];
      p += 2;

      switch (extension_type) {
      case 43:
        // Supported version
        p += extension_length;
        break;
      case 51: {
        int tmp = p;
        key_share_server_hello_.Parse(buf, p);
        break;
      }
      default:
        break;
      }
    }
    std::copy(buf.begin() + p_begin, buf.begin() + p, std::back_inserter(server_hello_payload_));
}

std::vector<uint8_t> ServerHello::GetSharedKey() {
    return key_share_server_hello_.GetSharedKey();
}

std::vector<uint8_t> ServerHello::GetServerHello() {
    return server_hello_payload_;
}
 
} // namespace tls
