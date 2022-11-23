#include "handshake.hpp"

namespace tls {
Handshake::Handshake() : msg_type_(static_cast<uint8_t>(HandshakeType::client_hello)) {}
  std::vector<uint8_t> Handshake::GetBinary() {
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

void Handshake::Parse(std::vector<uint8_t> & buf, int &p) {
    msg_type_ = buf[p++];
    length_ = buf[p] << 16 | buf[p + 1] << 8 | buf[p + 2];
    p += 3;
    if (msg_type_ == 2) {
      server_hello_.Parse(buf, p);
    } else if (msg_type_ == 8) {
      encrypted_extensions_.Parse(buf, p);
    } else if (msg_type_ == 11) {
      certificate_.Parse(buf, p);
    } else if (msg_type_ == 15) {
      certificate_verify_.Parse(buf, p);
    } else if (msg_type_ == 20) {
      finished_.Parse(buf, p);
    } else {
      std::cout << "not implemented" << std::endl;
      p += length_;
      std::exit(1);
    }
}

std::vector<uint8_t> Handshake::GetSharedKey() {
    return server_hello_.GetSharedKey();
}

std::vector<uint8_t> Handshake::GetServerHello() {
    std::vector<uint8_t> handshake_payload = server_hello_.GetServerHello();
    std::vector<uint8_t> ret;
    // server_hello
    ret.push_back(2);
    // 24 bit length to ret
    uint8_t handshake_payload_length[3] = {
        static_cast<uint8_t>((handshake_payload.size() & 0xff0000) >> 16),
        static_cast<uint8_t>((handshake_payload.size() & 0xff00) >> 8),
        static_cast<uint8_t>((handshake_payload.size() & 0xff))
    };
    for (int i = 0; i < 3; i++) {
        ret.push_back(handshake_payload_length[i]);
    }

    std::copy(std::begin(handshake_payload), std::end(handshake_payload),
                std::back_inserter(ret));
    return ret;
}


} // namespace tls