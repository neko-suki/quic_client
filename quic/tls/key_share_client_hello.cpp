#include "key_share_client_hello.hpp"

namespace tls{
void KeyShareClientHello::CreateKey() {
    KeyShareEntry key_share_entry;
    key_share_entry.CreateKey();
    client_shares_.push_back(key_share_entry);
}

std::vector<uint8_t> KeyShareClientHello::GetBinary() {
    std::vector<uint8_t> ret;
    // key share key_share(51),
    ret.push_back(0x00);
    ret.push_back(0x33);

    std::vector<uint8_t> buf;
    for (auto &client_share : client_shares_) {
      std::vector<uint8_t> tmp = client_share.GetBinary();
      std::copy(tmp.begin(), tmp.end(), std::back_inserter(buf));
    }
    uint8_t client_shares__len[2] = {
        static_cast<uint8_t>((buf.size() & 0xff00) >> 8),
        static_cast<uint8_t>((buf.size() & 0x00ff)),
    };
    for (int i = 0; i < 2; i++) {
      ret.push_back(client_shares__len[i]);
    }
    std::copy(buf.begin(), buf.end(), std::back_inserter(ret));

    return ret;
}

ECDH KeyShareClientHello::GetECDH() {
    return client_shares_[0].GetECDH();
}
}