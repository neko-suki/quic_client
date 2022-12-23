#include "key_share_client_hello.hpp"

namespace tls {
KeyShareClientHello::KeyShareClientHello(){
  extension_type_ = ExtentionType::key_share_client_hello;
}

void KeyShareClientHello::CreateKey() {
  KeyShareEntry key_share_entry;
  key_share_entry.CreateKey();
  client_shares_.push_back(key_share_entry);
}

std::vector<uint8_t> KeyShareClientHello::GetBinary() {
  std::vector<uint8_t> ret;
  // key share key_share(51),
  ret.push_back(static_cast<uint16_t>(extension_type_) >> 8);
  ret.push_back(static_cast<uint16_t>(extension_type_) & 0xff);

  std::vector<uint8_t> buf;
  for (auto &client_share : client_shares_) {
    std::vector<uint8_t> tmp = client_share.GetBinary();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(buf));
  }

  // length of client_shares
  ret.push_back((buf.size() & 0xff00) >> 8);
  ret.push_back((buf.size() & 0x00ff));
  std::copy(buf.begin(), buf.end(), std::back_inserter(ret));

  return ret;
}

ECDH KeyShareClientHello::GetECDH() { return client_shares_[0].GetECDH(); }
} // namespace tls