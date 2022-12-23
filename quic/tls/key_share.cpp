#include "key_share.hpp"

namespace tls {
void KeyShareEntry::CreateKey() {
  named_group_ = 0x0017; // x25519
  if (!ecdh_.CreateKey()) {
    printf("create_key failed\n");
  }
  key_exchange_ = ecdh_.GetPublicKey();
}

std::vector<uint8_t> KeyShareEntry::GetBinary() {
  std::vector<uint8_t> tmp;
  // named_group
  tmp.push_back((named_group_ & 0xff00) >> 8);
  tmp.push_back((named_group_ & 0x00ff));

  // length of key_exchange
  tmp.push_back((key_exchange_.size() & 0xff00) >> 8);
  tmp.push_back((key_exchange_.size() & 0x00ff));

  std::copy(key_exchange_.begin(), key_exchange_.end(),
            std::back_inserter(tmp));

  std::vector<uint8_t> ret;
  ret.push_back((tmp.size() & 0xff00) >> 8);
  ret.push_back((tmp.size() & 0x00ff));

  std::copy(tmp.begin(), tmp.end(), std::back_inserter(ret));

  return ret;
}

void KeyShareEntry::Parse(std::vector<uint8_t> &buf, int &p) {
  named_group_ = buf[p] << 8 | buf[p + 1];
  p += 2;

  uint16_t key_exchange_length = buf[p] << 8 | buf[p + 1];
  p += 2;
  std::copy(buf.begin() + p, buf.begin() + p + key_exchange_length,
            std::back_inserter(key_exchange_));
  p += key_exchange_length;
}

std::vector<uint8_t> KeyShareEntry::GetSharedKey() {
  return key_exchange_;
}

ECDH KeyShareEntry::GetECDH() { return ecdh_; }
} // namespace tls