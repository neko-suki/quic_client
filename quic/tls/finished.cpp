#include "finished.hpp"

namespace tls {

void Finished::Parse(std::vector<uint8_t> &buf, int &p) {
  hash_length_ = 32; // 256 bit -> 256/8 = 32 byte
  std::copy(buf.begin() + p, buf.begin() + p + 32,
            std::back_inserter(verify_data_));
  p += 32;
}

std::vector<uint8_t> Finished::GetVerifyData() const {
  return verify_data_;
}
} // namespace tls
