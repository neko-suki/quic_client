#include "signature_algorithms.hpp"

namespace tls {

SignatureAlgorithms::SignatureAlgorithms() {
  extension_type_ = ExtentionType::signature_algorithms;
}

std::vector<uint8_t> SignatureAlgorithms::GetBinary() {
  std::vector<uint8_t> ret;
  // type: 000d
  ret.push_back(static_cast<uint16_t>(extension_type_) >> 4);
  ret.push_back(static_cast<uint16_t>(extension_type_) & 0xff);

  std::vector<uint8_t> tmp;
  tmp.push_back(0x00);
  tmp.push_back(0x02);

  //  ecdsa_secp256r1_sha256(0x0403),
  tmp.push_back(0x04);
  tmp.push_back(0x03);

  // length
  ret.push_back(static_cast<uint8_t>((tmp.size() & 0xff00) >> 8));
  ret.push_back(static_cast<uint8_t>(tmp.size() & 0xff));

  std::copy(tmp.begin(), tmp.end(), std::back_inserter(ret));
  return ret;
}
} // namespace tls