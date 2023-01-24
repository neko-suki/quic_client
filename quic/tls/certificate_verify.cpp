#include "certificate_verify.hpp"

namespace tls {

void CertificateVerify::Parse(std::vector<uint8_t> &buf, int &p) {
  msg_type_ = static_cast<HandshakeType>(buf[p]);
  p++;    // msg_type;
  p += 3; // skip length
  algorithm_ = (buf[p] << 8) | buf[p + 1];
  p += 2;
  uint16_t length = (buf[p] << 8) | buf[p + 1];
  p += 2;
  std::copy(buf.begin() + p, buf.begin() + p + length,
            std::back_inserter(signature_));
  p += length;
}
} // namespace tls
