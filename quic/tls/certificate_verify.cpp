#include "certificate_verify.hpp"

namespace tls {

CertificateVerify::CertificateVerify() {}

void CertificateVerify::Parse(std::vector<uint8_t> &buf, int &p) {
  uint16_t status_scheme = (buf[p] << 8) | buf[p + 1];
  p += 2;
  uint16_t length = (buf[p] << 8) | buf[p + 1];
  p += 2;
  std::copy(buf.begin() + p, buf.begin() + p + length,
            std::back_inserter(signature));
  p += length;
}
} // namespace tls
