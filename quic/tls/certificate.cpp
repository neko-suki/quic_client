#include "certificate.hpp"

namespace tls {

void CertificateEntry::Parse(std::vector<uint8_t> &buf, int &p) {
  certificate_type_ = static_cast<CertificateType>(buf[p]);
  uint32_t length = 0;
  switch (certificate_type_) {
  case CertificateType::X509:
    // X509
    length = (buf[p] << 16) | (buf[p + 1] << 8) | (buf[p + 2]);
    p += 3;
    std::copy(buf.begin() + p, buf.begin() + p + length,
              std::back_inserter(cert_data_));
    p += length;
    break;
  case CertificateType::RawPublicKey:
    // RawPublicKey
    length = (buf[p] << 16) | (buf[p + 1] << 8) | (buf[p]);
    p += 3;
    std::copy(buf.begin() + p, buf.begin() + p + length,
              std::back_inserter(cert_data_));
    p += length;
    break;
  default:
    break;
  }

  // extension
  uint32_t extension_length = (buf[p] << 8) | (buf[p + 1]);
  p += 2;
  while (p < extension_length) {
    uint16_t extension_type = buf[p] << 8 | buf[p + 1];
    p += 2;
    uint16_t extension_length = buf[p] << 8 | buf[p + 1];
    p += 2;

    switch (extension_type) {
    default:
      printf("extension not implemented: %d\n", extension_type);
      p += extension_length;
      break;
    }
  }
}

void Certificate::Parse(std::vector<uint8_t> &buf, int &p) {
  msg_type_ = static_cast<HandshakeType>(buf[p]);
  p++;    // msg_type;
  p += 3; // skip length

  uint8_t certificate_request_context_length = buf[p];
  p++;
  std::copy(buf.begin() + p,
            buf.begin() + p + certificate_request_context_length,
            std::back_inserter(certificate_request_context_));
  p += certificate_request_context_length;

  uint32_t certificate_list_length =
      (buf[p] << 16) | (buf[p + 1] << 8) | buf[p + 2];
  p += 3;
  int p_end = p + certificate_list_length;
  while (p < p_end) {
    CertificateEntry tmp;
    tmp.Parse(buf, p);
    certificate_entry_.emplace_back(tmp);
  }
}

} // namespace tls
