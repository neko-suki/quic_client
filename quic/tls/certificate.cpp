#include "certificate.hpp"

namespace tls {

CertificateEntry::CertificateEntry() {}

void CertificateEntry::Parse(std::vector<uint8_t> &buf, int &p) {
  uint8_t certificate_type_ = buf[p];
  uint32_t length = 0;
  switch (certificate_type_) {
  case 0:
    // std::cout << "certificate_type: X509" << std::endl;
    length = (buf[p] << 16) | (buf[p + 1] << 8) | (buf[p + 2]);
    p += 3;
    // std::cout << "certificate length: " << length << std::endl;
    std::copy(buf.begin() + p, buf.begin() + p + length,
              std::back_inserter(cert_data_));
    p += length;
    break;
  case 2:
    // std::cout << "certificate_type: RawPublicKey" << std::endl;
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
  // std::cout << "extension_length: " << extension_length << std::endl;
  while (p < extension_length) {
    uint16_t extension_type = buf[p] << 8 | buf[p + 1];
    p += 2;
    // std::cout << "extention type: " << extension_type << std::endl;
    uint16_t extension_length = buf[p] << 8 | buf[p + 1];
    p += 2;
    // std::cout << "extention length: " << extension_length << std::endl;

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
  p += certificate_request_context_length;

  uint32_t certificate_list_length =
      (buf[p] << 16) | (buf[p + 1] << 8) | buf[p + 2];
  p += 3;
  certificate_entry_.Parse(buf, p);
  // p += certificate_list_length;
}

} // namespace tls
