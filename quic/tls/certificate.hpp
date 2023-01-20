/*
      enum {
          X509(0),
          RawPublicKey(2),
          (255)
      } CertificateType;

      struct {
          select (certificate_type) {
              case RawPublicKey:
                /* From RFC 7250 ASN.1_subjectPublicKeyInfo
                opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

              case X509:
                opaque cert_data<1..2^24-1>;
          };
          Extension extensions<0..2^16-1>;
      } CertificateEntry;

      struct {
          opaque certificate_request_context<0..2^8-1>;
          CertificateEntry certificate_list<0..2^24-1>;
      } Certificate;
*/

#ifndef TLS_CERTIFICATE_HPP_
#define TLS_CERTIFICATE_HPP_

#include <vector>

#include <stdint.h>

#include "handshake_type.hpp"

namespace tls {

class CertificateEntry {
public:
  CertificateEntry();
  void Parse(std::vector<uint8_t> &buf, int &p);
  uint8_t certificate_type_;
  std::vector<uint8_t> cert_data_;
};

class Certificate {
public:
  Certificate();
  void Parse(std::vector<uint8_t> &buf, int &p);
  CertificateEntry certificate_entry_;
};

} // namespace tls
#endif // TLS_CERTIFICATE_HPP_