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

#pragma once

#include <vector>

#include <stdint.h>

#include "handshake.hpp"
#include "handshake_type.hpp"

namespace tls {

enum class CertificateType {
  X509 = 0,
  RawPublicKey = 2,
};

class CertificateEntry {
public:
  void Parse(std::vector<uint8_t> &buf, int &p);

private:
  CertificateType certificate_type_;
  std::vector<uint8_t> cert_data_;
};

class Certificate : public Handshake {
public:
  void Parse(std::vector<uint8_t> &buf, int &p);

private:
  std::vector<CertificateEntry> certificate_entry_;
  std::vector<uint8_t> certificate_request_context_;
};

} // namespace tls
