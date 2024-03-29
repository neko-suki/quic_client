/*
      enum {
          /* Elliptic Curve Groups (ECDHE)
          secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
          x25519(0x001D), x448(0x001E),

          /* Finite Field Groups (DHE)
          ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
          ffdhe6144(0x0103), ffdhe8192(0x0104),

          /* Reserved Code Points
          ffdhe_private_use(0x01FC..0x01FF),
          ecdhe_private_use(0xFE00..0xFEFF),
          (0xFFFF)
      } NamedGroup;

      struct {
          NamedGroup group;
          opaque key_exchange<1..2^16-1>;
      } KeyShareEntry;

      struct {
          KeyShareEntry client_shares<0..2^16-1>;
      } KeyShareClientHello;
*/
#pragma once

#include <vector>

#include <stdint.h>

#include "ecdh.hpp"
#include "extension.hpp"
#include "key_share.hpp"

namespace tls {
class KeyShareServerHello : public Extension {
public:
  void Parse(std::vector<uint8_t> &buf, int &p);
  std::vector<uint8_t> GetBinary();
  std::vector<uint8_t> GetSharedKey();

private:
  KeyShareEntry server_share_;
};

} // namespace tls
