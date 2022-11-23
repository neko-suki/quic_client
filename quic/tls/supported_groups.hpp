/*
https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.7
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
          NamedGroup named_group_list<2..2^16-1>;
      } NamedGroupList;
*/
#ifndef TLS_SUPPORTED_GROUPS_HPP_
#define TLS_SUPPORTED_GROUPS_HPP_
#include <stdint.h>
#include <vector>

#include "extension.hpp"

namespace tls {

class NamedGroupList : public Extension {
public:
  NamedGroupList();
  std::vector<uint8_t> GetBinary();
  std::vector<uint8_t> named_group_list;
};
} // namespace tls
#endif