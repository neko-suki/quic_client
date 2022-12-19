/*
https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.1
Implementations of this specification MUST send this extension in the
   ClientHello containing all versions of TLS which they are prepared to
   negotiate (for this specification, that means minimally 0x0304, but
   if previous versions of TLS are allowed to be negotiated, they MUST
   be present as well).

uint16 ProtocolVersion;

struct {
    select (Handshake.msg_type) {
        case client_hello:
            ProtocolVersion versions<2..254>;

        case server_hello: /* and HelloRetryRequest
            ProtocolVersion selected_version;
    };
} SupportedVersions;
*/

#include "supported_version.hpp"

namespace tls {
SupportedVersions::SupportedVersions() {
  extension_type_ = ExtentionType::supported_versions;
}

std::vector<uint8_t> SupportedVersions::GetBinary() {
  std::vector<uint8_t> ret;
  // type: 0043 = 0x002b = 16*2 + 11
  ret.push_back(0x00);
  ret.push_back(0x2b);

  // length of extension
  ret.push_back(0x00);
  ret.push_back(0x03);

  // length of versions
  ret.push_back(0x02);

  // 0x0304 = TLS 1.3
  ret.push_back(0x03);
  ret.push_back(0x04);

  return ret;
}
} // namespace tls
