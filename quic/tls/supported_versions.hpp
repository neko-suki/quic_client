/*
https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.1
Implementations of this specification MUST send this extension in the
   ClientHello containing all versions of TLS which they are prepared to
   negotiate (for this specification, that means minimally 0x0304, but
   if previous versions of TLS are allowed to be negotiated, they MUST
   be present as well).

    struct {
        select (Handshake.msg_type) {
            case client_hello:
                ProtocolVersion versions<2..254>;

            case server_hello: /* and HelloRetryRequest
                ProtocolVersion selected_version;
        };
    } SupportedVersions;
*/
#pragma once
#include <vector>

#include <stdint.h>

#include "extension.hpp"

namespace tls {
class SupportedVersions : public Extension {
public:
  SupportedVersions();
  std::vector<uint8_t> GetBinary();
};
} // namespace tls
