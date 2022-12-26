/*
https://www.rfc-editor.org/rfc/rfc6066#section-3
   enum {
       application_layer_protocol_negotiation(16), (65535)
   } ExtensionType;

   The "extension_data" field of the
   ("application_layer_protocol_negotiation(16)") extension SHALL
   contain a "ProtocolNameList" value.

   opaque ProtocolName<1..2^8-1>;

   struct {
       ProtocolName protocol_name_list<2..2^16-1>
   } ProtocolNameList;

*/
#pragma once
#include <string>
#include <vector>

#include <stdint.h>

#include "extension.hpp"

namespace tls {
class ALPN : public Extension {
public:
  ALPN();
  std::vector<uint8_t> GetBinary();
};
} // namespace tls
