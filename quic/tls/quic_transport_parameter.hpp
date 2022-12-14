/*
https://www.rfc-editor.org/rfc/rfc9001.html#section-8.2
   enum {
      quic_transport_parameters(0x39), (65535)
   } ExtensionType;
*/

#pragma once
#include <vector>

#include <stdint.h>

#include "../quic/variable_length_integer.hpp"
#include "extension.hpp"

namespace tls {
class QUICTransportParameter : public Extension {
public:
  QUICTransportParameter();
  void SetInitialSourceConnectionID(
      std::vector<uint8_t> &initial_source_connection_id);
  std::vector<uint8_t> GetBinary();

private:
  std::vector<uint8_t> scid_;
};
} // namespace tls
