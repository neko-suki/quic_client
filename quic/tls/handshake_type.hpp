#pragma once

#include <stdint.h>

namespace tls {

enum class HandshakeType {
  client_hello = 1,
  server_hello = 2,
  encrypted_extensions = 8,
  certificate = 11,
  certificate_request = 13,
  certificate_verify = 15,
  finished = 20,
  key_update = 24,
  message_hash = 254,
};
}