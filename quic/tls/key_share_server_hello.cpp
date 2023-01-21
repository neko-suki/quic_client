#include "key_share_server_hello.hpp"

namespace tls {
void KeyShareServerHello::Parse(std::vector<uint8_t> &buf, int &p) {
  server_share_.Parse(buf, p);
}

std::vector<uint8_t> KeyShareServerHello::GetBinary() { return {}; }

std::vector<uint8_t> KeyShareServerHello::GetSharedKey() {
  return server_share_.GetSharedKey();

}
} // namespace tls