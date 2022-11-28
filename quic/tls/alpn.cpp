#include "alpn.hpp"

namespace tls {
std::vector<uint8_t> ALPN::GetBinary() {
  std::vector<std::string> protocol_name_list;
  protocol_name_list.push_back("h3");

  std::vector<uint8_t> ret;
  // type: 0016 alpn
  ret.push_back(0x00);
  ret.push_back(0x10);

  std::vector<uint8_t> buf;

  for (const auto &protocol_name : protocol_name_list) {
    uint8_t protocol_name_length[1] = {
        static_cast<uint8_t>(protocol_name.size() & 0xff)};
    std::copy(protocol_name_length, protocol_name_length + 1,
              std::back_inserter(buf));
    std::copy(protocol_name.begin(), protocol_name.end(),
              std::back_inserter(buf));
  }

  uint8_t buf_length[2] = {static_cast<uint8_t>((buf.size() & 0xff00) >> 8),
                           static_cast<uint8_t>(buf.size() & 0xff)};

  std::vector<uint8_t> extension;
  for (int i = 0; i < 2; i++) {
    extension.push_back(buf_length[i]);
  }
  std::copy(buf.begin(), buf.end(), std::back_inserter(extension));

  uint8_t alpn_extentino_length[2] = {
      static_cast<uint8_t>((extension.size() & 0xff00) >> 8),
      static_cast<uint8_t>(extension.size() & 0xff)};

  for (int i = 0; i < 2; i++) {
    ret.push_back(alpn_extentino_length[i]);
  }
  std::copy(extension.begin(), extension.end(), std::back_inserter(ret));

  return ret;
}
} // namespace tls