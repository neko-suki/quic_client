#include <string>

#include "server_name.hpp"

namespace tls {
ServerName::ServerName() {
  extension_type_ = ExtentionType::supported_versions;
}

std::vector<uint8_t> ServerName::GetBinary() {
  std::vector<uint8_t> ret;
  // type: 0000 server_name
  ret.push_back(0x00);
  ret.push_back(0x00);

  std::vector<uint8_t> buf;
  // name_type: hostname
  buf.push_back(0x00);
  std::string server_name = "localhost";
  uint8_t server_name_length[2] = {
      static_cast<uint8_t>((server_name.size() & 0xff00) >> 8),
      static_cast<uint8_t>(server_name.size() & 0xff)};
  std::copy(server_name_length, server_name_length + 2,
            std::back_inserter(buf));

  std::copy(server_name.begin(), server_name.end(),
            std::back_inserter(buf));

  uint8_t length[2] = {static_cast<uint8_t>((buf.size() & 0xff00) >> 8),
                       static_cast<uint8_t>(buf.size() & 0xff)};

  std::vector<uint8_t> tmp;
  std::copy(length, length + 2, std::back_inserter(tmp));
  std::copy(buf.begin(), buf.end(), std::back_inserter(tmp));

  uint8_t tmp_length[2] = {
      static_cast<uint8_t>((tmp.size() & 0xff00) >> 8),
      static_cast<uint8_t>(tmp.size() & 0xff)};
  for (int i = 0; i < 2; i++) {
    ret.push_back(tmp_length[i]);
  }
  std::copy(tmp.begin(), tmp.end(), std::back_inserter(ret));

  return ret;
}
} // namespace tls