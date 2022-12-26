#include <string>

#include "server_name.hpp"

namespace tls {
ServerName::ServerName() {
  extension_type_ = ExtentionType::server_name;
}

std::vector<uint8_t> ServerName::GetBinary() {
  std::vector<uint8_t> ret;
  // type: 0000 server_name
  ret.push_back(static_cast<uint16_t>(extension_type_) >> 8);
  ret.push_back(static_cast<uint16_t>(extension_type_) & 0xff);

  std::vector<uint8_t> buf;
  // name_type: hostname
  buf.push_back(0x00);

  std::string server_name = "localhost";

  // length of server_Name
  buf.push_back(static_cast<uint8_t>((server_name.size() & 0xff00) >> 8));
  buf.push_back(static_cast<uint8_t>(server_name.size() & 0xff));

  std::copy(server_name.begin(), server_name.end(),
            std::back_inserter(buf));

  std::vector<uint8_t> tmp;
  tmp.push_back(static_cast<uint8_t>((buf.size() & 0xff00) >> 8));
  tmp.push_back(static_cast<uint8_t>(buf.size() & 0xff));

  std::copy(buf.begin(), buf.end(), std::back_inserter(tmp));

  ret.push_back(static_cast<uint8_t>((tmp.size() & 0xff00) >> 8));
  ret.push_back(static_cast<uint8_t>(tmp.size() & 0xff));

  std::copy(tmp.begin(), tmp.end(), std::back_inserter(ret));

  return ret;
}
} // namespace tls