#include "alpn.hpp"

#include <iostream>

namespace tls {
ALPN::ALPN() {
  extension_type_ = ExtentionType::application_layer_protocol_negotiation;
}

std::vector<uint8_t> ALPN::GetBinary() {
  std::vector<uint8_t> ret;
  // type: 0016 alpn
  ret.push_back(static_cast<uint16_t>(extension_type_) >> 8);
  ret.push_back(static_cast<uint16_t>(extension_type_) & 0xff);

  std::vector<std::string> protocol_name_list;
  protocol_name_list.push_back("h3");

  std::vector<uint8_t> buf;
  for (const auto &protocol_name : protocol_name_list) {
    buf.push_back(static_cast<uint8_t>(protocol_name.size() & 0xff));
    std::copy(protocol_name.begin(), protocol_name.end(),
              std::back_inserter(buf));
  }

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