#include "supported_groups.hpp"

namespace tls {

NamedGroupList::NamedGroupList() {
}

std::vector<uint8_t> NamedGroupList::GetBinary() {
  std::vector<uint8_t> ret;
  // supported_groups(0x0010)
  ret.push_back(0x00);
  ret.push_back(0x0a);
  // length
  ret.push_back(0x00);
  ret.push_back(0x04);

  // secp256r1(0x0017),
  named_group_list.push_back(0x00);
  named_group_list.push_back(0x17);

  // size of named curve list: 0x002
  ret.push_back(0x00);
  ret.push_back(named_group_list.size());

  std::copy(named_group_list.begin(), named_group_list.end(),
            std::back_inserter(ret));
  return ret;
}
} // namespace tls