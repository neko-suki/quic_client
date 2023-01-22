#pragma once

#include <iostream>

#include <string>
#include <vector>

namespace tls {

class Hash {
public:
  std::vector<uint8_t> ComputeHash(size_t hash_length,
                                   std::vector<uint8_t> &in);
};
} // namespace tls
