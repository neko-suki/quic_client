#pragma once

#include <algorithm>
#include <vector>

#include "variable_length_integer.hpp"

namespace quic {
class ACKManager {
public:
  ACKManager();
  void AddACK(uint64_t ack_number);
  std::vector<uint8_t> GenFrameBinary();

private:
  uint64_t largest_acked_;
  // std::vector<std::pair<int,int>> unack_range; not implemented for the time
  // being.
};
} // namespace quic
