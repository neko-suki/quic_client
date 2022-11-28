#include "ack_manager.hpp"

namespace quic {
ACKManager::ACKManager() : largest_acked_(0) {}

void ACKManager::AddACK(uint64_t ack_number) {
  largest_acked_ = std::max(largest_acked_, ack_number);
}

std::vector<uint8_t> ACKManager::GenFrameBinary() {
  std::vector<uint8_t> ack_frame_binary;
  ack_frame_binary.push_back(0x02); // no ECN

  // largest_acked
  VariableLengthInteger largest_acked(largest_acked_);
  std::vector<uint8_t> largest_acked_binary = largest_acked.GetBinary();
  std::copy(largest_acked_binary.begin(), largest_acked_binary.end(),
            std::back_inserter(ack_frame_binary));

  // ack delay
  VariableLengthInteger ack_delay(991);
  std::vector<uint8_t> ack_delay_binary = ack_delay.GetBinary();
  std::copy(ack_delay_binary.begin(), ack_delay_binary.end(),
            std::back_inserter(ack_frame_binary));

  // ack_range_count
  VariableLengthInteger ack_range_count(0);
  std::vector<uint8_t> ack_range_count_binary = ack_range_count.GetBinary();
  std::copy(ack_range_count_binary.begin(), ack_range_count_binary.end(),
            std::back_inserter(ack_frame_binary));

  // first_ack_range
  VariableLengthInteger first_ack_range(0);
  std::vector<uint8_t> first_ack_range_binary = first_ack_range.GetBinary();
  std::copy(first_ack_range_binary.begin(), first_ack_range_binary.end(),
            std::back_inserter(ack_frame_binary));

  return ack_frame_binary;
}

} // namespace quic
