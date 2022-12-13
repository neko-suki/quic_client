#include "ack_frame.hpp"

#include <iostream>

#include "parse_variable_length_integer.hpp"

namespace quic {
ACKFrame::ACKFrame() : QUICFrame(QUICFrameType::ACK) {}

std::vector<uint8_t> ACKFrame::GetBinary() {
  return std::vector<uint8_t>();
}

void ACKFrame::Parse(std::vector<uint8_t> &buf, int &p) {
  larget_acknowledged_ = parse_variable_length_integer(buf.data(), p);
  // std::cout <<"largest_acknowledged:  " << larget_acknowledged_ <<
  // std::endl;
  ack_delay_ = parse_variable_length_integer(buf.data(), p);
  // std::cout <<"ack_delay: " << ack_delay_ << std::endl;
  ack_range_count_ = parse_variable_length_integer(buf.data(), p);
  // std::cout <<"ack_range_count: " << ack_range_count_ << std::endl;
  first_ack_range_ = parse_variable_length_integer(buf.data(), p);
  // std::cout <<"first_ack_range: " << first_ack_range_ << std::endl;
  for (int i = 0; i < ack_range_count_; i++) {
    ACKRange ack_range;
    ack_range.gap = parse_variable_length_integer(buf.data(), p);
    // std::cout <<"gap: " << ack_range.gap << std::endl;
    ack_range.ack_range_length =
        parse_variable_length_integer(buf.data(), p);
    // std::cout <<"ack_range_length: " << ack_range.ack_range_length <<
    // std::endl;
  }
}

} // namespace quic