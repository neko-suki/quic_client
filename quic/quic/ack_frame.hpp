#ifndef QUIC_ACK_FRAME_HPP_
#define QUIC_ACK_FRAME_HPP_

#include <stdint.h>

#include <vector>

#include "quic_frame.hpp"

namespace quic {

typedef struct {
  uint64_t gap;
  uint64_t ack_range_length;
} ACKRange;

class ACKFrame : public QUICFrame {
public:
  ACKFrame();
  std::vector<uint8_t> GetBinary();
  void Parse(std::vector<uint8_t> &buf, int &p);
  uint64_t LargestAcknowledged();

private:
  uint64_t largeet_acknowledged_;
  uint64_t ack_delay_;
  uint64_t ack_range_count_;
  uint64_t first_ack_range_;
  std::vector<ACKRange> ack_range_;
};

} // namespace quic
#endif