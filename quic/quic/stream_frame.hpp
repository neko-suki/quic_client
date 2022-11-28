#pragma once
#include <stdint.h>

#include <vector>

#include "quic_frame.hpp"

namespace quic {

class StreamFrame : public QUICFrame {
public:
  StreamFrame() : QUICFrame(QUICFrameType::STREAM) {}
  std::vector<uint8_t> GetBinary();
  void Parse(std::vector<uint8_t> &buf, int &p);
  std::vector<uint8_t> stream_data();

private:
  uint64_t stream_id_;
  uint64_t offset_;
  uint64_t length_;
  std::vector<uint8_t> stream_data_;
};

} // namespace quic
