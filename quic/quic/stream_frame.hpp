#pragma once
#include <stdint.h>

#include <string>
#include <vector>

#include "quic_frame.hpp"

namespace quic {

class StreamFrame : public QUICFrame {
public:
  StreamFrame() : QUICFrame(QUICFrameType::STREAM) {}
  void AddPayload(std::string &in);
  void SetStreamID(uint64_t stream_id);
  void SetFin();
  std::vector<uint8_t> GetBinary();
  void Parse(std::vector<uint8_t> &buf, int &p);
  std::vector<uint8_t> stream_data();
  uint64_t GetStreamID();
  void AddPayload(std::vector<uint8_t> & in);

private:
  uint64_t stream_id_;
  uint64_t offset_;
  uint64_t length_;
  std::vector<uint8_t> stream_data_;
  bool is_fin_;
};

} // namespace quic
