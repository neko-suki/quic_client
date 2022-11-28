#ifndef QUIC_QUIC_FRAME_HPP_
#define QUIC_QUIC_FRAME_HPP_

#include <stdint.h>

namespace quic {

enum class QUICFrameType {
  ACK = 0x02,
  ACKECN = 0x03,
  CRYPTO = 0x06,
  STREAM = 0x08, // to be fixed. Stream should be 0x08..0x0f
  HANDSHAKE_DONE = 0x1e
};

class QUICFrame {
public:
  QUICFrame(QUICFrameType frame_type) : frame_type_(frame_type) {}
  virtual std::vector<uint8_t> GetBinary() = 0;
  virtual void Parse(std::vector<uint8_t> &buf, int &p) = 0;
  QUICFrameType FrameType() { return frame_type_; }
  QUICFrameType frame_type_;
};

} // namespace quic
#endif