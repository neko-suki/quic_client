/*
HANDSHAKE_DONE Frame {
  Type (i) = 0x1e,
}
*/
#pragma once

#include <stdint.h>
#include <vector>

#include "quic_frame.hpp"

namespace quic {
class HandshakeDoneFrame : public QUICFrame {
public:
  HandshakeDoneFrame() : QUICFrame(QUICFrameType::HANDSHAKE_DONE) {}
  std::vector<uint8_t> GetBinary();
  void Parse(std::vector<uint8_t> &buf, int &p);

private:
};
} // namespace quic
