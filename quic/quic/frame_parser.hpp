#ifndef QUIC_PARSE_FRAME_HPP_
#define QUIC_PARSE_FRAME_HPP_

#include <memory>

#include "../tls/handshake.hpp"

#include "ack_frame.hpp"
#include "crypto_frame.hpp"
#include "parse_variable_length_integer.hpp"
#include "quic_frame.hpp"

namespace quic {

class FrameParser {
public:
  std::unique_ptr<QUICFrame> Parse(std::vector<uint8_t> &buf, int &p);
  std::vector<std::unique_ptr<QUICFrame>>
  ParseAll(std::vector<uint8_t> &buf);
};
} // namespace quic

#endif // QUIC_PARSE_FRAME_HPP_