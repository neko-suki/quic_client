#pragma once

#include <memory>

#include "ack_frame.hpp"
#include "crypto_frame.hpp"
#include "parse_variable_length_integer.hpp"
#include "quic_frame.hpp"

namespace quic {

class FrameParser {
public:
  std::vector<std::unique_ptr<QUICFrame>>
  ParseAll(std::vector<uint8_t> &buf);
private:
  std::unique_ptr<QUICFrame> Parse(std::vector<uint8_t> &buf, int &p);
};
} // namespace quic
