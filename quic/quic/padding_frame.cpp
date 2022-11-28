#include "padding_frame.hpp"

namespace quic {
std::vector<uint8_t> GeneratePaddingFrame(size_t size) {
  return std::vector<uint8_t>(size, 0);
}
} // namespace quic
