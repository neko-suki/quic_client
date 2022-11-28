#ifndef QUIC_PADDING_FRAME_HPP_
#define QUIC_PADDING_FRAME_HPP_

#include <stdint.h>
#include <vector>

namespace quic {
std::vector<uint8_t> GeneratePaddingFrame(size_t size);
}
#endif // QUIC_PADDING_FRAME_HPP_