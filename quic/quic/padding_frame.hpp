#pragma once

#include <stdint.h>
#include <vector>

namespace quic {
std::vector<uint8_t> GeneratePaddingFrame(size_t size);
}
