#pragma once

#include <string>

#include <stdint.h>

#include "stream_frame.hpp"
#include "variable_length_integer.hpp"

namespace quic {
class StreamManager {
public:
  StreamManager();
  StreamFrame CreateClientInitiatedBidirectionalStream();

private:
  uint64_t client_initiated_bidirectional_stream_id_;
};
} // namespace quic