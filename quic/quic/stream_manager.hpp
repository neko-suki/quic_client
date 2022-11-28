#pragma once

#include "variable_length_integer.hpp"

#include <string>

#include <stdint.h>

namespace quic {

class Stream {
public:
  Stream(uint64_t id);
  void AddPayload(std::string &in);
  void SetFin();
  std::vector<uint8_t> GetPayload();

private:
  VariableLengthInteger stream_id_;
  std::vector<uint8_t> payload_;
  bool is_fin_;
};

class StreamManager {
public:
  StreamManager();
  Stream CreateClientInitiatedBidirectionalStream();

private:
  uint64_t client_initiated_bidirectional_stream_id_;
};
} // namespace quic