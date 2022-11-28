#include "stream_manager.hpp"

namespace quic {

Stream::Stream(uint64_t id) : stream_id_(id) {}

void Stream::AddPayload(std::string &in) {
  std::copy(in.begin(), in.end(), std::back_inserter(payload_));
}

void Stream::SetFin() { is_fin_ = true; }

/*
    The OFF bit (0x04) in the frame type is set to indicate that there is an
   Offset field present. When set to 1, the Offset field is present. When set to
   0, the Offset field is absent and the Stream Data starts at an offset of 0
   (that is, the frame contains the first bytes of the stream, or the end of a
   stream that includes no data). The LEN bit (0x02) in the frame type is set to
   indicate that there is a Length field present. If this bit is set to 0, the
   Length field is absent and the Stream Data field extends to the end of the
   packet. If this bit is set to 1, the Length field is present. The FIN bit
   (0x01) indicates that the frame marks the end of the stream. The final size
   of the stream is the sum of the offset and the length of this frame.
*/
std::vector<uint8_t> Stream::GetPayload() {
  // assume that using padding if need.
  uint8_t frame_type = 0x08;
  // need OFF bit?
  // Do nothing for the time being

  // need LEN bit? -> need padding
  // always set length for the time being.
  frame_type |= 0x02;

  // need FIN bit?
  if (is_fin_) {
    frame_type |= 0x01;
  }
  VariableLengthInteger length(payload_.size());

  std::vector<uint8_t> stream_payload;
  stream_payload.push_back(frame_type);
  std::vector<uint8_t> stream_id_binary = stream_id_.GetBinary();
  std::copy(stream_id_binary.begin(), stream_id_binary.end(),
            std::back_inserter(stream_payload));
  std::vector<uint8_t> length_binary = length.GetBinary();
  std::copy(length_binary.begin(), length_binary.end(),
            std::back_inserter(stream_payload));
  std::copy(payload_.begin(), payload_.end(),
            std::back_inserter(stream_payload));
  return stream_payload;
}

StreamManager::StreamManager() : client_initiated_bidirectional_stream_id_(0) {}

Stream StreamManager::CreateClientInitiatedBidirectionalStream() {
  /*
      Bits	Stream Type
      0x00	Client-Initiated, Bidirectional
      0x01	Server-Initiated, Bidirectional
      0x02	Client-Initiated, Unidirectional
      0x03	Server-Initiated, Unidirectional
  */
  return Stream((client_initiated_bidirectional_stream_id_++) << 2);
}

} // namespace quic