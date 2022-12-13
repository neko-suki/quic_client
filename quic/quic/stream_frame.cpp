#include "stream_frame.hpp"

#include <cstdio>
#include <string>

#include "parse_variable_length_integer.hpp"
#include "variable_length_integer.hpp"

namespace quic {

void StreamFrame::AddPayload(std::string &in) {
  std::copy(in.begin(), in.end(), std::back_inserter(stream_data_));
}

void StreamFrame::SetStreamID(uint64_t stream_id) {
  stream_id_ = stream_id;
}

void StreamFrame::SetFin() { is_fin_ = true; }

/*
    The OFF bit (0x04) in the frame type is set to indicate that there is
   an Offset field present. When set to 1, the Offset field is present.
   When set to 0, the Offset field is absent and the Stream Data starts at
   an offset of 0 (that is, the frame contains the first bytes of the
   stream, or the end of a stream that includes no data). The LEN bit
   (0x02) in the frame type is set to indicate that there is a Length field
   present. If this bit is set to 0, the Length field is absent and the
   Stream Data field extends to the end of the packet. If this bit is set
   to 1, the Length field is present. The FIN bit (0x01) indicates that the
   frame marks the end of the stream. The final size of the stream is the
   sum of the offset and the length of this frame.
*/
std::vector<uint8_t> StreamFrame::GetBinary() {
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
  VariableLengthInteger length(stream_data_.size());

  std::vector<uint8_t> stream_payload;
  stream_payload.push_back(frame_type);
  VariableLengthInteger stream_id_v(stream_id_);
  std::vector<uint8_t> stream_id_binary = stream_id_v.GetBinary();
  std::copy(stream_id_binary.begin(), stream_id_binary.end(),
            std::back_inserter(stream_payload));
  std::vector<uint8_t> length_binary = length.GetBinary();
  std::copy(length_binary.begin(), length_binary.end(),
            std::back_inserter(stream_payload));
  std::copy(stream_data_.begin(), stream_data_.end(),
            std::back_inserter(stream_payload));
  return stream_payload;
}

void StreamFrame::Parse(std::vector<uint8_t> &buf, int &p) {
  uint8_t type = buf[p];
  p++;
  stream_id_ = parse_variable_length_integer(buf, p);
  /*
      The OFF bit (0x04) in the frame type is set to indicate that there is
     an Offset field present. When set to 1, the Offset field is present.
     When set to 0, the Offset field is absent and the Stream Data starts
     at an offset of 0 (that is, the frame contains the first bytes of the
     stream, or the end of a stream that includes no data). The LEN bit
     (0x02) in the frame type is set to indicate that there is a Length
     field present. If this bit is set to 0, the Length field is absent and
     the Stream Data field extends to the end of the packet. If this bit is
     set to 1, the Length field is present. The FIN bit (0x01) indicates
     that the frame marks the end of the stream. The final size of the
     stream is the sum of the offset and the length of this frame.
  */
  if (type & 0x04) {
    offset_ = parse_variable_length_integer(buf, p);
  }
  if (type & 0x02) {
    length_ = parse_variable_length_integer(buf, p);
  }
  std::copy(buf.begin() + p, buf.begin() + p + length_,
            std::back_inserter(stream_data_));
  p += length_;
}

std::vector<uint8_t> StreamFrame::stream_data() { return stream_data_; }

} // namespace quic
