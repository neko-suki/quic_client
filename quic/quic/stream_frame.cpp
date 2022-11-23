#include "stream_frame.hpp"

#include <cstdio>
#include <string>

#include "parse_variable_length_integer.hpp"

namespace quic{

std::vector<uint8_t> StreamFrame::GetBinary(){
    return {};
}

void StreamFrame::Parse(std::vector<uint8_t> & buf, int & p){
    uint8_t type = buf[p];
    p++;
    stream_id_= parse_variable_length_integer(buf, p);
    /*
        The OFF bit (0x04) in the frame type is set to indicate that there is an Offset field present. When set to 1, the Offset field is present. When set to 0, the Offset field is absent and the Stream Data starts at an offset of 0 (that is, the frame contains the first bytes of the stream, or the end of a stream that includes no data).
        The LEN bit (0x02) in the frame type is set to indicate that there is a Length field present. If this bit is set to 0, the Length field is absent and the Stream Data field extends to the end of the packet. If this bit is set to 1, the Length field is present.
        The FIN bit (0x01) indicates that the frame marks the end of the stream. The final size of the stream is the sum of the offset and the length of this frame.
    */
    if (type & 0x04){
        offset_ = parse_variable_length_integer(buf, p);
    }
    if (type & 0x02){
        length_ = parse_variable_length_integer(buf, p);
    }
    std::copy(buf.begin()+p, buf.begin() + length_, std::back_inserter(stream_data_));
    printf("stream_id: %lu\n", stream_id_);
    std::string buf_string(buf.data() + p, buf.data() + p + length_);
    printf("=================================================================\n");
    printf("stream frame received. payload: %s\n", buf_string.c_str());
    printf("=================================================================\n");
    p += length_;

}


}
