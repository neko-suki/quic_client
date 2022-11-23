#include "handshake_done_frame.hpp"

namespace quic{
std::vector<uint8_t> HandshakeDoneFrame::GetBinary(){
    return std::vector<uint8_t>(1, 0x1e);
}

void HandshakeDoneFrame::Parse(std::vector<uint8_t> & buf, int & p){
    p++; // skip 0x1e
}
} // namespace
