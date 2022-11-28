#include "stream_manager.hpp"

#include "stream_frame.hpp"

namespace quic {
StreamManager::StreamManager() : client_initiated_bidirectional_stream_id_(0) {}

StreamFrame StreamManager::CreateClientInitiatedBidirectionalStream() {
  /*
      Bits	Stream Type
      0x00	Client-Initiated, Bidirectional
      0x01	Server-Initiated, Bidirectional
      0x02	Client-Initiated, Unidirectional
      0x03	Server-Initiated, Unidirectional
  */
  StreamFrame tmp;
  tmp.SetStreamID((client_initiated_bidirectional_stream_id_++) << 2);
  return tmp;
}

} // namespace quic