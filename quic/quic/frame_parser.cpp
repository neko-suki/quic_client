#include "frame_parser.hpp"
#include "../tls/handshake.hpp"

#include "ack_frame.hpp"
#include "crypto_frame.hpp"
#include "handshake_done_frame.hpp"
#include "parse_variable_length_integer.hpp"
#include "quic_frame.hpp"
#include "stream_frame.hpp"

namespace quic {
std::unique_ptr<QUICFrame> FrameParser::Parse(std::vector<uint8_t> &buf,
                                              int &p) {
  std::unique_ptr<QUICFrame> ret;
  switch (buf[p]) {
  case 0x00: {
    uint32_t cnt = 0;
    while (p < buf.size() && buf[p] == 0) {
      cnt++;
      p++;
    }
    printf("PADDING Frame received. cnt: %u\n", p);
    break;
  }
  case 0x01:
    printf("PING Frame received\n");
    p++;
    break;
  case 0x02: {
    ret = std::make_unique<ACKFrame>();
    printf("ACK frame received\n");
    p++;
    ret->Parse(buf, p);
    break;
  }
  case 0x06: {
    ret = std::make_unique<CryptoFrame>();
    printf("CRYPTO frame received\n");
    p++;
    ret->Parse(buf, p);
    break;
  }
  case 0x08:
  case 0x09:
  case 0x0a:
  case 0x0b:
  case 0x0c:
  case 0x0d:
  case 0x0e:
  case 0x0f: {
    ret = std::make_unique<StreamFrame>();
    printf("STREAM frame received\n");
    ret->Parse(buf, p);

    break;
  }
  case 0x18: {
    printf("NEW_CONNECTION_ID frame received\n");
    p++; // type;
    uint64_t sequence_number = parse_variable_length_integer(buf.data(), p);
    uint64_t retire_prior_to = parse_variable_length_integer(buf.data(), p);
    uint8_t length = buf[p];
    p++;
    p += length;
    p += 16; // skip stateless reset token
  } break;
  case 0x1e: {
    ret = std::make_unique<HandshakeDoneFrame>();
    printf("HANDSHAKE_DONE frame received\n");
    ret->Parse(buf, p);
    break;
  }
  default:
    printf("unknown frame: %2x\n", buf[p]);
    std::exit(1);
    break;
  }
  return ret;
}

std::vector<std::unique_ptr<QUICFrame>>
FrameParser::ParseAll(std::vector<uint8_t> &buf) {
  int p = 0;
  std::vector<std::unique_ptr<QUICFrame>> ret;
  while (p < buf.size()) {
    ret.push_back(std::move(Parse(buf, p)));
  }
  return std::move(ret);
}

} // namespace quic
