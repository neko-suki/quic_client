#include "parse_variable_length_integer.hpp"

namespace quic {
uint64_t parse_variable_length_integer(unsigned char *buf, int &p) {
  uint64_t length;
  int msb_2bit = ((buf[p] & 0xc0)) >> 6;

  if (msb_2bit == 0) {
    // length = 1
    length = buf[p] & 0x3f;
    p++;
  } else if (msb_2bit == 1) {
    length = ((buf[p] & 0x3f) << 8) | (buf[p + 1]);
    p += 2;
  } else if (msb_2bit == 2) {
    length = ((buf[p] & 0x3f) << 24) | (buf[p + 1] << 16) | (buf[p + 2] << 8) |
             (buf[p + 3]);
    p += 4;
  } else if (msb_2bit == 3) {
    length = ((unsigned long long)(buf[p] & 0x3f) << 56) |
             ((unsigned long long)(buf[p + 1]) << 48) |
             ((unsigned long long)(buf[p + 2]) << 40) |
             ((unsigned long long)(buf[p + 3]) << 32) |
             ((buf[p + 4] & 0x3f) << 24) | (buf[p + 5] << 16) |
             (buf[p + 6] << 8) | (buf[p + 7]);
    p += 8;
  }
  return length;
}

uint64_t parse_variable_length_integer(std::vector<uint8_t> &buf, int &p) {
  return parse_variable_length_integer(buf.data(), p);
}
} // namespace quic
