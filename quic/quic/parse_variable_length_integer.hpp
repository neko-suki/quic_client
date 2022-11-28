#ifndef QUIC_PARSE_VARIABLE_LENGTH_INTEGER_HPP_
#define QUIC_PARSE_VARIABLE_LENGTH_INTEGER_HPP_

#include <vector>

#include <stdint.h>

namespace quic {
uint64_t parse_variable_length_integer(unsigned char *buf, int &p);
uint64_t parse_variable_length_integer(std::vector<uint8_t> &buf, int &p);
} // namespace quic

#endif // QUIC_PARSE_VARIABLE_LENGTH_INTEGER_HPP_