/*
2MSB	Length	Usable Bits	Range
00	1	6	0-63
01	2	14	0-16383
10	4	30	0-1073741823
11	8	62	0-4611686018427387903
*/

#ifndef QUIC_VARIABLE_LENGTH_INTEGER_HPP_
#define QUIC_VARIABLE_LENGTH_INTEGER_HPP_

#include <cassert>
#include <stdint.h>
#include <vector>
#include <optional>


namespace quic {
class VariableLengthInteger {
public:
  VariableLengthInteger(int a);
  VariableLengthInteger(uint8_t a);
  VariableLengthInteger(uint64_t a);
  std::vector<uint8_t> GetBinary();
  void SetNumBytes(int32_t num_bytes);

  uint64_t val_;
  std::optional<int> num_bytes_;
};
} // namespace quic

#endif