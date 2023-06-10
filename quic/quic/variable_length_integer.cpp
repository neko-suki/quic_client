#include "variable_length_integer.hpp"

#include <iostream>

namespace quic {
VariableLengthInteger::VariableLengthInteger(int a) : val_(a) {}
VariableLengthInteger::VariableLengthInteger(uint8_t a) : val_(a) {}
VariableLengthInteger::VariableLengthInteger(uint64_t a) : val_(a) {}

std::vector<uint8_t> VariableLengthInteger::GetBinary() {
  std::vector<uint8_t> ret;
  int len = 0;
  uint8_t array[4];
  if (val_ <= 63) {
    len = 1;
    array[0] = static_cast<uint8_t>(val_);
  } else if (val_ <= 16383) {
    len = 2;
    array[0] = 0b0100'0000;
    array[0] |= static_cast<uint8_t>(val_ >> 8);
    array[1] = static_cast<uint8_t>(val_ & (0xff));
  } else if (val_ <= 1073741823) {
    len = 4;
    array[0] = 0b1000'0000;
    array[0] |= static_cast<uint8_t>(val_ >> 24);
    array[1] = static_cast<uint8_t>((val_ >> 16) & 0xff);
    array[2] = static_cast<uint8_t>((val_ >> 8) & 0xff);
    array[3] = static_cast<uint8_t>(val_ & 0xff);
  } else {
    assert("not implemented");
    len = 8;
    array[0] = 0b1100'0000;
    array[0] |= static_cast<uint8_t>(val_ >> 24);
    array[1] = static_cast<uint8_t>((val_ >> 16) & 0xff);
    array[2] = static_cast<uint8_t>((val_ >> 8) & 0xff);
    array[3] = static_cast<uint8_t>(val_ & 0xff);
  }
  for (int i = 0; i < len; i++) {
    ret.push_back(array[i]);
  }
  if (!num_bytes_.has_value()){
    return ret;
  }
  for(int i = 0;i < ret.size() - num_bytes_.value();i++){
    ret[i] = ret[i+num_bytes_.value()];
  }
  ret.resize(num_bytes_.value());
  return ret;
}

void VariableLengthInteger::SetNumBytes(int32_t num_bytes){
  num_bytes_ = num_bytes;
}

} // namespace quic
