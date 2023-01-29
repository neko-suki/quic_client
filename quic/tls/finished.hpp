/*
    struct {
        opaque verify_data[Hash.length];
    } Finished;
*/
#pragma once

#include <vector>

#include <stdint.h>

#include "handshake.hpp"

namespace tls {

class Finished : public Handshake {
public:
  void Parse(std::vector<uint8_t> &buf, int &p);
  std::vector<uint8_t> GetVerifyData() const;

private:
  uint32_t hash_length_;
  std::vector<uint8_t> verify_data_;
};

} // namespace tls
