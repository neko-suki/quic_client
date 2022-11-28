/*
    struct {
        opaque verify_data[Hash.length];
    } Finished;
*/

#ifndef TLS_FINISHED_HPP_
#define TLS_FINISHED_HPP_

#include <vector>

#include <stdint.h>

#include "client_hello.hpp"
#include "ecdh.hpp"
#include "handshake_type.hpp"
#include "server_hello.hpp"

namespace tls {

class Finished {
public:
  void Parse(std::vector<uint8_t> &buf, int &p);
  uint32_t hash_length_;
  std::vector<uint8_t> verify_data_;
};

} // namespace tls
#endif // TLS_FINISHED_HPP_