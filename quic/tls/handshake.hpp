#pragma once

#include <memory>

#include <stdint.h>

#include "ecdh.hpp"
#include "handshake_type.hpp"

namespace tls {

class Handshake;

std::unique_ptr<Handshake> HandshakeParser(std::vector<uint8_t> &buf,
                                           int &p);

class Handshake {
public:
  virtual void Parse(std::vector<uint8_t> &buf, int &p) {}

  HandshakeType GetMsgType();
  // const Finished &GetFinished();

protected:
  HandshakeType msg_type_;

private:
  uint32_t length_; // 24 as real
};
} // namespace tls
