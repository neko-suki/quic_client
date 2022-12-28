#pragma once

#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

namespace quic {
class Socket {
public:
  Socket();
  void Send(std::vector<uint8_t> &packet);
  ssize_t RecvFrom(uint8_t *buf, const size_t buf_size);
  int sock_;
};
} // namespace quic
