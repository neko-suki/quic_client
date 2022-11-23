#pragma once

#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

namespace quic{
class Socket{
public:
    Socket();
    void Send(std::vector<uint8_t> & packet);
int sock_;

};
}
