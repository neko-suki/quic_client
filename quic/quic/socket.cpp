#include "socket.hpp"

namespace quic {
Socket::Socket() {
  if ((sock_ = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }
}
void Socket::Send(std::vector<uint8_t> &packet) {
  int n;
  int port = 4433;
  int packet_sz = packet.size();
  socklen_t len;

  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  // Filling server information
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
  servaddr.sin_addr.s_addr = INADDR_ANY;

  sendto(sock_, (const unsigned char *)packet.data(), packet_sz, MSG_CONFIRM,
         (const struct sockaddr *)&servaddr, sizeof(servaddr));
  // printf("Packet is sent.\n");
}
} // namespace quic