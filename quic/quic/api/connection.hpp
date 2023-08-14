#pragma once

#include <vector>

#include <stdint.h>

#include "../../quic/initial_packet.hpp"
#include "../../quic/initial_secret_generator.hpp"
#include "../../quic/parse_common.hpp"
#include "../../quic/socket.hpp"

namespace quic {
namespace api{
class Connection {
public:
  Connection() = default;

  // return vector<uint8_t> is temporary
  void Connect(InitialSecretGenerator & initial_secret_generator, 
    std::vector<uint8_t> & id_of_client,
    std::vector<uint8_t> & id_of_server,
    quic::Socket & sock,
    uint8_t packet[2048]
  );

  // temporarl API
  InitialPacket & GetInitialPacket(){
    return initial_packet_;
  }

  std::vector<std::unique_ptr<quic::QUICFrame>> GetInitialPacketFrame(){
    return std::move(initial_packet_response_);
  }

  struct PacketInfo GetPacketInfo(){
    return packet_info_;
  }

  std::vector<uint8_t> & GetDecodedPayload(){
    return decoded_payload_;
  }

private:
  void SendInitialPacket(InitialSecretGenerator & initial_secret_generator,
    quic::Socket & sock);
  void ReceiveInitialPacket(InitialSecretGenerator & initial_secret_generator, quic::Socket & sock, uint8_t packet[2048]);

  InitialPacket initial_packet_;
  std::vector<uint8_t> id_of_client_;
  std::vector<uint8_t> id_of_server_;
  std::vector<std::unique_ptr<quic::QUICFrame>> initial_packet_response_;
  struct PacketInfo packet_info_;
  std::vector<uint8_t> decoded_payload_;
};

} // api
} // namespace quic
