#pragma once

#include <vector>

#include <stdint.h>

#include "../../quic/initial_packet.hpp"
#include "../../quic/initial_secret_generator.hpp"
#include "../../quic/parse_common.hpp"
#include "../../quic/socket.hpp"
#include "../../tls/key_schedule.hpp"

namespace quic {
namespace api{
class Connection {
public:
  Connection() = default;

  // return vector<uint8_t> is temporary
  void Connect(std::vector<uint8_t> & id_of_client,
    std::vector<uint8_t> & id_of_server,
    quic::Socket & sock,
    uint8_t packet[2048]
  );

  // temporarl API
  struct PacketInfo GetPacketInfo(){
    return packet_info_;
  }

  std::vector<uint8_t> GetClientHelloBin(){
    return client_hello_bin_;
  }
  std::vector<uint8_t> GetServerHelloBin(){
    return server_hello_bin_;
  }

  tls::KeySchedule & GetKeySchedule(){
    return key_schedule_;
  }

  std::unique_ptr<quic::CryptoFrame> GetCryptoFrameHandshake(){
    return std::move(crypto_frame_handshake_);
  }

  std::vector<uint8_t> GetFinishedHash(){
    return finished_hash_;
  }

private:
  void SendInitialPacket(quic::Socket & sock);
  void ReceiveInitialPacket(quic::Socket & sock, uint8_t packet[2048]);
  void ReceiveHandshakePacket(quic::Socket & sock, uint8_t packet[2048]);
  void SendInitialAck(quic::Socket & sock);
  void SendHandshakePacket(quic::Socket & sock);

  InitialSecretGenerator initial_secret_generator_;
  std::vector<uint8_t> decoded_payload_;
  InitialPacket initial_packet_;

  // return to main
  std::vector<uint8_t> id_of_client_;
  std::vector<uint8_t> id_of_server_;
  std::vector<std::unique_ptr<quic::QUICFrame>> initial_packet_response_;
  struct PacketInfo packet_info_;
  std::unique_ptr<quic::QUICFrame> server_hello_crypto_frame_;
  std::vector<uint8_t> client_hello_bin_;
  std::vector<uint8_t> server_hello_bin_;
  tls::KeySchedule key_schedule_;
  std::vector<std::unique_ptr<quic::QUICFrame>> frame_in_handshake_packet_;
  std::unique_ptr<quic::CryptoFrame> crypto_frame_handshake_;
  std::vector<uint8_t> finished_hash_;

};

} // api
} // namespace quic
