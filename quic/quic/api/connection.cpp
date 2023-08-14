#include "connection.hpp"

#include <cstdio>

#include "../../quic/frame_parser.hpp"
#include "../../quic/unprotect_packet.hpp"
#include "../../quic/initial_packet.hpp"
#include "../../quic/initial_secret_generator.hpp"

namespace quic {
namespace api{

void Connection::Connect(InitialSecretGenerator & initial_secret_generator,
    std::vector<uint8_t> & id_of_client,
    std::vector<uint8_t> & id_of_server,
    quic::Socket & sock,
    uint8_t packet[2048]
){
  id_of_client_ = id_of_client;
  id_of_server_ = id_of_server;
  SendInitialPacket(initial_secret_generator, sock);
  ReceiveInitialPacket(initial_secret_generator, sock, packet);
}

void Connection::SendInitialPacket(InitialSecretGenerator & initial_secret_generator,
    quic::Socket & sock){
  printf("========== Send initial packet ==========\n");

  // make initial packet
  initial_packet_.CreateInitialPacket(id_of_client_, id_of_server_);
  
  initial_secret_generator.GenerateKey(id_of_server_);
  // initial_secret_generator.print();
  initial_packet_.Protect(initial_secret_generator);
  std::vector<uint8_t> initial_packet_binary = initial_packet_.GetBinary();
  sock.Send(initial_packet_binary);
}


void Connection::ReceiveInitialPacket(InitialSecretGenerator & initial_secret_generator, quic::Socket & sock, uint8_t packet[2048]){
  printf("========== Initial packet receive ==========\n");
  const size_t packet_size = 2048;
  ssize_t read_size = sock.RecvFrom(packet, packet_size);

  // unprotect initial packet
  UnprotectPacket p;
  // server initial key
  std::vector<uint8_t> server_initial_hp_key =
      initial_secret_generator.server_hp_key();
  std::vector<uint8_t> server_initial_iv =
      initial_secret_generator.server_iv();
  std::vector<uint8_t> server_initial_key =
      initial_secret_generator.server_key();

  std::vector<uint8_t> header;
  //std::vector<uint8_t> decoded_payload;
  packet_info_ = p.Unprotect(
      packet, packet_size, server_initial_hp_key, server_initial_iv,
      server_initial_key, header, decoded_payload_);

  id_of_server_ =
      packet_info_.source_connection_id; // updated to choosed id by server

  quic::FrameParser frame_parser;

  initial_packet_response_ = frame_parser.ParseAll(decoded_payload_);
}


} // namespace api
} // namespace quic