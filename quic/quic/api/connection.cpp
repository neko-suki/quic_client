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
  ReceiveHandshakePacket(sock, packet);
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

  for (int i = 0; i < initial_packet_response_.size(); i++) {
    if (initial_packet_response_[i]->FrameType() ==
        quic::QUICFrameType::CRYPTO) {
      server_hello_crypto_frame_ = std::move(initial_packet_response_[i]);
      break;
    }
  }

  // read crypto_frame
  quic::CryptoFrame *crypto_frame = reinterpret_cast<quic::CryptoFrame *>(
      server_hello_crypto_frame_.get());

  // parse handshake packet
  std::vector<uint8_t> server_key = crypto_frame->GetSharedKey(); // should be in connection

  tls::ECDH ecdh = initial_packet_.GetECDH(); // should be in connection
  ecdh.SetPeerPublicKey(server_key);

  std::vector<uint8_t> shared_secret = ecdh.GetSecret(); // should be in connection

  client_hello_bin_ = initial_packet_.GetClientHello(); // should be used in main
  server_hello_bin_ = crypto_frame->GetServerHello(); // should be used in main

  std::vector<uint8_t> hello_message(client_hello_bin_); // in connection
  std::copy(server_hello_bin_.begin(), server_hello_bin_.end(),
            std::back_inserter(hello_message));

  tls::Hash hash;
  size_t hash_length = 32;
  std::vector<uint8_t> hello_hash =
      hash.ComputeHash(hash_length, hello_message);
  key_schedule_.ComputeHandshakeKey(hash_length, hello_hash, shared_secret);
}

void Connection::ReceiveHandshakePacket(quic::Socket & sock, uint8_t packet[2048]){
  printf("========== Handshake packet received ==========\n");
  std::vector<uint8_t> server_handshake_hp =
      key_schedule_.GetServerHandshakeHP();
  std::vector<uint8_t> server_handshake_key =
      key_schedule_.GetServerHandshakeKey();
  std::vector<uint8_t> server_handshake_iv =
      key_schedule_.GetServerHandshakeIV();
  int ptr = packet_info_.tag_offset + AES_BLOCK_SIZE;
  const size_t packet_size = 2048;
  
  std::vector<uint8_t> header;
  quic::UnprotectPacket p;
  std::vector<uint8_t> decoded_payload;
  packet_info_ = p.Unprotect(packet + ptr, packet_size, server_handshake_hp,
                            server_handshake_iv, server_handshake_key,
                            header, decoded_payload);

  quic::FrameParser frame_parser;
  frame_in_handshake_packet_ = frame_parser.ParseAll(decoded_payload);

}

} // namespace api
} // namespace quic
