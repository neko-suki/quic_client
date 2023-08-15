#include "connection.hpp"

#include <cstdio>

#include "../../quic/frame_parser.hpp"
#include "../../quic/unprotect_packet.hpp"
#include "../../quic/initial_packet.hpp"
#include "../../tls/hmac.hpp"

namespace quic {
namespace api{

void Connection::Connect(
    std::vector<uint8_t> & id_of_client,
    std::vector<uint8_t> & id_of_server,
    quic::Socket & sock,
    uint8_t packet[2048]
){
  id_of_client_ = id_of_client;
  id_of_server_ = id_of_server;
  SendInitialPacket(sock);
  ReceiveInitialPacket(sock, packet);
  ReceiveHandshakePacket(sock, packet);
  SendInitialAck(sock);
}

void Connection::SendInitialPacket(
    quic::Socket & sock){
  printf("========== Send initial packet ==========\n");

  // make initial packet
  initial_packet_.CreateInitialPacket(id_of_client_, id_of_server_);
  
  initial_secret_generator_.GenerateKey(id_of_server_);
  initial_packet_.Protect(initial_secret_generator_);
  std::vector<uint8_t> initial_packet_binary = initial_packet_.GetBinary();
  sock.Send(initial_packet_binary);
}


void Connection::ReceiveInitialPacket(quic::Socket & sock, uint8_t packet[2048]){
  printf("========== Initial packet receive ==========\n");
  const size_t packet_size = 2048;
  ssize_t read_size = sock.RecvFrom(packet, packet_size);

  // unprotect initial packet
  UnprotectPacket p;
  // server initial key
  std::vector<uint8_t> server_initial_hp_key =
      initial_secret_generator_.server_hp_key();
  std::vector<uint8_t> server_initial_iv =
      initial_secret_generator_.server_iv();
  std::vector<uint8_t> server_initial_key =
      initial_secret_generator_.server_key();

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
  std::vector<std::unique_ptr<quic::QUICFrame>> handshake_packet_crypto_frame = frame_parser.ParseAll(decoded_payload);
  
  for (int i = 0; i < handshake_packet_crypto_frame.size(); i++) {
    if (handshake_packet_crypto_frame[i]->FrameType() ==
        quic::QUICFrameType::CRYPTO) {
      crypto_frame_handshake_ = std::unique_ptr<quic::CryptoFrame>(
          dynamic_cast<quic::CryptoFrame *>(
              handshake_packet_crypto_frame[i].release()));
      break;
    }
  }

  // verify data
  {
    std::vector<uint8_t> merged_handshake = client_hello_bin_;
    std::copy(server_hello_bin_.begin(), server_hello_bin_.end(),
              std::back_inserter(merged_handshake));
    std::vector<uint8_t> handshake_server_hello =
        crypto_frame_handshake_->GetServerHandshakeBinaryWithoutFinished();
    std::copy(handshake_server_hello.begin(), handshake_server_hello.end(),
              std::back_inserter(merged_handshake));

    tls::Hash hash;
    size_t hash_length = 32;
    std::vector<uint8_t> finished_hash =
        hash.ComputeHash(hash_length, merged_handshake);

    tls::HMAC hmac;
    std::vector<uint8_t> server_finished_key =
        key_schedule_.GetServerFinishedKey();
    std::vector<uint8_t> verify_data =
        hmac.ComputeHMAC(finished_hash, server_finished_key);

    std::vector<uint8_t> server_verify_data =
        crypto_frame_handshake_->GetVerifyData();

    if (server_verify_data != verify_data) {
      printf("Failed verify\n");
      std::exit(1);
    }
  }
}

void Connection::SendInitialAck(quic::Socket & sock){
  uint64_t initial_packet_number = packet_info_.packet_number;

  // send Initial ACK
  initial_packet_.CreateAckPacket(id_of_client_, id_of_server_,
                                 initial_packet_number);
  initial_packet_.Protect(initial_secret_generator_);

  std::vector<uint8_t> initial_ack_binary = initial_packet_.GetBinary();
  printf("========== Send initial ack ==========\n");
  sock.Send(initial_ack_binary);
}

} // namespace api
} // namespace quic
