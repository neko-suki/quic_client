#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "tls/client_hello.hpp"
#include "tls/ecdh.hpp"
#include "tls/hmac.hpp"
#include "tls/key_schedule.hpp"
#include "tls/supported_groups.hpp"

#include "quic/api/connection.hpp"

#include "quic/frame_parser.hpp"
#include "quic/initial_packet.hpp"
#include "quic/unprotect_packet.hpp"

#include "quic/ack_frame.hpp"
#include "quic/ack_manager.hpp"
#include "quic/crypto_frame.hpp"
#include "quic/handshake.hpp"
#include "quic/initial_secret_generator.hpp"
#include "quic/one_rtt_packet.hpp"
#include "quic/packet_number_manager.hpp"
#include "quic/quic_frame.hpp"
#include "quic/socket.hpp"
#include "quic/stream_frame.hpp"
#include "quic/stream_manager.hpp"
#include "quic/util.hpp"

void dump(std::vector<uint8_t> &data) {
  std::cout << "size of binary: " << data.size() << std::endl;
  for (int i = 0; i < data.size(); i++) {
    if (i != 0 && i % 8 == 0 && i % 16 != 0) {
      printf(" ");
    } else if (i != 0 && i % 16 == 0) {
      printf("\n");
    }
    printf("%02x", data[i]);
  }
  printf("\n");
}

int main(int argc, char **argv) {
  quic::api::Connection connection;
  quic::Socket sock;

  printf("========== Send initial packet ==========\n");

  // SCID of client
  std::vector<uint8_t> id_of_client = {0x83, 0x94, 0xc8, 0xf0,
                                       0x3e, 0x51, 0x57, 0x09};

  // id_of_server = DCID Of client
  std::vector<uint8_t> id_of_server = {0x83, 0x94, 0xc8, 0xf0,
                                       0x3e, 0x51, 0x57, 0x08};

  quic::InitialSecretGenerator initial_secret_generator;
  uint8_t packet[2048];
  connection.Connect(initial_secret_generator, id_of_client, id_of_server, sock, packet);

  printf("========== Initial packet receive ==========\n");

  quic::FrameParser frame_parser;

  quic::PacketInfo packet_info = connection.GetPacketInfo();
  id_of_server = packet_info.source_connection_id;

  std::vector<std::unique_ptr<quic::QUICFrame>> initial_packet_response = connection.GetInitialPacketFrame();

  std::unique_ptr<quic::QUICFrame> server_hello_crypto_frame = connection.GetServerHelloCryptoFrame();

  // read crypto_frame
  quic::CryptoFrame *crypto_frame = reinterpret_cast<quic::CryptoFrame *>(
      server_hello_crypto_frame.get());

  // parse handshake packet
  std::vector<uint8_t> server_key = crypto_frame->GetSharedKey();

  quic::InitialPacket & initial_packet = connection.GetInitialPacket();
  tls::ECDH ecdh = initial_packet.GetECDH(); // should be in connection
  ecdh.SetPeerPublicKey(server_key);

  std::vector<uint8_t> shared_secret = ecdh.GetSecret(); // should be in connection

  std::vector<uint8_t> client_hello_bin = initial_packet.GetClientHello(); // should be used in main
  std::vector<uint8_t> server_hello_bin = crypto_frame->GetServerHello(); // should be used in main

  std::vector<uint8_t> hello_message(client_hello_bin); // in connection
  std::copy(server_hello_bin.begin(), server_hello_bin.end(),
            std::back_inserter(hello_message));

  tls::Hash hash;
  size_t hash_length = 32;
  std::vector<uint8_t> hello_hash =
      hash.ComputeHash(hash_length, hello_message);

  tls::KeySchedule key_schedule;
  key_schedule.ComputeHandshakeKey(hash_length, hello_hash, shared_secret);


  // everything before here should be merged

  printf("========== Handshake packet received ==========\n");
  std::vector<uint8_t> server_handshake_hp =
      key_schedule.GetServerHandshakeHP();
  std::vector<uint8_t> server_handshake_key =
      key_schedule.GetServerHandshakeKey();
  std::vector<uint8_t> server_handshake_iv =
      key_schedule.GetServerHandshakeIV();

  int ptr = packet_info.tag_offset + AES_BLOCK_SIZE;
  const size_t packet_size = 2048;
  
  std::vector<uint8_t> header;
  quic::UnprotectPacket p;
  std::vector<uint8_t> decoded_payload;
  packet_info = p.Unprotect(packet + ptr, packet_size, server_handshake_hp,
                            server_handshake_iv, server_handshake_key,
                            header, decoded_payload);
  uint64_t initial_packet_number = packet_info.packet_number;

  std::unique_ptr<quic::CryptoFrame> crypto_frame_handshake;
  std::vector<std::unique_ptr<quic::QUICFrame>>
      handshake_packet_crypto_frame =
          frame_parser.ParseAll(decoded_payload);

  for (int i = 0; i < handshake_packet_crypto_frame.size(); i++) {
    if (handshake_packet_crypto_frame[i]->FrameType() ==
        quic::QUICFrameType::CRYPTO) {
      crypto_frame_handshake = std::unique_ptr<quic::CryptoFrame>(
          dynamic_cast<quic::CryptoFrame *>(
              handshake_packet_crypto_frame[i].release()));
      break;
    }
  }

  // verify data
  {
    std::vector<uint8_t> merged_handshake = client_hello_bin;
    std::copy(server_hello_bin.begin(), server_hello_bin.end(),
              std::back_inserter(merged_handshake));
    std::vector<uint8_t> handshake_server_hello =
        crypto_frame_handshake->GetServerHandshakeBinaryWithoutFinished();
    std::copy(handshake_server_hello.begin(), handshake_server_hello.end(),
              std::back_inserter(merged_handshake));

    std::vector<uint8_t> finished_hash =
        hash.ComputeHash(hash_length, merged_handshake);

    tls::HMAC hmac;
    std::vector<uint8_t> server_finished_key =
        key_schedule.GetServerFinishedKey();
    std::vector<uint8_t> verify_data =
        hmac.ComputeHMAC(finished_hash, server_finished_key);

    std::vector<uint8_t> server_verify_data =
        crypto_frame_handshake->GetVerifyData();

    if (server_verify_data != verify_data) {
      printf("Failed verify\n");
      std::exit(1);
    }
  }

  // send Initial ACK
  initial_packet.CreateAckPacket(id_of_client, id_of_server,
                                 initial_packet_number);
  initial_packet.Protect(initial_secret_generator);

  std::vector<uint8_t> initial_ack_binary = initial_packet.GetBinary();
  printf("========== Send initial ack ==========\n");
  sock.Send(initial_ack_binary);

  // send Handshake packet
  std::vector<uint8_t> finished_key = key_schedule.GetFinishedKey();

  std::vector<uint8_t> merged_handshake = client_hello_bin;
  std::copy(server_hello_bin.begin(), server_hello_bin.end(),
            std::back_inserter(merged_handshake));
  std::vector<uint8_t> server_handshake =
      crypto_frame_handshake->GetServerHandshakeBinary();
  std::copy(server_handshake.begin(),
            server_handshake.end(),
            std::back_inserter(merged_handshake));


 for(int i = 0;i < server_hello_bin.size();i++)printf("%02x", server_hello_bin[i]);
 printf("\n");

 for(int i = 0;i < server_handshake.size();i++)printf("%02x", server_handshake[i]);
 printf("\n");


  std::vector<uint8_t> finished_hash =
      hash.ComputeHash(hash_length, merged_handshake);

  tls::HMAC hmac;
  std::vector<uint8_t> verify_data =
      hmac.ComputeHMAC(finished_hash, finished_key);

  // generate handshake packet
  quic::Handshake handshake;
  handshake.CreateClientHandshake(id_of_client, id_of_server, verify_data,
                                  packet_info.packet_number);

  std::vector<uint8_t> client_handshake_hp =
      key_schedule.GetClientHandshakeHP();
  std::vector<uint8_t> client_handshake_key =
      key_schedule.GetClientHandshakeKey();
  std::vector<uint8_t> client_handshake_iv =
      key_schedule.GetClientHandshakeIV();
  handshake.Protect(client_handshake_key, client_handshake_iv,
                    client_handshake_hp);

  std::vector<uint8_t> handshake_binary = handshake.GetBinary();
  printf("========== Send handshake finished and ack ==========\n");
  sock.Send(handshake_binary);

  printf("========== Application Packet ==========\n");

  key_schedule.ComputeApplicationKey(hash_length, finished_hash);
  key_schedule.DumpKeylog();

  // prepare server key
  std::vector<uint8_t> server_app_hp = key_schedule.GetServerAppHP();
  std::vector<uint8_t> server_app_key = key_schedule.GetServerAppKey();
  std::vector<uint8_t> server_app_iv = key_schedule.GetServerAppIV();

  // prepare client key
  std::vector<uint8_t> client_app_hp = key_schedule.GetClientAppHP();
  std::vector<uint8_t> client_app_key = key_schedule.GetClientAppKey();
  std::vector<uint8_t> client_app_iv = key_schedule.GetClientAppIV();

  std::condition_variable cond;
  std::mutex mtx;
  bool handshake_done = false;

  quic::PacketNumberManager packet_number_manager;
  quic::ACKManager ack_manager;
  // TODO: need lock?
  std::optional<uint64_t> largest_ack_received;

  std::thread recv_thread([&] {
    while (true) {
      ssize_t read_size = sock.RecvFrom(packet, packet_size);
      quic::PacketType packet_type = quic::GetPacketType(packet);
      if (quic::PacketType::Handshake == packet_type) {
        printf("========== Handshake Packet received ==========\n");
        header.clear();
        packet_info = p.Unprotect(
            packet, read_size, server_handshake_hp, server_handshake_iv,
            server_handshake_key, header, decoded_payload);
        ptr = packet_info.tag_offset + AES_BLOCK_SIZE;

        frame_parser.ParseAll(decoded_payload);
        printf("========== Parse Handshake Packet ACK end ==========\n");
      } else {
        printf("========== 1-RTT packet received ==========\n");
        header.clear();
        packet_info = p.Unprotect(packet, read_size, server_app_hp,
                                  server_app_iv, server_app_key, header,
                                  decoded_payload, id_of_client);
        std::vector<std::unique_ptr<quic::QUICFrame>> frames =
            frame_parser.ParseAll(decoded_payload);
        for (int i = 0; i < frames.size(); i++) {
          if (!frames[i]){
            continue;
          }
          if (frames[i]->FrameType() ==
                               quic::QUICFrameType::HANDSHAKE_DONE) {
            handshake_done = true;
            cond.notify_one();
          } else if ((static_cast<int32_t>(frames[i]->FrameType()) &
                      static_cast<int32_t>(quic::QUICFrameType::STREAM)) ==
                         static_cast<int32_t>(
                             quic::QUICFrameType::STREAM)) {
            quic::StreamFrame *p =
                reinterpret_cast<quic::StreamFrame *>(frames[i].get());
            std::vector<uint8_t> data = p->stream_data();
            printf("echo response: ");
            for (const auto &ch : data) {
              printf("%c", ch);
            }
            printf("\n");
          } else if (static_cast<int32_t>(frames[i]->FrameType()) == static_cast<int32_t>(quic::QUICFrameType::ACK)){
            printf("this is ack frame\n");
            quic::ACKFrame *p = reinterpret_cast<quic::ACKFrame*>(frames[i].get());
            largest_ack_received = p->LargestAcknowledged();
          }
        }
        ack_manager.AddACK(packet_info.packet_number);
        std::vector<uint8_t> ack_binary = ack_manager.GenFrameBinary();
        quic::OneRttPacket one_rtt_packet(
            id_of_server, packet_number_manager.GetPacketNumber(), largest_ack_received);
        one_rtt_packet.AddFrame(ack_binary);
        std::vector<uint8_t> send_binary = one_rtt_packet.GetBinary(
            client_app_hp, client_app_key, client_app_iv);
        sock.Send(send_binary);
      }
    }
  });

/*
  std::thread ping_thread([&] {
    while (true) {
      quic::OneRttPacket one_rtt_packet(
          id_of_server, packet_number_manager.GetPacketNumber(), largest_ack_received);
      std::vector<uint8_t> ping_Frame(1,0x01);
      one_rtt_packet.AddFrame(ping_Frame);
      std::vector<uint8_t> send_binary = one_rtt_packet.GetBinary(
          client_app_hp, client_app_key, client_app_iv);
      sock.Send(send_binary);

      sleep(1);
    }
  });
*/

  {
    std::unique_lock<std::mutex> lk(mtx);
    cond.wait(lk, [&handshake_done] { return handshake_done; });
    printf("========== Handshake Done ==========\n");

    quic::StreamManager stream_manager;
    std::string input;
    while (getline(std::cin, input)) {
      if (input.size() == 0)
        continue;
      printf("echo input: %s\n", input.c_str());
      quic::StreamFrame stream =
          stream_manager.CreateClientInitiatedBidirectionalStream();
      stream.AddPayload(input);
      stream.SetFin();
      std::vector<uint8_t> stream_frame = stream.GetBinary();

      quic::OneRttPacket one_rtt_packet(
          id_of_server, packet_number_manager.GetPacketNumber(), largest_ack_received);
      one_rtt_packet.AddFrame(stream_frame);
      std::vector<uint8_t> send_binary = one_rtt_packet.GetBinary(
          client_app_hp, client_app_key, client_app_iv);
      sock.Send(send_binary);
    }
  }

  //ping_thread.join();
  recv_thread.join();

  sleep(10);
  return 0;
}