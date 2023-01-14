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

#include "quic/frame_parser.hpp"
#include "quic/initial_packet.hpp"
#include "quic/unprotect_packet.hpp"

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
  /*
  check hkdf extract
  std::vector<uint8_t> salt = {
      0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a
  };
  std::vector<uint8_t> ikm = {
      0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08
  };
  quic::HKDF hkdf;
  std::vector<uint8_t> extracted = hkdf.Extract(32, salt, ikm);
  std::vector<uint8_t> expect_extracted = {
      0x7d,0xb5,0xdf,0x06,0xe7,0xa6,0x9e,0x43,0x24,0x96,0xad,0xed,0xb0,0x08,0x51,0x92,0x35,0x95,0x22,0x15,0x96,0xae,0x2a,0xe9,0xfb,0x81,0x15,0xc1,0xe9,0xed,0x0a,0x44
  };
  if (extracted == expect_extracted){
      std::cout <<"hkdf.extract is valid" << std::endl;
  } else {
      std::cout <<"hkdf.extract is invalid" << std::endl;
  }
  */

  // this should be argument
  /*
  {
      //check key generation
      tls::KeySchedule key_schedule;

      std::vector<uint8_t> hello_hash = {
          0xff,0x78,0x8f,0x9e,0xd0,0x9e,0x60,0xd8,0x14,0x2a,0xc1,0x0a,0x89,0x31,0xcd,0xb6,0xa3,0x72,0x62,0x78,0xd3,0xac,0xdb,0xa5,0x4d,0x9d,0x9f,0xfc,0x73,0x26,0x61,0x1b
      };
      // this should be argument
      std::vector<uint8_t> shared_secret = {
          0xdf,0x4a,0x29,0x1b,0xaa,0x1e,0xb7,0xcf,0xa6,0x93,0x4b,0x29,0xb4,0x74,0xba,0xad,0x26,0x97,0xe2,0x9f,0x1f,0x92,0x0d,0xcc,0x77,0xc8,0xa0,0xa0,0x88,0x44,0x76,0x24
      };
      key_schedule.ComputeHandshakeKey(32, hello_hash, shared_secret);

      std::vector<uint8_t> handshake_hash = {
          0xb9,0x65,0x18,0x5a,0xf5,0x03,0x4e,0xda,0x0e,0xa1,0x3a,0xb4,0x24,0xdd,0xe1,0x93,0xaf,0xcb,0x42,0x45,0x18,0x23,0xa9,0x69,0x21,0xae,0x9d,0x2d,0xad,0x95,0x94,0xef
      };
      key_schedule.ComputeApplicationKey(32, handshake_hash);
  }
  */

  printf("========== Send initial packet ==========\n");
  // SCID of client
  std::vector<uint8_t> id_of_client = {0x83, 0x94, 0xc8, 0xf0,
                                       0x3e, 0x51, 0x57, 0x09};

  // id_of_server = DCID Of client
  std::vector<uint8_t> id_of_server = {0x83, 0x94, 0xc8, 0xf0,
                                       0x3e, 0x51, 0x57, 0x08};

  // make initial packet
  quic::InitialPacket initial_packet;
  initial_packet.CreateInitialPacket(id_of_client, id_of_server);

  quic::InitialSecretGenerator initial_secret_generator;
  initial_secret_generator.GenerateKey(id_of_server);
  // initial_secret_generator.print();
  initial_packet.Protect(initial_secret_generator);

  std::vector<uint8_t> initial_packet_binary = initial_packet.GetBinary();
  quic::Socket sock;
  sock.Send(initial_packet_binary);

  printf("========== Initial packet receive ==========\n");
  uint8_t packet[2048];
  const size_t packet_size = 2048;
  ssize_t read_size = sock.RecvFrom(packet, packet_size);

  // unprotect initial packet
  quic::UnprotectPacket p;
  // server initial key
  std::vector<uint8_t> server_initial_hp_key =
      initial_secret_generator.server_hp_key();
  std::vector<uint8_t> server_initial_iv =
      initial_secret_generator.server_iv();
  std::vector<uint8_t> server_initial_key =
      initial_secret_generator.server_key();

  std::vector<uint8_t> header;
  std::vector<uint8_t> decoded_payload;
  struct quic::PacketInfo packet_info = p.Unprotect(
      packet, packet_size, server_initial_hp_key, server_initial_iv,
      server_initial_key, header, decoded_payload);

  id_of_server =
      packet_info.source_connection_id; // updated to choosed id by server

  int buf_pointer = 0;
  bool initial_frame_received = false;
  bool ack_received = false;
  // read frame
  quic::FrameParser frame_parser;
  std::unique_ptr<quic::QUICFrame> initial_frame;
  while (!initial_frame_received || !ack_received) {
    std::unique_ptr<quic::QUICFrame> frame =
        frame_parser.Parse(decoded_payload, buf_pointer);
    switch (frame->frame_type_) {
    case quic::QUICFrameType::ACK:
      ack_received = true;
      break;
    case quic::QUICFrameType::CRYPTO:
      initial_frame_received = true;
      initial_frame = std::move(frame);
      break;
    default:
      printf("invalid frame type\n");
      std::exit(1);
      break;
    }
  }

  // read crypto_frame
  quic::CryptoFrame *crypto_frame =
      reinterpret_cast<quic::CryptoFrame *>(initial_frame.get());

  // parse handshake packet
  std::vector<uint8_t> server_key = crypto_frame->GetSharedKey(0);
  tls::ECDH ecdh = initial_packet.GetECDH();
  ecdh.SetPeerPublicKey(server_key);

  std::vector<uint8_t> secret = ecdh.GetSecret();

  std::vector<uint8_t> client_hello_bin = initial_packet.GetClientHello();
  std::vector<uint8_t> server_hello_bin = crypto_frame->GetServerHello();

  std::vector<uint8_t> hello_message(client_hello_bin);
  std::copy(server_hello_bin.begin(), server_hello_bin.end(),
            std::back_inserter(hello_message));

  tls::Hash hash;
  size_t hash_length = 32;
  std::vector<uint8_t> hello_hash =
      hash.ComputeHash(hash_length, hello_message);

  tls::KeySchedule key_schedule;
  key_schedule.ComputeHandshakeKey(hash_length, hello_hash, secret);

  printf("========== Handshake packet received ==========\n");
  std::vector<uint8_t> server_handshake_hp =
      key_schedule.GetServerHandshakeHP();
  std::vector<uint8_t> server_handshake_key =
      key_schedule.GetServerHandshakeKey();
  std::vector<uint8_t> server_handshake_iv =
      key_schedule.GetServerHandshakeIV();

  int ptr = packet_info.tag_offset + AES_BLOCK_SIZE;
  header.clear();
  packet_info = p.Unprotect(packet + ptr, packet_size, server_handshake_hp,
                            server_handshake_iv, server_handshake_key,
                            header, decoded_payload);

  buf_pointer = 0;
  std::unique_ptr<quic::QUICFrame> handshake_frame =
      frame_parser.Parse(decoded_payload, buf_pointer);
  quic::CryptoFrame *crypto_frame_handshake =
      reinterpret_cast<quic::CryptoFrame *>(handshake_frame.get());

  // skip paddding frame
  while (buf_pointer < decoded_payload.size()) {
    frame_parser.Parse(decoded_payload, buf_pointer);
  }

  // verify data
  {
    std::vector<uint8_t> merged_handshake = client_hello_bin;
    std::copy(server_hello_bin.begin(), server_hello_bin.end(),
              std::back_inserter(merged_handshake));
    std::vector<uint8_t> handshake_server_hello =
        crypto_frame_handshake->GetPayloadWithoutFinished();
    std::copy(handshake_server_hello.begin(), handshake_server_hello.end(),
              std::back_inserter(merged_handshake));

    std::vector<uint8_t> finished_hash =
        hash.ComputeHash(hash_length, merged_handshake);

    tls::HMAC hmac;
    std::vector<uint8_t> finished_key =
        key_schedule.GetServerFinishedKey();
    std::vector<uint8_t> verify_data =
        hmac.ComputeHMAC(finished_hash, finished_key);

    std::vector<uint8_t> server_sent_finished =
        crypto_frame_handshake->ServerSentFinished();

    if (server_sent_finished != verify_data) {
      printf("Failed verify\n");
      std::exit(1);
    }
  }

  // send Initial ACK
  initial_packet.CreateAckPacket(id_of_client, id_of_server);
  initial_packet.Protect(initial_secret_generator);

  std::vector<uint8_t> initial_ack_binary = initial_packet.GetBinary();
  printf("========== Send initial ack ==========\n");
  sock.Send(initial_ack_binary);

  // send Handshake packet
  std::vector<uint8_t> finished_key = key_schedule.GetFinishedKey();

  std::vector<uint8_t> merged_handshake = client_hello_bin;
  std::copy(server_hello_bin.begin(), server_hello_bin.end(),
            std::back_inserter(merged_handshake));
  std::vector<uint8_t> handshake_server_hello_to_server_fin =
      crypto_frame_handshake->GetPayload();
  std::copy(handshake_server_hello_to_server_fin.begin(),
            handshake_server_hello_to_server_fin.end(),
            std::back_inserter(merged_handshake));

  std::vector<uint8_t> finished_hash =
      hash.ComputeHash(hash_length, merged_handshake);

  tls::HMAC hmac;
  std::vector<uint8_t> verify_data =
      hmac.ComputeHMAC(finished_hash, finished_key);

  // generate handshake packet
  quic::Handshake handshake;
  handshake.CreateClientHandshake(id_of_client, id_of_server, verify_data);

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

  std::thread recv_thread([&] {
    while (true) {
      read_size = sock.RecvFrom(packet, packet_size);
      quic::PacketType packet_type = quic::IsLongHeaderPacket(packet);
      if (quic::PacketType::Handshake == packet_type) {
        printf("========== Handshake Packet received ==========\n");
        header.clear();
        packet_info = p.Unprotect(
            packet, read_size, server_handshake_hp, server_handshake_iv,
            server_handshake_key, header, decoded_payload);
        ptr = packet_info.tag_offset + AES_BLOCK_SIZE;

        buf_pointer = 0;
        frame_parser.Parse(decoded_payload, buf_pointer);
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
          if (frames[i] && frames[i]->FrameType() ==
                               quic::QUICFrameType::HANDSHAKE_DONE) {
            handshake_done = true;
            cond.notify_one();
          } else if (frames[i] &&
                     (static_cast<int32_t>(frames[i]->FrameType()) &
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
          }
        }
        ack_manager.AddACK(packet_info.packet_number);
        std::vector<uint8_t> ack_binary = ack_manager.GenFrameBinary();
        quic::OneRttPacket one_rtt_packet(
            id_of_server, packet_number_manager.GetPacketNumber());
        one_rtt_packet.AddFrame(ack_binary);
        one_rtt_packet.Send(sock, client_app_hp, client_app_key,
                            client_app_iv);
      }
    }
  });

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
          id_of_server, packet_number_manager.GetPacketNumber());
      one_rtt_packet.AddFrame(stream_frame);
      one_rtt_packet.Send(sock, client_app_hp, client_app_key,
                          client_app_iv);
    }
  }

  recv_thread.join();

  sleep(10);
  return 0;
}