#include "one_rtt_packet.hpp"

#include "packet_protection.hpp"
#include "padding_frame.hpp"
#include "socket.hpp"
#include "variable_length_integer.hpp"

#include <cmath>
#include <iostream>

namespace quic {
OneRttPacket::OneRttPacket(std::vector<uint8_t> dst_id,
                           uint64_t packet_number, std::optional<uint64_t> largest_acked)
    : packet_number_(packet_number), dst_id_(dst_id), largest_acked_(largest_acked) {}

int OneRttPacket::CreateHeader() {
  printf("=== CreateHeader: packet_number_: %ld\n", packet_number_);
  VariableLengthInteger packet_number_v(packet_number_);
  packet_number_v.SetNumBytes(GenerateMask());
  std::vector<uint8_t> packet_number_binary = packet_number_v.GetBinary();

  uint8_t first_byte = 0b01000000;
  first_byte |= (packet_number_binary.size() - 1);
  header_.push_back(first_byte);
  std::copy(dst_id_.begin(), dst_id_.end(), std::back_inserter(header_));
  int packet_number_offset = header_.size();
  std::copy(packet_number_binary.begin(), packet_number_binary.end(),
            std::back_inserter(header_));
  return packet_number_offset;
}

std::vector<uint8_t>
OneRttPacket::GetBinary(std::vector<uint8_t> &client_app_hp,
                        std::vector<uint8_t> &client_app_key,
                        std::vector<uint8_t> &client_app_iv) {
  if (payload_.size() < 1162) {
    std::vector<uint8_t> padding_frame =
        GeneratePaddingFrame(1162 - payload_.size());
    std::copy(padding_frame.begin(), padding_frame.end(),
              std::back_inserter(payload_));
  }

  int packet_number_offset = CreateHeader();

  std::vector<uint8_t> encrypted_payload(payload_.size());
  std::vector<uint8_t> tag(AES_BLOCK_SIZE);

  PacketProtection p;
  p.Protect(header_, payload_, client_app_key, client_app_iv,
            client_app_hp, packet_number_, packet_number_offset,
            encrypted_payload, tag);

  std::vector<uint8_t> send_binary = std::move(header_);
  std::copy(encrypted_payload.begin(), encrypted_payload.end(),
            std::back_inserter(send_binary));
  std::copy(tag.begin(), tag.end(), std::back_inserter(send_binary));

  return send_binary;
}

void OneRttPacket::AddFrame(std::vector<uint8_t> frame_binary) {
  std::copy(frame_binary.begin(), frame_binary.end(),
            std::back_inserter(payload_));
}

int OneRttPacket::GenerateMask(){
  uint64_t ret;
  uint64_t num_unacked;
  if (!largest_acked_.has_value()){
    num_unacked = packet_number_ + 1;
  } else {
    num_unacked = packet_number_ - largest_acked_.value();
  }


  int32_t min_bits = ceil(std::log2(num_unacked)) + 1;
  int32_t num_bytes = std::ceil(min_bits/8.0);

  ret = ((1LL<<min_bits)-1) & packet_number_;
  return num_bytes;
}


} // namespace quic