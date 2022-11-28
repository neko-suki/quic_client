#include "handshake.hpp"

#include "ack_manager.hpp"

namespace quic {
Handshake::Handshake() : packet_number_offset_(0), packet_number_(1) {}

std::vector<uint8_t> Handshake::GetBinary() {
  std::vector<uint8_t> ret(header_.begin(), header_.end());
  std::copy(protected_payload_.begin(), protected_payload_.end(),
            std::back_inserter(ret));
  std::copy(tag_.begin(), tag_.end(), std::back_inserter(ret));
  return ret;
}

void Handshake::Protect(std::vector<uint8_t> &client_key,
                        std::vector<uint8_t> &client_iv,
                        std::vector<uint8_t> &client_hp_key) {
  protected_payload_.resize(payload_.size());
  tag_.resize(AES_BLOCK_SIZE);

  packet_protection_.Protect(header_, payload_, client_key, client_iv,
                             client_hp_key, packet_number_,
                             packet_number_offset_, protected_payload_, tag_);
  packet_number_++;
}

void Handshake::CreateClientHandshake(std::vector<uint8_t> &scid,
                                      std::vector<uint8_t> &dcid,
                                      std::vector<uint8_t> &verify_data) {
  CreateCryptoFrame(verify_data);
  CreateACKFrame();
  CreatePaddingFrame();
  CreateHeader(scid, dcid);
}

void Handshake::CreateCryptoFrame(std::vector<uint8_t> &verify_data) {
  std::vector<uint8_t> handshake;
  handshake.push_back(20);
  uint8_t finished_length[3] = {
      static_cast<uint8_t>((verify_data.size() & 0xff0000) >> 16),
      static_cast<uint8_t>((verify_data.size() & 0xff00) >> 8),
      static_cast<uint8_t>(verify_data.size() & 0xff)};
  std::copy(finished_length, finished_length + 3,
            std::back_inserter(handshake));

  std::copy(verify_data.begin(), verify_data.end(),
            std::back_inserter(handshake));

  std::vector<uint8_t> crypto_frame;
  crypto_frame.push_back(0x06);
  VariableLengthInteger offset(0);
  std::vector<uint8_t> offset_binary = offset.GetBinary();
  std::copy(offset_binary.begin(), offset_binary.end(),
            std::back_inserter(crypto_frame));
  VariableLengthInteger length(handshake.size());
  std::vector<uint8_t> length_binary = length.GetBinary();
  std::copy(length_binary.begin(), length_binary.end(),
            std::back_inserter(crypto_frame));
  std::copy(handshake.begin(), handshake.end(),
            std::back_inserter(crypto_frame));

  std::copy(crypto_frame.begin(), crypto_frame.end(),
            std::back_inserter(payload_));
}

void Handshake::CreateACKFrame() {
  ACKManager ack_manager;
  ack_manager.AddACK(0);
  std::vector<uint8_t> ack_frame_binary = ack_manager.GenFrameBinary();
  std::copy(ack_frame_binary.begin(), ack_frame_binary.end(),
            std::back_inserter(payload_));
}

void Handshake::CreatePaddingFrame() {
  std::vector<uint8_t> padding_frame_binary =
      GeneratePaddingFrame(1100 - payload_.size());
  std::copy(padding_frame_binary.begin(), padding_frame_binary.end(),
            std::back_inserter(payload_));
}

void Handshake::CreateHeader(std::vector<uint8_t> &scid,
                             std::vector<uint8_t> &dcid) {
  packet_number_offset_ = 0;
  uint8_t first_byte = 0;
  first_byte |= 0b1000'0000;
  first_byte |= 0b0100'0000;
  // long packet type(2) = 2
  first_byte |= 0b0010'0000;
  // reserved_bits(2)
  // packet_number_length(2)
  first_byte |= 0b0000'0000;
  header_.push_back(first_byte);
  packet_number_offset_++;

  // version
  uint8_t version[4] = {0x00, 0x00, 0x00, 0x01};
  for (int i = 0; i < sizeof(version); i++) {
    header_.push_back(version[i]);
  }
  packet_number_offset_ += 4;

  header_.push_back(dcid.size());
  std::copy(dcid.begin(), dcid.end(), std::back_inserter(header_));
  packet_number_offset_ += 1 + dcid.size();

  header_.push_back(scid.size());
  std::copy(scid.begin(), scid.end(), std::back_inserter(header_));
  packet_number_offset_ += 1 + scid.size();

  // length = packet_number_length + payload_size + size of tag
  VariableLengthInteger length(1 + payload_.size() + 16);
  std::vector<uint8_t> length_binary = length.GetBinary();
  std::copy(length_binary.begin(), length_binary.end(),
            std::back_inserter(header_));
  packet_number_offset_ += length_binary.size();
  // printf("length of handshake: %ld\n", 1 + payload_.size() + 16);

  // packet number length
  uint8_t pn[1] = {static_cast<uint8_t>(packet_number_)};
  for (int i = 0; i < 1; i++) {
    header_.push_back(pn[i]);
  }
}

} // namespace quic
