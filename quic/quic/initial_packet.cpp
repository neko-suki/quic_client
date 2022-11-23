#include "initial_packet.hpp"

namespace quic{
InitialPacket::InitialPacket():packet_number_(0){
}

void InitialPacket::Protect(InitialSecretGenerator & initial_secret_generator){
    protected_payload_.resize(payload_.size());
    std::vector<uint8_t> key = initial_secret_generator.client_key();
    std::vector<uint8_t> iv = initial_secret_generator.client_iv();
    std::vector<uint8_t> hp_key = initial_secret_generator.client_hp_key();

    tag_.resize(AES_BLOCK_SIZE);

    packet_protection_.Protect(
        header_,
        payload_,
        key,
        iv,
        hp_key,
        packet_number_,
        packet_number_offset_,
        protected_payload_,
        tag_
    );

    packet_number_++;
}

void InitialPacket::CreateInitialPacket(std::vector<uint8_t> & scid, std::vector<uint8_t> & dcid){
    // CRYPTO_FRAME
    crypto_frame_.CreateFrame(scid);
    std::vector<uint8_t> crypto_frame_binary = crypto_frame_.GetBinary();

    // PADDING_FRAME
    std::vector<uint8_t> padding_frame_binary = GeneratePaddingFrame(1162-crypto_frame_binary.size());

    std::copy( crypto_frame_binary.begin(),  crypto_frame_binary.end(), std::back_inserter(payload_));
    std::copy(padding_frame_binary.begin(), padding_frame_binary.end(), std::back_inserter(payload_));

    CreateHeader(scid, dcid);
}

void InitialPacket::CreateAckPacket(std::vector<uint8_t> & scid, std::vector<uint8_t> & dcid){
    header_.clear();
    payload_.clear();
    ack_manager.AddACK(0); // to be fixed
    payload_ = ack_manager.GenFrameBinary();
    std::vector<uint8_t> padding_frame_binary = GeneratePaddingFrame(1162 - payload_.size());
    std::copy(padding_frame_binary.begin(), padding_frame_binary.end(), std::back_inserter(payload_));

    CreateHeader(scid, dcid);
}

std::vector<uint8_t> InitialPacket::GetBinary(){
    std::vector<uint8_t> ret;
    std::copy(header_.begin(), header_.end(), std::back_inserter(ret));
    std::copy(protected_payload_.begin(), protected_payload_.end(), std::back_inserter(ret));
    std::copy(tag_.begin(), tag_.end(), std::back_inserter(ret));
    return ret;
}

tls::ECDH InitialPacket::GetECDH(){
    return crypto_frame_.GetECDH();
}

std::vector<uint8_t> InitialPacket::GetClientHello(){
    return crypto_frame_.GetClientHello();
}


void InitialPacket::CreateHeader(std::vector<uint8_t> & scid, std::vector<uint8_t> & dcid){
    // first byte;
    packet_number_offset_ = 0;
    uint8_t first_byte = 0;
    // header form;
    first_byte |= 0b1000'0000;
    // fixed bit
    first_byte |= 0b0100'0000;
    // long packet type(2)
    // first_byte |= 0b0000'0000;
    // reserved_bits(2)
    // packet_numiber_length(2)
    first_byte |= 0b0000'0000;
    header_.push_back(first_byte);
    packet_number_offset_ ++;

    // version
    uint8_t version[4] = {
        0x00, 0x00, 0x00, 0x01
        //0xda, 0xda, 0xda, 0xda
    };
    for(int i = 0;i < sizeof(version);i++){
        header_.push_back(version[i]);
    }
    packet_number_offset_ += 4;

    header_.push_back(dcid.size());
    for(int i = 0;i < dcid.size();i++){
        header_.push_back(dcid[i]);
    }
    packet_number_offset_ += 1 + dcid.size();

    header_.push_back(scid.size());
    for(int i = 0;i < scid.size();i++){
        header_.push_back(scid[i]);
    }
    packet_number_offset_ += 1 + scid.size();

    // token length
    VariableLengthInteger token_length(0);
    std::vector<uint8_t> tmp = token_length.GetBinary();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(header_));
    packet_number_offset_ += 1;
    
    // length = packet_number_length + payload_size + size of tag
    VariableLengthInteger length(1 + payload_.size() + 16);
    std::vector<uint8_t> length_binary = length.GetBinary();
    std::copy(length_binary.begin(), length_binary.end(), std::back_inserter(header_));

    packet_number_offset_ += length_binary.size();

    // packet number length
    uint8_t pn[1] = {
        static_cast<uint8_t>(packet_number_)
    };
    for(int i = 0;i < 1;i++){
        header_.push_back(pn[i]);
    }
    std::cout << "header size: " << header_.size() << std::endl;
}
} //  namespace