#pragma once

#include <vector>

#include <stdint.h>

#include "socket.hpp"

namespace quic {

class OneRttPacket {
public:
    OneRttPacket(std::vector<uint8_t> dst_id, std::vector<uint8_t> & client_app_hp, std::vector<uint8_t> & client_app_key, 
            std::vector<uint8_t> & client_app_iv, uint64_t packet_number);
    void Send(Socket & sock);
    void AddFrame(std::vector<uint8_t> frame_binary);

private:
    int CreateHeader();
    uint64_t packet_number_;
    std::vector<uint8_t> header_;
    std::vector<uint8_t> payload_;
    std::vector<uint8_t> dst_id_;
    std::vector<uint8_t> client_app_hp_key_;
    std::vector<uint8_t> client_app_key_;
    std::vector<uint8_t> client_app_iv_;

};


} // namespace quic