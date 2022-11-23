#include "crypto_frame.hpp"
#include "parse_variable_length_integer.hpp"
#include "variable_length_integer.hpp"

namespace quic{
void CryptoFrame::CreateFrame(std::vector<uint8_t> & initial_source_connection_id){
    // Frame Type
    crypto_frame_binary_.push_back(0x06);
    // offset
    VariableLengthInteger offset(0);
    std::vector<uint8_t> tmp = offset.GetBinary();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(crypto_frame_binary_));

    // contents of crypto frame
    // handshake should be better
    client_hello_.CreateClientHello(initial_source_connection_id);
    std::vector<uint8_t> client_hello_binary = client_hello_.GetBinary();

    // length
    VariableLengthInteger length(client_hello_binary.size());
    tmp = length.GetBinary();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(crypto_frame_binary_));

    // crypto frame
    std::copy(client_hello_binary.begin(), client_hello_binary.end(), std::back_inserter(crypto_frame_binary_));
}

std::vector<uint8_t> CryptoFrame::GetBinary(){
    return crypto_frame_binary_;
}

// parse handshake protocol
void CryptoFrame::Parse(std::vector<uint8_t> & buf, int & p){
    frame_type_ = QUICFrameType::CRYPTO;
    uint64_t offset = parse_variable_length_integer(buf, p);
    uint64_t length = parse_variable_length_integer(buf, p);
    uint32_t buf_end = p + length;
    std::copy(buf.begin() + p, buf.begin() + buf_end, std::back_inserter(payload_));
    while(p < buf_end){
        int p_begin = p;
        tls::Handshake handshake;
        handshake.Parse(buf, p);

        if (handshake.msg_type_ != 20){
            std::copy(buf.begin()+p_begin, buf.begin() + p, std::back_inserter(payload_without_finished_));
        } else {
            // finished
            std::vector<uint8_t> finished = handshake.finished_.verify_data_;
            server_sent_verified_ = finished;
        }
        handshake_.push_back(std::move(handshake));
    }
}

std::vector<uint8_t> CryptoFrame::GetSharedKey(int index){
    return handshake_[index].GetSharedKey();
}

// should be use handshake
tls::ECDH CryptoFrame::GetECDH(){
    return client_hello_.GetECDH();
}

std::vector<uint8_t> CryptoFrame::GetClientHello(){
    return client_hello_.GetClientHello();
}

std::vector<uint8_t> CryptoFrame::GetServerHello(){
    return handshake_[0].GetServerHello();
}

std::vector<uint8_t> CryptoFrame::GetPayload(){
    return payload_;
}

std::vector<uint8_t> CryptoFrame::GetPayloadWithoutFinished(){
    return payload_without_finished_;
}
std::vector<uint8_t> CryptoFrame::ServerSentFinished(){
    return server_sent_verified_;
}
} // namespace
