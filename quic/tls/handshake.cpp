#include "handshake.hpp"
#include "server_hello.hpp"
#include "encrypted_extensions.hpp"

namespace tls {

std::unique_ptr<Handshake> HandshakeParser(std::vector<uint8_t> &buf, int &p){
  std::unique_ptr<Handshake> ret;
  HandshakeType msg_type_ = static_cast<HandshakeType>(buf[p]);
  if (msg_type_ == HandshakeType::server_hello) {
    std::unique_ptr<ServerHello> server_hello_ptr = std::make_unique<ServerHello>();
    server_hello_ptr->Parse(buf, p);
    ret = std::unique_ptr<Handshake>(dynamic_cast<Handshake*>(server_hello_ptr.release()));
  } else if (msg_type_ == HandshakeType::encrypted_extensions) {
    std::unique_ptr<EncryptedExtensions> encrypted_extensions_ptr = std::make_unique<EncryptedExtensions>();
    encrypted_extensions_ptr->Parse(buf, p);
    ret = std::unique_ptr<Handshake>(dynamic_cast<Handshake*>(encrypted_extensions_ptr.release()));
  } else if (msg_type_ == HandshakeType::certificate) {
    ret = std::make_unique<Handshake>();
    ret->Parse(buf, p);
  } else if (msg_type_ == HandshakeType::certificate_verify) {
    ret = std::make_unique<Handshake>();
    ret->Parse(buf, p);
  } else if (msg_type_ == HandshakeType::finished) {
    ret = std::make_unique<Handshake>();
    ret->Parse(buf, p);
  } else {
    printf("not implemented\n");
    std::exit(1);
  } 
  return ret; 
}

Handshake::Handshake()
    : msg_type_(HandshakeType::client_hello) {}

void Handshake::Parse(std::vector<uint8_t> &buf, int &p) {
  msg_type_ = static_cast<HandshakeType>(buf[p++]);
  length_ = buf[p] << 16 | buf[p + 1] << 8 | buf[p + 2];
  p += 3;
  //if (msg_type_ == HandshakeType::encrypted_extensions) {
    //encrypted_extensions_.Parse(buf, p);
  if (msg_type_ == HandshakeType::certificate) {
    certificate_.Parse(buf, p);
  } else if (msg_type_ == HandshakeType::certificate_verify) {
    certificate_verify_.Parse(buf, p);
  } else if (msg_type_ == HandshakeType::finished) {
    finished_.Parse(buf, p);
  } else {
    printf("not implemented\n");
    p += length_;
    std::exit(1);
  }
}

/*
std::vector<uint8_t> Handshake::GetSharedKey() {
  return server_hello_.GetSharedKey();
}

std::vector<uint8_t> Handshake::GetServerHello() {
  std::vector<uint8_t> handshake_payload = server_hello_.GetServerHello();
  std::vector<uint8_t> ret;
  // server_hello
  ret.push_back(2);
  // 24 bit length to ret
  uint8_t handshake_payload_length[3] = {
      static_cast<uint8_t>((handshake_payload.size() & 0xff0000) >> 16),
      static_cast<uint8_t>((handshake_payload.size() & 0xff00) >> 8),
      static_cast<uint8_t>((handshake_payload.size() & 0xff))};
  for (int i = 0; i < 3; i++) {
    ret.push_back(handshake_payload_length[i]);
  }

  std::copy(std::begin(handshake_payload), std::end(handshake_payload),
            std::back_inserter(ret));
  return ret;
}
*/

HandshakeType Handshake::GetMsgType() { return msg_type_; }

const Finished &Handshake::GetFinished() { return finished_; }
} // namespace tls