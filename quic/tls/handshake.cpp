#include "handshake.hpp"
#include "certificate.hpp"
#include "certificate_verify.hpp"
#include "encrypted_extensions.hpp"
#include "finished.hpp"
#include "server_hello.hpp"

namespace tls {

std::unique_ptr<Handshake> HandshakeParser(std::vector<uint8_t> &buf,
                                           int &p) {
  std::unique_ptr<Handshake> ret;
  HandshakeType msg_type = static_cast<HandshakeType>(buf[p]);
  if (msg_type == HandshakeType::server_hello) {
    std::unique_ptr<ServerHello> server_hello_ptr =
        std::make_unique<ServerHello>();
    server_hello_ptr->Parse(buf, p);
    ret = std::unique_ptr<Handshake>(
        dynamic_cast<Handshake *>(server_hello_ptr.release()));
  } else if (msg_type == HandshakeType::encrypted_extensions) {
    std::unique_ptr<EncryptedExtensions> encrypted_extensions_ptr =
        std::make_unique<EncryptedExtensions>();
    encrypted_extensions_ptr->Parse(buf, p);
    ret = std::unique_ptr<Handshake>(
        dynamic_cast<Handshake *>(encrypted_extensions_ptr.release()));
  } else if (msg_type == HandshakeType::certificate) {
    std::unique_ptr<Certificate> certificate_ptr =
        std::make_unique<Certificate>();
    certificate_ptr->Parse(buf, p);
    ret = std::unique_ptr<Handshake>(
        dynamic_cast<Certificate *>(certificate_ptr.release()));
  } else if (msg_type == HandshakeType::certificate_verify) {
    std::unique_ptr<CertificateVerify> certificate_verify_ptr =
        std::make_unique<CertificateVerify>();
    certificate_verify_ptr->Parse(buf, p);
    ret = std::unique_ptr<Handshake>(dynamic_cast<CertificateVerify *>(
        certificate_verify_ptr.release()));
  } else if (msg_type == HandshakeType::finished) {
    std::unique_ptr<Finished> finished_ptr = std::make_unique<Finished>();
    finished_ptr->Parse(buf, p);
    ret = std::unique_ptr<Handshake>(
        dynamic_cast<Finished *>(finished_ptr.release()));
  } else {
    printf("not implemented\n");
    std::exit(1);
  }
  return ret;
}

HandshakeType Handshake::GetMsgType() { return msg_type_; }

} // namespace tls