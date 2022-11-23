#include "signature_algorithm.hpp"

namespace tls {

SignatureAlgorithm::SignatureAlgorithm() {
    extension_type_ = ExtentionType::supported_versions;
}

std::vector<uint8_t> SignatureAlgorithm::GetBinary() {
    std::vector<uint8_t> ret;
    // type: 000d
    ret.push_back(0x00);
    ret.push_back(0x0d);

    std::vector<uint8_t> tmp;
    tmp.push_back(0x00);
    tmp.push_back(0x02);
    //  ecdsa_secp256r1_sha256(0x0403),
    tmp.push_back(0x04);
    tmp.push_back(0x03);

    uint8_t length[2] = {
      static_cast<uint8_t>((tmp.size() & 0xff00) >> 8), 
      static_cast<uint8_t>(tmp.size() & 0xff)
    };
    for (int i = 0; i < 2; i++) {
      ret.push_back(length[i]);
    }

    std::copy(tmp.begin(), tmp.end(), std::back_inserter(ret));
    return ret;
}
} // namespace tls