/*
enum {
          /* RSASSA-PKCS1-v1_5 algorithms
          rsa_pkcs1_sha256(0x0401),
          rsa_pkcs1_sha384(0x0501),
          rsa_pkcs1_sha512(0x0601),

          /* ECDSA algorithms
          ecdsa_secp256r1_sha256(0x0403),
          ecdsa_secp384r1_sha384(0x0503),
          ecdsa_secp521r1_sha512(0x0603),

          /* RSASSA-PSS algorithms with public key OID rsaEncryption
          rsa_pss_rsae_sha256(0x0804),
          rsa_pss_rsae_sha384(0x0805),
          rsa_pss_rsae_sha512(0x0806),

          /* EdDSA algorithms
          ed25519(0x0807),
          ed448(0x0808),

          /* RSASSA-PSS algorithms with public key OID RSASSA-PSS
          rsa_pss_pss_sha256(0x0809),
          rsa_pss_pss_sha384(0x080a),
          rsa_pss_pss_sha512(0x080b),

          /* Legacy algorithms
          rsa_pkcs1_sha1(0x0201),
          ecdsa_sha1(0x0203),

          /* Reserved Code Points
          private_use(0xFE00..0xFFFF),
          (0xFFFF)
      } SignatureScheme;

      struct {
          SignatureScheme supported_signature_algorithms<2..2^16-2>;
      } SignatureSchemeList;
*/

/*
https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.1
Implementations of this specification MUST send this extension in the
   ClientHello containing all versions of TLS which they are prepared to
   negotiate (for this specification, that means minimally 0x0304, but
   if previous versions of TLS are allowed to be negotiated, they MUST
   be present as well).

    struct {
        select (Handshake.msg_type) {
            case client_hello:
                ProtocolVersion versions<2..254>;

            case server_hello: /* and HelloRetryRequest
                ProtocolVersion selected_version;
        };
    } SupportedVersions;
*/
#ifndef TLS_SIGNATURE_ALGORITHM_HPP_
#define TLS_SIGNATURE_ALGORITHM_HPP_
#include <vector>

#include <stdint.h>

#include "extension.hpp"

namespace tls {
class SignatureAlgorithm : public Extension {
public:
  SignatureAlgorithm();
  std::vector<uint8_t> GetBinary();
};
} // namespace tls

#endif