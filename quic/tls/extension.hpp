/*
https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2
    struct {
        ExtensionType extension_type;
        opaque extension_data<0..2^16-1>;
    } Extension;

    enum {
        server_name(0),                             /* RFC 6066 *
        max_fragment_length(1),                     /* RFC 6066 *
        status_request(5),                          /* RFC 6066 *
        supported_groups(10),                       /* RFC 8422, 7919 *
        signature_algorithms(13),                   /* RFC 8446 *
        use_srtp(14),                               /* RFC 5764 *
        heartbeat(15),                              /* RFC 6520 *
        application_layer_protocol_negotiation(16), /* RFC 7301 *
        signed_certificate_timestamp(18),           /* RFC 6962 *
        client_certificate_type(19),                /* RFC 7250 *
        server_certificate_type(20),                /* RFC 7250 *
        padding(21),                                /* RFC 7685 *
        pre_shared_key(41),                         /* RFC 8446 *
        early_data(42),                             /* RFC 8446 *
        supported_versions(43),                     /* RFC 8446 *
        cookie(44),                                 /* RFC 8446 *
        psk_key_exchange_modes(45),                 /* RFC 8446 *
        certificate_authorities(47),                /* RFC 8446 *
        oid_filters(48),                            /* RFC 8446 *
        post_handshake_auth(49),                    /* RFC 8446 *
        signature_algorithms_cert(50),              /* RFC 8446 *
        key_share(51),                              /* RFC 8446 *
        (65535)
    } ExtensionType;
*/
#pragma once
#include <vector>

namespace tls {

enum class ExtentionType {
  supported_versions = 43,
  signature_algorithm = 50
};

class Extension {
public:
  Extension() {}
  virtual std::vector<uint8_t> GetBinary() = 0;

  ExtentionType extension_type_;
};
} // namespace tls
