/*
https://www.rfc-editor.org/rfc/rfc6066#section-3
struct {
          NameType name_type;
          select (name_type) {
              case host_name: HostName;
          } name;
      } ServerName;

      enum {
          host_name(0), (255)
      } NameType;

      opaque HostName<1..2^16-1>;

      struct {
          ServerName server_name_list<1..2^16-1>
      } ServerNameList;
*/

#ifndef TLS_SERVER_NAME_HPP_
#define TLS_SERVER_NAME_HPP_
#include <vector>

#include <stdint.h>

#include "extension.hpp"

namespace tls {
class ServerName : public Extension {
public:
  ServerName();
  std::vector<uint8_t> GetBinary();
};
} // namespace tls

#endif