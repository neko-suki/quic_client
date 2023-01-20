/*
    struct {
        opaque verify_data[Hash.length];
    } Finished;
*/

#ifndef TLS_FINISHED_HPP_
#define TLS_FINISHED_HPP_

#include <vector>

#include <stdint.h>

namespace tls {

class Finished {
public:
  void Parse(std::vector<uint8_t> &buf, int &p);
  uint32_t hash_length_;
  std::vector<uint8_t> GetVerifyData() const;

private:
  std::vector<uint8_t> verify_data_;
};

} // namespace tls
#endif // TLS_FINISHED_HPP_