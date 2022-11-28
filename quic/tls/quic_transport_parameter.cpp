#include "quic_transport_parameter.hpp"

namespace tls {
void QUICTransportParameter::SetInitialSourceConnectionID(
    std::vector<uint8_t> &initial_source_connection_id) {
  scid_ = initial_source_connection_id;
}

std::vector<uint8_t> QUICTransportParameter::GetBinary() {
  std::vector<uint8_t> ret;
  /*
      enum {
          quic_transport_parameters(0x39), (65535)
      } ExtensionType;
  */
  ret.push_back(0x00);
  ret.push_back(0x39);

  /*
  Transport Parameter {
      Transport Parameter ID (i),
      Transport Parameter Length (i),
      Transport Parameter Value (..),
  }
  */

  std::vector<uint8_t> buf;
  std::vector<uint8_t> ins_buf;
  // initial_source_connection_id (0x0f):
  // This is the value that the endpoint included in the Source Connection ID
  // field of the first Initial packet it sends for the connection; see
  // Section 7.3.
  {
    // transport parameter id
    quic::VariableLengthInteger initial_source_connection_id_v(0x0f);
    ins_buf = initial_source_connection_id_v.GetBinary();
    std::copy(ins_buf.begin(), ins_buf.end(), std::back_inserter(buf));

    // parameter length
    quic::VariableLengthInteger initial_source_connection_id_length(
        scid_.size());
    ins_buf = initial_source_connection_id_length.GetBinary();
    std::copy(ins_buf.begin(), ins_buf.end(), std::back_inserter(buf));

    // parameter value;
    std::copy(scid_.begin(), scid_.end(), std::back_inserter(buf));
  }

  {
    // initial_max_data (0x04)
    quic::VariableLengthInteger initial_max_data_v(0x04);
    ins_buf = initial_max_data_v.GetBinary();
    std::copy(ins_buf.begin(), ins_buf.end(), std::back_inserter(buf));

    quic::VariableLengthInteger max_data(3750000);
    std::vector<uint8_t> max_data_binary = max_data.GetBinary();

    // parameter length
    quic::VariableLengthInteger max_data_length(max_data_binary.size());
    ins_buf = max_data_length.GetBinary();
    std::copy(ins_buf.begin(), ins_buf.end(), std::back_inserter(buf));

    // parameter value;
    std::copy(max_data_binary.begin(), max_data_binary.end(),
              std::back_inserter(buf));
  }

  {
    // initial_max_stream_data_bidi_local (0x05)
    quic::VariableLengthInteger initial_max_stream_data_bidi_local_v(0x05);
    ins_buf = initial_max_stream_data_bidi_local_v.GetBinary();
    std::copy(ins_buf.begin(), ins_buf.end(), std::back_inserter(buf));

    quic::VariableLengthInteger initial_max_stream_data_bidi_local(3750000);
    std::vector<uint8_t> initial_max_stream_data_bidi_local_binary =
        initial_max_stream_data_bidi_local.GetBinary();

    // parameter length
    quic::VariableLengthInteger initial_max_stream_data_bidi_locallength(
        initial_max_stream_data_bidi_local_binary.size());
    ins_buf = initial_max_stream_data_bidi_locallength.GetBinary();
    std::copy(ins_buf.begin(), ins_buf.end(), std::back_inserter(buf));

    // parameter value;
    std::copy(initial_max_stream_data_bidi_local_binary.begin(),
              initial_max_stream_data_bidi_local_binary.end(),
              std::back_inserter(buf));
  }

  //
  uint8_t length[2] = {
      static_cast<uint8_t>((buf.size() & 0xff00) >> 8),
      static_cast<uint8_t>(buf.size() & 0x00ff),
  };

  // length
  for (int i = 0; i < 2; i++) {
    ret.push_back(length[i]);
  }
  std::copy(buf.begin(), buf.end(), std::back_inserter(ret));

  return ret;
}

} // namespace tls
