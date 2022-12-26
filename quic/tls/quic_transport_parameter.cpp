#include "quic_transport_parameter.hpp"

namespace tls {
QUICTransportParameter::QUICTransportParameter() {
  extension_type_ = ExtentionType::quic_transport_parameter;
}

void QUICTransportParameter::SetInitialSourceConnectionID(
    std::vector<uint8_t> &initial_source_connection_id) {
  scid_ = initial_source_connection_id;
}

std::vector<uint8_t> QUICTransportParameter::GetBinary() {
  std::vector<uint8_t> ret;
  ret.push_back(static_cast<uint16_t>(extension_type_) >> 8);
  ret.push_back(static_cast<uint16_t>(extension_type_) & 0xff);

  std::vector<uint8_t> buf;

  {
    // transport parameter id
    quic::VariableLengthInteger initial_source_connection_id_v(0x0f);
    std::vector<uint8_t> tmp = initial_source_connection_id_v.GetBinary();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(buf));

    // parameter length
    quic::VariableLengthInteger initial_source_connection_id_length(
        scid_.size());
    tmp = initial_source_connection_id_length.GetBinary();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(buf));

    // parameter value;
    std::copy(scid_.begin(), scid_.end(), std::back_inserter(buf));
  }

  {
    // initial_max_data (0x04)
    quic::VariableLengthInteger initial_max_data_v(0x04);
    std::vector<uint8_t> tmp = initial_max_data_v.GetBinary();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(buf));

    quic::VariableLengthInteger max_data(3750000);
    std::vector<uint8_t> max_data_binary = max_data.GetBinary();

    // parameter length
    quic::VariableLengthInteger max_data_length(max_data_binary.size());
    tmp = max_data_length.GetBinary();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(buf));

    // parameter value;
    std::copy(max_data_binary.begin(), max_data_binary.end(),
              std::back_inserter(buf));
  }

  {
    // initial_max_stream_data_bidi_local (0x05)
    quic::VariableLengthInteger initial_max_stream_data_bidi_local_v(0x05);
    std::vector<uint8_t> tmp =
        initial_max_stream_data_bidi_local_v.GetBinary();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(buf));

    quic::VariableLengthInteger initial_max_stream_data_bidi_local(
        3750000);
    std::vector<uint8_t> initial_max_stream_data_bidi_local_binary =
        initial_max_stream_data_bidi_local.GetBinary();

    // parameter length
    quic::VariableLengthInteger initial_max_stream_data_bidi_locallength(
        initial_max_stream_data_bidi_local_binary.size());
    tmp = initial_max_stream_data_bidi_locallength.GetBinary();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(buf));

    // parameter value;
    std::copy(initial_max_stream_data_bidi_local_binary.begin(),
              initial_max_stream_data_bidi_local_binary.end(),
              std::back_inserter(buf));
  }

  ret.push_back(static_cast<uint8_t>((buf.size() & 0xff00) >> 8));
  ret.push_back(static_cast<uint8_t>(buf.size() & 0x00ff));

  std::copy(buf.begin(), buf.end(), std::back_inserter(ret));

  return ret;
}

} // namespace tls
