#include "key_schedule.hpp"

namespace tls {

void KeySchedule::ComputeHandshakeKey(
    size_t hash_length, std::vector<uint8_t> &hello_hash,
    std::vector<uint8_t> &shared_secret) {

  hello_hash_ = hello_hash;
  early_secret_ = ComputeEarlySecret(hash_length);

  // Derive-Secret(secret=early_secret., Label="derived", Message="")
  std::vector<uint8_t> empty_message;
  std::string label = "derived";
  HKDF hkdf;
  derived_secret_ =
      hkdf.DeriveSecret(hash_length, early_secret_, label, empty_message);

  // handshake secret
  handshake_secret_ =
      hkdf.Extract(hash_length, derived_secret_, shared_secret);

  // client handshake secret
  label = "c hs traffic";
  csecret_ =
      hkdf.ExpandLabel(handshake_secret_, label, hello_hash, hash_length);

  // client key
  label = "quic key";
  std::vector<uint8_t> empty_context;
  client_handshake_key_ =
      hkdf.ExpandLabel(csecret_, label, empty_context, 16);

  // client handshake iv
  label = "quic iv";
  client_handshake_iv_ =
      hkdf.ExpandLabel(csecret_, label, empty_context, 12);

  // client handshake hp
  label = "quic hp";
  client_handshake_hp_ =
      hkdf.ExpandLabel(csecret_, label, empty_context, 16);

  // server handshake
  label = "s hs traffic";
  ssecret_ =
      hkdf.ExpandLabel(handshake_secret_, label, hello_hash, hash_length);

  // server handshake key
  label = "quic key";
  server_handshake_key_ =
      hkdf.ExpandLabel(ssecret_, label, empty_context, 16);

  // server handshake iv
  label = "quic iv";
  server_handshake_iv_ =
      hkdf.ExpandLabel(ssecret_, label, empty_context, 12);

  // server handshake hp
  label = "quic hp";
  server_handshake_hp_ =
      hkdf.ExpandLabel(ssecret_, label, empty_context, 16);

  // For verification?
  label = "finished";
  finished_key_ =
      hkdf.ExpandLabel(csecret_, label, empty_context, hash_length);
  server_finished_key_ =
      hkdf.ExpandLabel(ssecret_, label, empty_context, hash_length);
}

void KeySchedule::ComputeApplicationKey(
    size_t hash_length, std::vector<uint8_t> &handshake_hash) {

  HKDF hkdf;

  // derived secret
  std::vector<uint8_t> empty_message;
  std::string label = "derived";
  derived_secret_for_master_secret_ = hkdf.DeriveSecret(
      hash_length, handshake_secret_, label, empty_message);

  // master secret
  std::vector<uint8_t> zero_key(hash_length, 0);
  master_secret_ = hkdf.Extract(
      hash_length, derived_secret_for_master_secret_, zero_key);

  std::vector<uint8_t> empty_context;

  // client secret
  label = "c ap traffic";
  cmaster_secret_ =
      hkdf.ExpandLabel(master_secret_, label, handshake_hash, hash_length);

  // client app key
  label = "quic key";
  client_app_key_ =
      hkdf.ExpandLabel(cmaster_secret_, label, empty_context, 16);

  // client app iv
  label = "quic iv";
  client_app_iv_ =
      hkdf.ExpandLabel(cmaster_secret_, label, empty_context, 12);

  // client app hp
  label = "quic hp";
  client_app_hp_ =
      hkdf.ExpandLabel(cmaster_secret_, label, empty_context, 16);

  // server secret
  label = "s ap traffic";
  smaster_secret_ =
      hkdf.ExpandLabel(master_secret_, label, handshake_hash, hash_length);

  // server app key
  label = "quic key";
  server_app_key_ =
      hkdf.ExpandLabel(smaster_secret_, label, empty_context, 16);

  // server app iv
  label = "quic iv";
  server_app_iv_ =
      hkdf.ExpandLabel(smaster_secret_, label, empty_context, 12);

  // server app hp
  label = "quic hp";
  server_app_hp_ =
      hkdf.ExpandLabel(smaster_secret_, label, empty_context, 16);
}

std::vector<uint8_t> KeySchedule::ComputeEarlySecret(size_t hash_length) {
  std::vector<uint8_t> salt(hash_length, 0);
  std::vector<uint8_t> ikm(hash_length, 0);
  HKDF hkdf;
  std::vector<uint8_t> ret = hkdf.Extract(hash_length, salt, ikm);

  return ret;
}

std::vector<uint8_t> KeySchedule::GetServerHandshakeKey() {
  return server_handshake_key_;
}
std::vector<uint8_t> KeySchedule::GetServerHandshakeHP() {
  return server_handshake_hp_;
}
std::vector<uint8_t> KeySchedule::GetServerHandshakeIV() {
  return server_handshake_iv_;
}

std::vector<uint8_t> KeySchedule::GetClientHandshakeKey() {
  return client_handshake_key_;
}
std::vector<uint8_t> KeySchedule::GetClientHandshakeHP() {
  return client_handshake_hp_;
}
std::vector<uint8_t> KeySchedule::GetClientHandshakeIV() {
  return client_handshake_iv_;
}

std::vector<uint8_t> KeySchedule::GetFinishedKey() {
  return finished_key_;
}

std::vector<uint8_t> KeySchedule::GetServerFinishedKey() {
  return server_finished_key_;
}

std::vector<uint8_t> KeySchedule::GetServerAppKey() {
  return server_app_key_;
}
std::vector<uint8_t> KeySchedule::GetServerAppHP() {
  return server_app_hp_;
}
std::vector<uint8_t> KeySchedule::GetServerAppIV() {
  return server_app_iv_;
}

std::vector<uint8_t> KeySchedule::GetClientAppKey() {
  return client_app_key_;
}
std::vector<uint8_t> KeySchedule::GetClientAppHP() {
  return client_app_hp_;
}
std::vector<uint8_t> KeySchedule::GetClientAppIV() {
  return client_app_iv_;
}

void KeySchedule::DumpKeylog() {
  FILE *fp = fopen("keylog.txt", "w");
  fprintf(fp, "SERVER_HANDSHAKE_TRAFFIC_SECRET ");
  for (int i = 0; i < early_secret_.size(); i++) {
    fprintf(fp, "%02x", early_secret_[i]);
  }
  fprintf(fp, " ");
  for (int i = 0; i < ssecret_.size(); i++) {
    fprintf(fp, "%02x", ssecret_[i]);
  }
  fprintf(fp, "\n");
  fprintf(fp, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ");
  for (int i = 0; i < early_secret_.size(); i++) {
    fprintf(fp, "%02x", early_secret_[i]);
  }
  fprintf(fp, " ");
  for (int i = 0; i < csecret_.size(); i++) {
    fprintf(fp, "%02x", csecret_[i]);
  }
  fprintf(fp, "\n");

  fprintf(fp, "SERVER_TRAFFIC_SECRET_0 ");
  for (int i = 0; i < early_secret_.size(); i++) {
    fprintf(fp, "%02x", early_secret_[i]);
  }
  fprintf(fp, " ");
  for (int i = 0; i < smaster_secret_.size(); i++) {
    fprintf(fp, "%02x", smaster_secret_[i]);
  }
  fprintf(fp, "\n");
  fprintf(fp, "CLIENT_TRAFFIC_SECRET_0 ");
  for (int i = 0; i < early_secret_.size(); i++) {
    fprintf(fp, "%02x", early_secret_[i]);
  }
  fprintf(fp, " ");
  for (int i = 0; i < cmaster_secret_.size(); i++) {
    fprintf(fp, "%02x", cmaster_secret_[i]);
  }
  fprintf(fp, "\n");

  fclose(fp);
}
} // namespace tls
