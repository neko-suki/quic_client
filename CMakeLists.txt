cmake_minimum_required(VERSION 3.2)

project(examples)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")

set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})

set(DIVISIBLE_INSTALL_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(DIVISIBLE_INSTALL_BIN_DIR ${PROJECT_SOURCE_DIR}/bin)
set(DIVISIBLE_INSTALL_LIB_DIR ${PROJECT_SOURCE_DIR}/lib)

# quic
set(SOURCE_FILES 
quic/main.cpp 

quic/tls/alpn.cpp
quic/tls/certificate.cpp
quic/tls/certificate_verify.cpp
quic/tls/ecdh.cpp
quic/tls/encrypted_extensions.cpp
quic/tls/finished.cpp
quic/tls/supported_versions.cpp
quic/tls/supported_groups.cpp
quic/tls/key_schedule.cpp
quic/tls/key_share.cpp
quic/tls/key_share_client_hello.cpp
quic/tls/key_share_server_hello.cpp
quic/tls/hash.cpp
quic/tls/handshake.cpp
quic/tls/hkdf.cpp
quic/tls/hmac.cpp
quic/tls/client_hello.cpp
quic/tls/ecdh.cpp
quic/tls/signature_algorithms.cpp
quic/tls/server_name.cpp
quic/tls/server_hello.cpp
quic/tls/quic_transport_parameter.cpp

quic/quic/api/connection.cpp
quic/quic/ack_frame.cpp
quic/quic/ack_manager.cpp
quic/quic/crypto_frame.cpp
quic/quic/frame_parser.cpp
quic/quic/handshake.cpp
quic/quic/handshake_done_frame.cpp
quic/quic/initial_packet.cpp
quic/quic/initial_secret_generator.cpp
quic/quic/one_rtt_packet.cpp
quic/quic/packet_number_manager.cpp
quic/quic/packet_protection.cpp
quic/quic/padding_frame.cpp
quic/quic/unprotect_packet.cpp
quic/quic/parse_variable_length_integer.cpp
quic/quic/socket.cpp
quic/quic/stream_frame.cpp
quic/quic/stream_manager.cpp
quic/quic/util.cpp
quic/quic/variable_length_integer.cpp
)

add_executable(quic_client ${SOURCE_FILES})
target_compile_definitions(quic_client PUBLIC -DOPEN_MODE2=\"rb\")
target_link_libraries(quic_client crypto ssl pthread)
install(TARGETS quic_client DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# client_initial test
add_executable(client_initial_test ${SOURCE_FILES})
target_compile_definitions(client_initial_test PUBLIC -DOPEN_MODE2=\"rb\")
target_link_libraries(client_initial_test crypto ssl pthread)
install(TARGETS client_initial_test DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})