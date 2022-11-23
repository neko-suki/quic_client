cmake_minimum_required(VERSION 3.2)

project(examples)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")

set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})

set(DIVISIBLE_INSTALL_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(DIVISIBLE_INSTALL_BIN_DIR ${PROJECT_SOURCE_DIR}/bin)
set(DIVISIBLE_INSTALL_LIB_DIR ${PROJECT_SOURCE_DIR}/lib)

set(DIVISION_HEADERS_DIR ${PROJECT_SOURCE_DIR}/src/division)

include_directories(${DIVISIBLE_INSTALL_INCLUDE_DIR})
include_directories(${DIVISION_HEADERS_DIR})

# build hash
set(SOURCE_FILES src/common.c src/hash.c)
add_executable(hash ${SOURCE_FILES})
target_link_libraries(hash crypto ssl)
install(TARGETS hash DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# build hmac
set(SOURCE_FILES src/common.c src/hmac.c)
add_executable(hmac ${SOURCE_FILES})
target_link_libraries(hmac crypto ssl)
install(TARGETS hmac DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# build aes
set(SOURCE_FILES src/common.c src/aes.c)
add_executable(aes ${SOURCE_FILES})
target_link_libraries(aes crypto ssl)
install(TARGETS aes DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# build aes-ecb for header protection
set(SOURCE_FILES src/header_protection.c)
add_executable(header_protection ${SOURCE_FILES})
target_link_libraries(header_protection crypto ssl)
install(TARGETS header_protection DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# build packet protection
set(SOURCE_FILES src/packet_protection.cpp)
add_executable(packet_protection ${SOURCE_FILES})
target_link_libraries(packet_protection crypto ssl)
install(TARGETS packet_protection DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# build packet decryption
set(SOURCE_FILES src/packet_decryption.c)
add_executable(packet_decryption ${SOURCE_FILES})
target_link_libraries(packet_decryption crypto ssl)
install(TARGETS packet_decryption DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# quic
set(SOURCE_FILES quic/ecdh.c)
add_executable(ecdh ${SOURCE_FILES})
target_link_libraries(ecdh crypto ssl)
install(TARGETS ecdh DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# signature generation
set(SOURCE_FILES src/common.c src/rsa_sig.c)
add_executable(rsaSig ${SOURCE_FILES})
target_link_libraries(rsaSig crypto ssl)
install(TARGETS rsaSig DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# signature verify
set(SOURCE_FILES src/common.c src/rsa_ver.c)
add_executable(rsaVer ${SOURCE_FILES})
target_compile_definitions(rsaVer PUBLIC -DOPEN_MODE2=\"rb\")
target_link_libraries(rsaVer crypto ssl)
install(TARGETS rsaVer DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# signature verify
set(SOURCE_FILES src/openssl_hkdf.cpp)
add_executable(hkdf ${SOURCE_FILES})
target_compile_definitions(hkdf PUBLIC -DOPEN_MODE2=\"rb\")
target_include_directories(hkdf PUBLIC /usr/include/botan-2)
target_link_libraries(hkdf botan-2)
install(TARGETS hkdf DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# TODO: make library build

# quic
set(SOURCE_FILES 
quic/main.cpp 

quic/tls/alpn.cpp
quic/tls/certificate.cpp
quic/tls/certificate_verify.cpp
quic/tls/ecdh.cpp
quic/tls/encrypted_extensions.cpp
quic/tls/finished.cpp
quic/tls/supported_version.cpp
quic/tls/supported_groups.cpp
quic/tls/key_schedule.cpp
quic/tls/key_share.cpp
quic/tls/key_share_client_hello.cpp
quic/tls/key_share_server_hello.cpp
quic/tls/hash.cpp
quic/tls/handshake.cpp
quic/tls/hmac.cpp
quic/tls/client_hello.cpp
quic/tls/ecdh.cpp
quic/tls/signature_algorithm.cpp
quic/tls/server_name.cpp
quic/tls/server_hello.cpp
quic/tls/quic_transport_parameter.cpp

quic/quic/ack_frame.cpp
quic/quic/ack_manager.cpp
quic/quic/crypto_frame.cpp
quic/quic/frame_parser.cpp
quic/quic/handshake.cpp
quic/quic/handshake_done_frame.cpp
quic/quic/hkdf.cpp
quic/quic/initial_packet.cpp
quic/quic/initial_secret_generator.cpp
quic/quic/one_rtt_packet.cpp
quic/quic/packet_number_manager.cpp
quic/quic/packet_protection.cpp
quic/quic/padding_frame.cpp
quic/quic/parse_packet.cpp
quic/quic/parse_variable_length_integer.cpp
quic/quic/socket.cpp
quic/quic/stream_frame.cpp
quic/quic/stream_manager.cpp
quic/quic/util.cpp
quic/quic/variable_length_integer.cpp
)
add_executable(quic_client ${SOURCE_FILES})
target_compile_definitions(quic_client PUBLIC -DOPEN_MODE2=\"rb\")
target_include_directories(quic_client PUBLIC /usr/include/botan-2)
target_link_libraries(quic_client crypto ssl botan-2 pthread)
install(TARGETS quic_client DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})

# client_initial test
add_executable(client_initial_test ${SOURCE_FILES})
target_compile_definitions(client_initial_test PUBLIC -DOPEN_MODE2=\"rb\")
target_include_directories(client_initial_test PUBLIC /usr/include/botan-2)
target_link_libraries(client_initial_test crypto ssl botan-2 pthread)
install(TARGETS client_initial_test DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})