Experimental implementation of QUIC client.

# Environment

Ubuntu 20.04

# requirement

- CMake >= v3.2
- OpenSSL v1.1.1f
- libbotan-2-dev/focal,now 2.12.1-2build1 amd64


# How to use
## How to build

```
$ clone git@github.com:neko-suki/quic_client.git
$ cd quic_client
$ mkdir build
$ cd build
$ cmake ..
$ make
```

## How to run
Echo client is available.

### server
Use [s2n-quic](https://github.com/aws/s2n-quic/tree/main) [v1.12.0](https://github.com/aws/s2n-quic/releases/tag/v1.12.0). 

```
$ git clone https://github.com/aws/s2n-quic
$ cd s2n-quic/examples/echo
$ git checkout -b v1.12.0 refs/tags/v1.12.0
$ cargo build
$ ./target/debug/quic_echo_server 
```

### client

```bash
$ ./quic_client 
========== Send initial packet ==========
========== Initial packet received ==========
ACK frame received
CRYPTO frame received
========== Handshake packet received ==========
CRYPTO frame received
PADDING Frame received. cnt: 966
========== Send initial ack ==========
========== Send handshake finished and ack ==========
========== Application Packet ==========
========== 1-RTT packet received ==========
PING Frame received
PADDING Frame received. cnt: 1446
========== Handshake Packet received ==========
ACK frame received
========== Parse Handshake Packet ACK end ==========
========== 1-RTT packet received ==========
HANDSHAKE_DONE frame received
NEW_CONNECTION_ID frame received
NEW_CONNECTION_ID frame received
========== Handshake Done ==========
asdf <- input from stdin
echo input: asdf
========== 1-RTT packet received ==========
ACK frame received
STREAM frame received
stream frame received. id: 0, payload: asdf  <- response from server
PADDING Frame received. cnt: 19
```

# limitations
- Only secp256r1 is available.
- ACK is not properly managed.
