#pragma once

#include <stdint.h>
#include <string>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <netinet/in.h>
#endif

struct KCPConfig {
    std::string ip;
    int port;
};

struct KCPHandshake {
    uint8_t client_pub[32];
    uint8_t server_pub[32];
    uint8_t session_key[32];
    uint8_t signature[64];
    uint32_t signature_len{0};
};

bool KCPHandshakeSimulate(const KCPConfig& cfg, const uint8_t client_pub[32], KCPHandshake& out);
// Socket-based relay (stub header; implement UDP send/recv in server daemon)
bool KCPRelayStart(const KCPConfig& cfg);
bool KCPRelaySend(const uint8_t* data, size_t len);
bool KCPRelayRecv(uint8_t* buf, size_t buf_len, size_t& out_len);
void KCPRelayStop();
// Bind a peer address (per target) for routing responses
bool KCPRelayBindPeer(const std::string& target, const sockaddr_in& addr);
bool KCPRelaySendTo(const std::string& target, const uint8_t* data, size_t len);
