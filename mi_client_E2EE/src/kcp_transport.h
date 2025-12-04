#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <atomic>
#include <array>

#ifdef MI_USE_KCP
#include <ikcp.h>
#endif

struct KCPHandshakeResult {
    uint8_t session_key[32];
    bool verified{false};
};

// KCP transport wrapper; when MI_USE_KCP is off, falls back to loopback simulation.
class KCPTransport {
public:
    using ReceiveCallback = std::function<void(const uint8_t* data, size_t len)>;
    using SendFunc = std::function<bool(const uint8_t* data, size_t len)>;
    using HandshakeVerifier = std::function<bool(const uint8_t server_pub[32], const uint8_t server_sign_pub[32], const uint8_t* transcript, size_t len)>;
    using SignFunc = std::function<bool(const uint8_t* data, size_t len, std::vector<uint8_t>& sig)>;
    using VerifyFunc = std::function<bool(const uint8_t* data, size_t len, const uint8_t* sig, size_t sig_len, const uint8_t server_sign_pub[32])>;

    bool Connect(const std::string& ip, int port,
                 const uint8_t client_pub[32],
                 const uint8_t client_priv[32],
                 const uint8_t server_pub[32],
                 const uint8_t server_sign_pub[32],
                 const uint8_t server_sign_priv[32],
                 HandshakeVerifier verifier,
                 SignFunc signer,
                 VerifyFunc verifier_sig,
                 KCPHandshakeResult& out,
                 const std::function<bool(const uint8_t nonce[16], uint8_t out_sig[64], size_t& sig_len)>& server_sig_fetch);

    void Disconnect();

    void SetReceive(ReceiveCallback cb);
    void SetNetworkSend(SendFunc cb);

    bool Send(const uint8_t* data, size_t len);

private:
    uint8_t client_pub_[32]{0};
    uint8_t server_sign_priv_[32]{0};
    uint8_t transport_key_[32]{0};
    bool transport_key_set_{false};
    ReceiveCallback recv_;
    SendFunc net_send_;
    bool connected_{false};
#ifdef MI_USE_KCP
    ikcpcb* kcp_{nullptr};
    int sock_{-1};
    std::thread recv_thread_;
    std::thread tick_thread_;
    std::atomic<bool> recv_running_{false};
    std::atomic<bool> tick_running_{false};
    std::string remote_ip_;
    int remote_port_{0};
    static int OutputCallback(const char* buf, int len, ikcpcb* kcp, void* user);
    void StartRecvLoop();
    void StartTickLoop();
#endif
};
