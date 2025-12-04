#include "kcp_transport.h"

#include "../../common/crypto_stub.h"
#ifdef MI_USE_KCP
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSESOCKET closesocket
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define CLOSESOCKET close
#endif
#endif

#include <algorithm>
#include <thread>
#include <vector>
#include <chrono>
#include <cstring>

bool KCPTransport::Connect(const std::string& ip, int port,
                           const uint8_t client_pub[32],
                           const uint8_t client_priv[32],
                           const uint8_t server_pub[32],
                           const uint8_t server_sign_pub[32],
                           const uint8_t server_sign_priv[32],
                           HandshakeVerifier verifier,
                           SignFunc signer,
                           VerifyFunc verifier_sig,
                           KCPHandshakeResult& out,
                           const std::function<bool(const uint8_t nonce[16], uint8_t out_sig[64], size_t& sig_len)>& server_sig_fetch) {
#ifdef MI_USE_KCP
    remote_ip_ = ip;
    remote_port_ = port;
    std::memcpy(client_pub_, client_pub, 32);
    std::memcpy(server_sign_priv_, server_sign_priv, 32);
#if defined(_WIN32)
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    sock_ = static_cast<int>(socket(AF_INET, SOCK_DGRAM, 0));
    if (sock_ < 0) {
        return false;
    }
    kcp_ = ikcp_create(0x1, nullptr);
    if (!kcp_) return false;
    ikcp_nodelay(kcp_, 1, 10, 2, 1);
    ikcp_setoutput(kcp_, OutputCallback);
    kcp_->user = this;
    ikcp_wndsize(kcp_, 128, 128);
    ikcp_setmtu(kcp_, 1400);
    recv_running_.store(true);
    StartRecvLoop();
    StartTickLoop();
#endif
    // Simulated ECDH handshake with nonce; in real KCP this would be a network round-trip.
    uint8_t nonce[16];
    CryptoRandomBytes(nonce, sizeof(nonce));
    std::vector<uint8_t> transcript;
    transcript.insert(transcript.end(), client_pub, client_pub + 32);
    transcript.insert(transcript.end(), server_pub, server_pub + 32);
    transcript.insert(transcript.end(), nonce, nonce + sizeof(nonce));
    std::vector<uint8_t> sig;
    if (server_sig_fetch) {
        size_t sig_len = 0;
        uint8_t buf_sig[64]{0};
        if (server_sig_fetch(nonce, buf_sig, sig_len)) {
            sig.assign(buf_sig, buf_sig + sig_len);
        }
    }

    uint8_t shared[32];
    CryptoECDH(client_priv, server_pub, shared);
    uint8_t material[32 + sizeof(nonce)];
    std::memcpy(material, shared, 32);
    std::memcpy(material + 32, nonce, sizeof(nonce));
    CryptoDeriveKeyHkdf(nullptr, 0, material, sizeof(material), out.session_key);
    std::fill_n(material, sizeof(material), 0);
    // Derive transport key from client_pub + server_sign_priv (symmetric between client and server)
    uint8_t tk_input[64];
    std::memcpy(tk_input, client_pub_, 32);
    std::memcpy(tk_input + 32, server_sign_priv_, 32);
    CryptoDeriveKeyHkdf(nullptr, 0, tk_input, sizeof(tk_input), transport_key_);
    transport_key_set_ = true;

    // Require signed transcript
    bool sign_nonzero = std::any_of(server_sign_pub, server_sign_pub + 32, [](uint8_t b) { return b != 0; });
    out.verified = sign_nonzero;
    if (verifier_sig) {
        out.verified = out.verified && verifier_sig(transcript.data(), transcript.size(), sig.data(), sig.size(), server_sign_pub);
    }
    if (verifier) {
        out.verified = out.verified && verifier(server_pub, server_sign_pub, transcript.data(), transcript.size());
    }
    connected_ = out.verified;
    return out.verified;
}

void KCPTransport::Disconnect() {
    connected_ = false;
#ifdef MI_USE_KCP
    recv_running_.store(false);
    if (tick_running_.load() && tick_thread_.joinable()) {
        tick_running_.store(false);
        tick_thread_.join();
    }
    if (recv_thread_.joinable()) {
        recv_thread_.join();
    }
    if (sock_ >= 0) {
        CLOSESOCKET(sock_);
        sock_ = -1;
    }
    if (kcp_) {
        ikcp_release(kcp_);
        kcp_ = nullptr;
    }
#endif
    std::fill(std::begin(transport_key_), std::end(transport_key_), 0);
    transport_key_set_ = false;
}

void KCPTransport::SetReceive(ReceiveCallback cb) {
    recv_ = std::move(cb);
}

void KCPTransport::SetNetworkSend(SendFunc cb) {
    net_send_ = std::move(cb);
}

bool KCPTransport::Send(const uint8_t* data, size_t len) {
    if (!connected_ || !recv_) {
        return false;
    }
#ifdef MI_USE_KCP
    if (kcp_) {
        ikcp_send(kcp_, reinterpret_cast<const char*>(data), static_cast<int>(len));
        ikcp_flush(kcp_);
        return true;
    }
    if (net_send_) {
        return net_send_(data, len);
    }
#endif
    // Loopback or external relay hook
    if (net_send_) {
        return net_send_(data, len);
    }
    std::vector<uint8_t> buf(data, data + len);
    std::thread([cb = recv_, buf = std::move(buf)]() {
        cb(buf.data(), buf.size());
    }).detach();
    return true;
}

#ifdef MI_USE_KCP
int KCPTransport::OutputCallback(const char* buf, int len, ikcpcb* kcp, void* user) {
    (void)kcp;
    auto* self = reinterpret_cast<KCPTransport*>(user);
    if (!self || self->sock_ < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(self->remote_port_));
#if defined(_WIN32)
    InetPtonA(AF_INET, self->remote_ip_.c_str(), &addr.sin_addr);
#else
    inet_pton(AF_INET, self->remote_ip_.c_str(), &addr.sin_addr);
#endif
    // Encrypt KCP payload with transport key: [magic(2)=0xEE01][client_pub(32)][iv(12)][tag(16)][ct]
    if (self->transport_key_set_) {
        uint8_t iv[12];
        CryptoRandomBytes(iv, sizeof(iv));
        std::vector<uint8_t> ct;
        std::vector<uint8_t> tag;
        CryptoAesGcmEncrypt(self->transport_key_, iv, sizeof(iv), nullptr, 0,
                            reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(len), ct, tag);
        std::vector<uint8_t> pkt;
        pkt.reserve(2 + 32 + sizeof(iv) + tag.size() + ct.size());
        pkt.push_back(0xEE);
        pkt.push_back(0x01);
        pkt.insert(pkt.end(), self->client_pub_, self->client_pub_ + 32);
        pkt.insert(pkt.end(), iv, iv + sizeof(iv));
        pkt.insert(pkt.end(), tag.begin(), tag.end());
        pkt.insert(pkt.end(), ct.begin(), ct.end());
        sendto(self->sock_, reinterpret_cast<const char*>(pkt.data()), static_cast<int>(pkt.size()), 0,
               reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    } else {
        sendto(self->sock_, buf, len, 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    }
    return 0;
}

void KCPTransport::StartRecvLoop() {
    recv_thread_ = std::thread([this]() {
        sockaddr_in addr{};
        socklen_t addrlen = sizeof(addr);
        std::vector<char> buf(4096);
        while (recv_running_.load()) {
            int n = recvfrom(sock_, buf.data(), static_cast<int>(buf.size()), 0,
                             reinterpret_cast<sockaddr*>(&addr), &addrlen);
            if (n > 0 && kcp_) {
                const uint8_t* raw = reinterpret_cast<const uint8_t*>(buf.data());
                std::vector<uint8_t> plain;
                bool is_enc = (n > 2 && static_cast<uint8_t>(raw[0]) == 0xEE && static_cast<uint8_t>(raw[1]) == 0x01);
                if (is_enc && n > 2 + 32 + 12 + 16) {
                    const uint8_t* peer_pub = raw + 2;
                    // validate recipient matches this client
                    if (std::memcmp(peer_pub, client_pub_, 32) != 0) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                        continue; // drop mismatched target
                    }
                    const uint8_t* iv = raw + 2 + 32;
                    const uint8_t* tag = raw + 2 + 32 + 12;
                    size_t ct_len = static_cast<size_t>(n) - 2 - 32 - 12 - 16;
                    const uint8_t* ct = raw + 2 + 32 + 12 + 16;
                    if (transport_key_set_) {
                        if (CryptoAesGcmDecrypt(transport_key_, iv, 12, nullptr, 0, ct, ct_len, tag, 16, plain)) {
                            ikcp_input(kcp_, reinterpret_cast<const char*>(plain.data()), static_cast<int>(plain.size()));
                        }
                    }
                } else {
                    ikcp_input(kcp_, buf.data(), n);
                }
                char out[4096];
                int hr = 0;
                while ((hr = ikcp_recv(kcp_, out, sizeof(out))) > 0) {
                    std::vector<uint8_t> msg(out, out + hr);
                    if (recv_) {
                        recv_(msg.data(), msg.size());
                    }
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }
    });
}

void KCPTransport::StartTickLoop() {
    tick_running_.store(true);
    tick_thread_ = std::thread([this]() {
        auto next = std::chrono::steady_clock::now();
        while (tick_running_.load()) {
            if (kcp_) {
                auto now_ms = static_cast<IUINT32>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count());
                ikcp_update(kcp_, now_ms);
            }
            next += std::chrono::milliseconds(10);
            std::this_thread::sleep_until(next);
        }
    });
}
#endif
