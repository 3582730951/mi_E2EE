#include "kcp_stub.h"
#include "mysql_stub.h"
#include "../../common/crypto_stub.h"
#include "../../include/generated_keys.h"
#include <vector>
#include <array>
#include <algorithm>
#include <cstring>
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>
#include <unordered_map>
#include <array>
#ifdef MI_USE_KCP
#include <ikcp.h>
#endif
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define closesocket close
#endif

namespace {

bool hex_to_bytes(const char* hex, uint8_t out[32]) {
    if (!hex) return false;
    size_t len = std::strlen(hex);
    if (len != 64) return false;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    for (size_t i = 0; i < 32; ++i) {
        int hi = val(hex[i * 2]);
        int lo = val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

struct Session {
#ifdef MI_USE_KCP
    ikcpcb* kcp{nullptr};
#endif
    sockaddr_in addr{};
};

struct PeerCrypto {
    std::array<uint8_t, 32> client_pub{};
    std::array<uint8_t, 32> key{};
    bool has_key{false};
};

const uint8_t kMagic0 = 0xEE;
const uint8_t kMagic1 = 0x01;
constexpr size_t kIvLen = 12;
constexpr size_t kTagLen = 16;

std::array<uint8_t, 32> g_server_sign_priv{};

void derive_transport_key(const uint8_t client_pub[32], uint8_t out[32]) {
    uint8_t material[64];
    std::memcpy(material, client_pub, 32);
    std::memcpy(material + 32, g_server_sign_priv.data(), 32);
    CryptoDeriveKeyHkdf(nullptr, 0, material, sizeof(material), out);
}

} // namespace

static std::atomic<bool> g_net_running{false};
static int g_sock = -1;
static std::mutex g_recv_mu;
static std::queue<std::vector<uint8_t>> g_recv_q;
static std::thread g_recv_thread;
static sockaddr_in g_remote{};
static std::unordered_map<std::string, sockaddr_in> g_peers;
static std::mutex g_peer_mu;
static std::mutex g_send_mu;
static std::unordered_map<std::string, Session> g_sessions;
static std::thread g_tick_thread;
static std::unordered_map<std::string, PeerCrypto> g_peer_crypto;

static void StartRecvLoop();

bool KCPRelayStart(const KCPConfig& cfg) {
    if (g_sock >= 0) return true;
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    if (std::all_of(g_server_sign_priv.begin(), g_server_sign_priv.end(), [](uint8_t b){return b==0;})) {
        hex_to_bytes(MI_BUILTIN_SERVER_SIGN_PRIV_HEX, g_server_sign_priv.data());
    }
    g_sock = static_cast<int>(socket(AF_INET, SOCK_DGRAM, 0));
    if (g_sock < 0) return false;
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = 0;
    local.sin_addr.s_addr = INADDR_ANY;
    bind(g_sock, reinterpret_cast<sockaddr*>(&local), sizeof(local));
    g_remote.sin_family = AF_INET;
    g_remote.sin_port = htons(static_cast<uint16_t>(cfg.port));
#ifdef _WIN32
    InetPtonA(AF_INET, cfg.ip.c_str(), &g_remote.sin_addr);
#else
    inet_pton(AF_INET, cfg.ip.c_str(), &g_remote.sin_addr);
#endif
    g_net_running.store(true);
    StartRecvLoop();
#ifdef MI_USE_KCP
    // Tick loop for KCP sessions
    g_tick_thread = std::thread([]() {
        while (g_net_running.load()) {
            auto now = static_cast<IUINT32>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
            {
                std::lock_guard<std::mutex> lk(g_peer_mu);
                for (auto& kv : g_sessions) {
                    if (kv.second.kcp) ikcp_update(kv.second.kcp, now);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
#endif
    return true;
}

bool KCPRelaySend(const uint8_t* data, size_t len) {
    if (g_sock < 0 || !data || len == 0) return false;
    std::lock_guard<std::mutex> lk(g_send_mu);
    std::vector<uint8_t> pkt(data, data + len);
    // default path has no target key, keep plaintext
    int sent = sendto(g_sock, reinterpret_cast<const char*>(pkt.data()), static_cast<int>(pkt.size()), 0,
                      reinterpret_cast<sockaddr*>(&g_remote), sizeof(g_remote));
    return sent == static_cast<int>(pkt.size());
}

bool KCPRelaySendTo(const std::string& target, const uint8_t* data, size_t len) {
    if (g_sock < 0 || !data || len == 0) return false;
    sockaddr_in addr{};
    {
        std::lock_guard<std::mutex> lk(g_peer_mu);
        auto it = g_peers.find(target);
        if (it != g_peers.end()) {
            addr = it->second;
        }
    }
    if (addr.sin_family != 0) {
        std::lock_guard<std::mutex> lk(g_send_mu);
        std::vector<uint8_t> payload(data, data + len);
        std::lock_guard<std::mutex> lk_peer(g_peer_mu);
        auto itc = g_peer_crypto.find(target);
        if (itc != g_peer_crypto.end() && itc->second.has_key) {
            uint8_t iv[kIvLen];
            CryptoRandomBytes(iv, sizeof(iv));
            std::vector<uint8_t> ct, tag;
            CryptoAesGcmEncrypt(itc->second.key.data(), iv, sizeof(iv), nullptr, 0,
                                payload.data(), payload.size(), ct, tag);
            std::vector<uint8_t> enc;
            enc.reserve(2 + 32 + sizeof(iv) + tag.size() + ct.size());
            enc.push_back(kMagic0);
            enc.push_back(kMagic1);
            enc.insert(enc.end(), itc->second.client_pub.begin(), itc->second.client_pub.end());
            enc.insert(enc.end(), iv, iv + sizeof(iv));
            enc.insert(enc.end(), tag.begin(), tag.end());
            enc.insert(enc.end(), ct.begin(), ct.end());
            int sent = sendto(g_sock, reinterpret_cast<const char*>(enc.data()), static_cast<int>(enc.size()), 0,
                              reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            return sent == static_cast<int>(enc.size());
        }
        int sent = sendto(g_sock, reinterpret_cast<const char*>(payload.data()), static_cast<int>(payload.size()), 0,
                          reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        return sent == static_cast<int>(payload.size());
    }
    return KCPRelaySend(data, len);
}

bool KCPRelayRecv(uint8_t* buf, size_t buf_len, size_t& out_len) {
    std::lock_guard<std::mutex> lock(g_recv_mu);
    if (g_recv_q.empty()) return false;
    auto pkt = std::move(g_recv_q.front());
    g_recv_q.pop();
    out_len = std::min(buf_len, pkt.size());
    std::memcpy(buf, pkt.data(), out_len);
    return true;
}

void KCPRelayStop() {
    g_net_running.store(false);
    if (g_recv_thread.joinable()) g_recv_thread.join();
    if (g_tick_thread.joinable()) g_tick_thread.join();
    if (g_sock >= 0) {
#ifdef _WIN32
        closesocket(g_sock);
        WSACleanup();
#else
        closesocket(g_sock);
#endif
        g_sock = -1;
    }
    std::lock_guard<std::mutex> lock(g_recv_mu);
    while (!g_recv_q.empty()) g_recv_q.pop();
    std::lock_guard<std::mutex> lk(g_peer_mu);
    g_peers.clear();
    g_peer_crypto.clear();
    for (auto& kv : g_sessions) {
#ifdef MI_USE_KCP
        if (kv.second.kcp) {
            ikcp_release(kv.second.kcp);
        }
#endif
    }
    g_sessions.clear();
}

bool KCPRelayBindPeer(const std::string& target, const sockaddr_in& addr) {
    std::lock_guard<std::mutex> lk(g_peer_mu);
    g_peers[target] = addr;
    return true;
}

static void StartRecvLoop() {
    g_recv_thread = std::thread([]() {
        sockaddr_in addr{};
        socklen_t addrlen = sizeof(addr);
        std::vector<uint8_t> buf(4096);
        while (g_net_running.load()) {
            int n = recvfrom(g_sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0,
                             reinterpret_cast<sockaddr*>(&addr), &addrlen);
            if (n > 0) {
                bool handled = false;
                if (n > 2 + 32 + kIvLen + kTagLen &&
                    buf[0] == kMagic0 && buf[1] == kMagic1) {
                    const uint8_t* client_pub = buf.data() + 2;
                    uint8_t tkey[32];
                    derive_transport_key(client_pub, tkey);
                    const uint8_t* iv = buf.data() + 2 + 32;
                    const uint8_t* tag = iv + kIvLen;
                    size_t ct_len = static_cast<size_t>(n) - 2 - 32 - kIvLen - kTagLen;
                    const uint8_t* ct = tag + kTagLen;
                    std::vector<uint8_t> plain;
                    if (CryptoAesGcmDecrypt(tkey, iv, kIvLen, nullptr, 0, ct, ct_len, tag, kTagLen, plain)) {
                        if (plain.size() > 2) {
                            uint16_t tlen = static_cast<uint16_t>(plain[0] | (plain[1] << 8));
                            if (tlen + 2 <= plain.size()) {
                                std::string tgt(reinterpret_cast<const char*>(plain.data() + 2), tlen);
                                {
                                    std::lock_guard<std::mutex> lk(g_peer_mu);
                                    g_peers[tgt] = addr;
                                    PeerCrypto pc{};
                                    std::memcpy(pc.client_pub.data(), client_pub, 32);
                                    std::memcpy(pc.key.data(), tkey, 32);
                                    pc.has_key = true;
                                    g_peer_crypto[tgt] = pc;
                                }
                                std::lock_guard<std::mutex> lock(g_recv_mu);
                                g_recv_q.push(plain);
                                handled = true;
                            }
                        }
                    }
                }
                if (!handled) {
                    // legacy plaintext path
                    if (n > 2) {
                        uint16_t tlen = static_cast<uint16_t>(buf[0] | (buf[1] << 8));
                        if (tlen + 2 <= n) {
                            std::string tgt(reinterpret_cast<const char*>(buf.data() + 2), tlen);
                            std::lock_guard<std::mutex> lk(g_peer_mu);
                            g_peers[tgt] = addr;
                        }
                    }
                    std::lock_guard<std::mutex> lock(g_recv_mu);
                    buf.resize(n);
                    g_recv_q.push(buf);
                    buf.resize(4096);
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }
    });
}

static void EnsureSocket(const KCPConfig& cfg) {
    if (g_sock >= 0) return;
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    g_sock = static_cast<int>(socket(AF_INET, SOCK_DGRAM, 0));
    g_remote.sin_family = AF_INET;
    g_remote.sin_port = htons(static_cast<uint16_t>(cfg.port));
#ifdef _WIN32
    InetPtonA(AF_INET, cfg.ip.c_str(), &g_remote.sin_addr);
#else
    inet_pton(AF_INET, cfg.ip.c_str(), &g_remote.sin_addr);
#endif
    g_net_running.store(true);
    StartRecvLoop();
}

bool KCPHandshakeSimulate(const KCPConfig& cfg, const uint8_t client_pub[32], KCPHandshake& out) {
    EnsureSocket(cfg);
    // Use built-in server pub/priv to derive shared session key
    std::array<uint8_t, 32> server_priv{};
    std::array<uint8_t, 32> server_pub{};
    hex_to_bytes(MI_BUILTIN_SERVER_PUB_HEX, server_pub.data());
    hex_to_bytes(MI_BUILTIN_SERVER_SIGN_PRIV_HEX, server_priv.data());
    if (std::all_of(server_priv.begin(), server_priv.end(), [](uint8_t b){return b==0;})) {
        CryptoGenerateKeyPair(server_pub.data(), server_priv.data());
    }
    std::memcpy(out.server_pub, server_pub.data(), 32);
    std::memcpy(out.client_pub, client_pub, 32);
    uint8_t shared[32];
    CryptoECDH(server_priv.data(), client_pub, shared);
    CryptoDeriveKeyHkdf(nullptr, 0, shared, sizeof(shared), out.session_key);
    // sign transcript = client_pub || server_pub
    std::vector<uint8_t> transcript;
    transcript.insert(transcript.end(), client_pub, client_pub + 32);
    transcript.insert(transcript.end(), out.server_pub, out.server_pub + 32);
    std::vector<uint8_t> sig;
    std::array<uint8_t, 32> sign_priv{};
    hex_to_bytes(MI_BUILTIN_SERVER_SIGN_PRIV_HEX, sign_priv.data());
    CryptoEd25519Sign(sign_priv.data(), transcript.data(), transcript.size(), sig);
    out.signature_len = static_cast<uint32_t>(std::min<size_t>(sig.size(), sizeof(out.signature)));
    std::memcpy(out.signature, sig.data(), out.signature_len);
    return true;
}
