#include "mi_server_api.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "mysql_stub.h"
#include "generated_keys.h"
#include "../../common/crypto_stub.h"
#include "../../common/sha256.h"

namespace {

struct ServerState {
    bool initialized{false};
    std::vector<std::string> users;
    struct SessionRecord {
        std::string username;
        int status{0};
    };
    std::vector<SessionRecord> sessions;
    std::unordered_map<std::string, std::array<uint8_t, 32>> password_hash;
    std::string mysql_host{"127.0.0.1"};
    int mysql_port{3306};
    std::string mysql_user;
    std::string mysql_pass;
    std::string mysql_db;
    bool mysql_enabled{false};
    std::mutex mu;
    std::unordered_map<std::string, std::vector<std::vector<uint8_t>>> relay;
    std::array<uint8_t, 32> server_sign_priv{};
    std::array<uint8_t, 32> server_sign_pub{};
} g_state;

bool validate_cfg(const ConfigStruct* cfg) {
    return cfg && cfg->server_ip && cfg->server_port > 0;
}

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

std::vector<uint8_t> sign_handshake(const uint8_t* data, size_t len) {
    std::vector<uint8_t> sig;
    CryptoEd25519Sign(g_state.server_sign_priv.data(), data, len, sig);
    return sig;
}

} // namespace

extern "C" {

MI_Result MI_CALL MI_Server_Init(const ConfigStruct* cfg) {
    if (!validate_cfg(cfg)) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::lock_guard<std::mutex> lock(g_state.mu);
    g_state.initialized = true;
    g_state.sessions.clear();
    g_state.users.clear();
    g_state.password_hash.clear();
    hex_to_bytes(MI_BUILTIN_SERVER_SIGN_PRIV_HEX, g_state.server_sign_priv.data());
    hex_to_bytes(MI_BUILTIN_SERVER_SIGN_PUB_HEX, g_state.server_sign_pub.data());
    g_state.relay.clear();
    KCPConfig kcp_cfg{cfg->server_ip, cfg->server_port};
    KCPRelayStart(kcp_cfg);
    return MI_OK;
}

void MI_CALL MI_Server_Shutdown(void) {
    std::lock_guard<std::mutex> lock(g_state.mu);
    g_state.initialized = false;
    g_state.users.clear();
    g_state.sessions.clear();
    g_state.password_hash.clear();
    g_state.relay.clear();
    KCPRelayStop();
}

MI_Result MI_CALL MI_Server_AddUser(const UserInfo* user) {
    if (!user || !user->username) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (!g_state.initialized) {
        return MI_ERR_INVALID_CONFIG;
    }
    if (g_state.mysql_enabled && MySQLAvailable()) {
        if (user->password_sha256 && user->password_len == 32) {
            MySQLConfig cfg{g_state.mysql_host, g_state.mysql_port, g_state.mysql_user, g_state.mysql_pass, g_state.mysql_db};
            if (!MySQLStoreUser(cfg, user->username, user->password_sha256)) {
                return MI_ERR_STORAGE;
            }
        }
    }
    g_state.users.emplace_back(user->username);
    if (user->password_sha256 && user->password_len == 32) {
        std::array<uint8_t, 32> hash{};
        std::memcpy(hash.data(), user->password_sha256, 32);
        g_state.password_hash[g_state.users.back()] = hash;
    }
    ServerState::SessionRecord sess{};
    sess.username = g_state.users.back();
    sess.status = 1;
    g_state.sessions.push_back(sess);
    return MI_OK;
}

MI_Result MI_CALL MI_Server_RemoveUser(const EncString username) {
    if (!username.data || username.len == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::string name(reinterpret_cast<const char*>(username.data),
                     reinterpret_cast<const char*>(username.data) + username.len);
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (!g_state.initialized) {
        return MI_ERR_INVALID_CONFIG;
    }
    if (g_state.mysql_enabled && MySQLAvailable()) {
        MySQLConfig cfg{g_state.mysql_host, g_state.mysql_port, g_state.mysql_user, g_state.mysql_pass, g_state.mysql_db};
        MySQLRemoveUser(cfg, name);
    }
    auto it = std::find(g_state.users.begin(), g_state.users.end(), name);
    if (it != g_state.users.end()) {
        g_state.users.erase(it);
    }
    g_state.sessions.erase(std::remove_if(g_state.sessions.begin(), g_state.sessions.end(),
                                          [&](const ServerState::SessionRecord& s) { return name == s.username; }),
                           g_state.sessions.end());
    g_state.password_hash.erase(name);
    return MI_OK;
}

MI_Result MI_CALL MI_Server_ListSessions(SessionList* out) {
    if (!out) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (!g_state.initialized) {
        return MI_ERR_INVALID_CONFIG;
    }
    if (g_state.sessions.empty()) {
        out->items = nullptr;
        out->count = 0;
        return MI_OK;
    }
    SessionInfo* arr = new SessionInfo[g_state.sessions.size()];
    for (size_t i = 0; i < g_state.sessions.size(); ++i) {
        const auto& s = g_state.sessions[i];
        if (!s.username.empty()) {
            size_t len = s.username.size();
            char* uname = new char[len + 1];
            std::memcpy(uname, s.username.data(), len);
            uname[len] = '\0';
            arr[i].username = uname;
        } else {
            arr[i].username = nullptr;
        }
        arr[i].status = s.status;
    }
    out->items = arr;
    out->count = g_state.sessions.size();
    return MI_OK;
}

MI_Result MI_CALL MI_Server_FreeSessionList(SessionList* list) {
    if (!list || !list->items) {
        return MI_OK;
    }
    for (size_t i = 0; i < list->count; ++i) {
        if (list->items[i].username) {
            delete[] list->items[i].username;
            list->items[i].username = nullptr;
        }
    }
    delete[] list->items;
    list->items = nullptr;
    list->count = 0;
    return MI_OK;
}

MI_Result MI_CALL MI_Server_AuthLogin(const EncString username, const uint8_t password_sha256[32]) {
    if (!username.data || username.len == 0 || !password_sha256) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::string name(reinterpret_cast<const char*>(username.data),
                     reinterpret_cast<const char*>(username.data) + username.len);
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (!g_state.initialized) {
        return MI_ERR_INVALID_CONFIG;
    }
    // Prefer MySQL if configured, otherwise fallback to in-memory map
    if (g_state.mysql_enabled && MySQLAvailable()) {
        MySQLConfig cfg{g_state.mysql_host, g_state.mysql_port, g_state.mysql_user, g_state.mysql_pass, g_state.mysql_db};
        if (MySQLVerifyPassword(cfg, name, password_sha256)) {
            return MI_OK;
        } else {
            return MI_ERR_BAD_PASSWORD;
        }
    }
    auto it = g_state.password_hash.find(name);
    if (it == g_state.password_hash.end()) {
        return MI_ERR_USER_NOT_FOUND;
    }
    if (std::memcmp(it->second.data(), password_sha256, 32) != 0) {
        return MI_ERR_BAD_PASSWORD;
    }
    return MI_OK;
}

MI_Result MI_CALL MI_Server_SetMySQLConfig(const char* host, int port, const char* user, const char* password, const char* db) {
    if (!host || !user || !password || !db || port <= 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::lock_guard<std::mutex> lock(g_state.mu);
    g_state.mysql_host = host;
    g_state.mysql_port = port;
    g_state.mysql_user = user;
    g_state.mysql_pass = password;
    g_state.mysql_db = db;
    return MI_OK;
}

MI_Result MI_CALL MI_Server_EnableMySQL(int enable) {
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (enable && !MySQLAvailable()) {
        g_state.mysql_enabled = false;
        return MI_ERR_STORAGE;
    }
    g_state.mysql_enabled = (enable != 0);
    return MI_OK;
}

MI_Result MI_CALL MI_Server_RelayEnqueue(const EncString target, const EncBuffer* packet) {
    if (!target.data || target.len == 0 || !packet || !packet->data || packet->len == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::string tgt(reinterpret_cast<const char*>(target.data),
                    reinterpret_cast<const char*>(target.data) + target.len);
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (!g_state.initialized) return MI_ERR_INVALID_CONFIG;
    std::vector<uint8_t> copy(packet->data, packet->data + packet->len);
    g_state.relay[tgt].push_back(std::move(copy));
    // Also send immediately over UDP if available (best-effort)
    KCPRelaySend(packet->data, packet->len);
    return MI_OK;
}

MI_Result MI_CALL MI_Server_RelayDequeue(const EncString target, EncBuffer* out_packet) {
    if (!target.data || target.len == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::string tgt(reinterpret_cast<const char*>(target.data),
                    reinterpret_cast<const char*>(target.data) + target.len);
    std::lock_guard<std::mutex> lock(g_state.mu);
    if (!g_state.initialized) return MI_ERR_INVALID_CONFIG;
    auto it = g_state.relay.find(tgt);
    if (it == g_state.relay.end() || it->second.empty()) {
        return MI_ERR_SERVER_UNAVAILABLE;
    }
    std::vector<uint8_t> pkt = std::move(it->second.front());
    it->second.erase(it->second.begin());
        if (it->second.empty()) {
            g_state.relay.erase(it);
        }
    if (out_packet) {
        out_packet->len = static_cast<uint32_t>(pkt.size());
        out_packet->data = new uint8_t[pkt.size()];
        std::memcpy(const_cast<uint8_t*>(out_packet->data), pkt.data(), pkt.size());
        out_packet->layout_id = 0;
        out_packet->algo_id = 0;
        out_packet->salt = 0;
    }
    return MI_OK;
}

MI_Result MI_CALL MI_Server_RelayMarkDelivered(const EncString target) {
    if (!target.data || target.len == 0) return MI_ERR_INVALID_CONFIG;
    std::string tgt(reinterpret_cast<const char*>(target.data),
                    reinterpret_cast<const char*>(target.data) + target.len);
    std::lock_guard<std::mutex> lock(g_state.mu);
    auto it = g_state.relay.find(tgt);
    if (it == g_state.relay.end()) return MI_OK;
    for (auto& pkt : it->second) {
        std::fill(pkt.begin(), pkt.end(), 0xFF);
    }
    g_state.relay.erase(it);
    return MI_OK;
}

MI_Result MI_CALL MI_Server_RelayPendingCount(const EncString target, uint32_t* out_count) {
    if (!target.data || target.len == 0 || !out_count) return MI_ERR_INVALID_CONFIG;
    std::string tgt(reinterpret_cast<const char*>(target.data),
                    reinterpret_cast<const char*>(target.data) + target.len);
    std::lock_guard<std::mutex> lock(g_state.mu);
    auto it = g_state.relay.find(tgt);
    if (it == g_state.relay.end()) {
        *out_count = 0;
    } else {
        *out_count = static_cast<uint32_t>(it->second.size());
    }
    return MI_OK;
}

MI_Result MI_CALL MI_Server_PollKCP(void) {
    uint8_t buf[4096];
    size_t out_len = 0;
    while (KCPRelayRecv(buf, sizeof(buf), out_len)) {
        if (out_len < 3) continue;
        uint16_t tgt_len = static_cast<uint16_t>(buf[0] | (buf[1] << 8));
        if (tgt_len + 2 >= out_len) continue;
        EncString tgt{};
        tgt.len = tgt_len;
        tgt.data = buf + 2;
        const uint8_t* payload = buf + 2 + tgt_len;
        size_t plen = out_len - 2 - tgt_len;
        if (plen < 1) continue;
        uint8_t type = payload[0];
        if (type == PACKET_AUTH) {
            if (plen < 1 + 2 + 32) continue;
            uint16_t uname_len = static_cast<uint16_t>(payload[1] | (payload[2] << 8));
            if (1 + 2 + uname_len + 32 > plen) continue;
            std::string uname(reinterpret_cast<const char*>(payload + 3), uname_len);
            const uint8_t* hash = payload + 3 + uname_len;
            bool ok = false;
            {
                std::lock_guard<std::mutex> lock(g_state.mu);
                auto it = g_state.password_hash.find(uname);
                if (it != g_state.password_hash.end()) {
                    ok = (std::memcmp(it->second.data(), hash, 32) == 0);
                } else if (g_state.mysql_enabled && MySQLAvailable()) {
                    MySQLConfig cfg{g_state.mysql_host, g_state.mysql_port, g_state.mysql_user, g_state.mysql_pass, g_state.mysql_db};
                    ok = MySQLVerifyPassword(cfg, uname, hash);
                }
            }
            std::vector<uint8_t> ack{PACKET_AUTH_ACK, static_cast<uint8_t>(ok ? 0 : 1)};
            EncBuffer ack_buf{};
            ack_buf.len = static_cast<uint32_t>(ack.size());
            ack_buf.data = ack.data();
            ack_buf.algo_id = 0;
            ack_buf.layout_id = 0;
            ack_buf.salt = 0;
            EncString target_uname{};
            target_uname.len = static_cast<uint32_t>(uname.size());
            target_uname.data = reinterpret_cast<const uint8_t*>(uname.data());
            MI_Server_RelayEnqueue(target_uname, &ack_buf);
        } else if (type == 0x55) { // SIGN_REQ
            // payload layout: [0x55][32 client_pub][32 server_pub][16 nonce]
            if (plen < 1 + 32 + 32 + 16) continue;
            const uint8_t* client_pub = payload + 1;
            const uint8_t* server_pub = payload + 1 + 32;
            const uint8_t* nonce = payload + 1 + 64;
            std::vector<uint8_t> transcript;
            transcript.insert(transcript.end(), client_pub, client_pub + 32);
            transcript.insert(transcript.end(), server_pub, server_pub + 32);
            transcript.insert(transcript.end(), nonce, nonce + 16);
            std::vector<uint8_t> sig;
            CryptoEd25519Sign(g_state.server_sign_priv.data(), transcript.data(), transcript.size(), sig);
            if (sig.size() > 64) sig.resize(64);
            std::vector<uint8_t> ack;
            ack.reserve(2 + sig.size());
            ack.push_back(PACKET_AUTH_ACK);
            ack.push_back(0x02); // status=2 carries signature
            ack.insert(ack.end(), sig.begin(), sig.end());
            EncBuffer sb{};
            sb.len = static_cast<uint32_t>(ack.size());
            sb.data = ack.data();
            sb.layout_id = 0;
            sb.algo_id = 0;
            sb.salt = 0;
            MI_Server_RelayEnqueue(tgt, &sb);
        } else if (type == PACKET_ACK) {
            // pop one pending packet for this target
            MI_Server_RelayDequeue(tgt, nullptr);
            uint32_t pending = 0;
            MI_Server_RelayPendingCount(tgt, &pending);
            if (pending == 0) {
                MI_Server_RelayMarkDelivered(tgt);
            }
        } else {
            EncBuffer pb{};
            pb.len = static_cast<uint32_t>(plen);
            pb.data = payload;
            pb.algo_id = 0;
            pb.layout_id = 0;
            pb.salt = 0;
            MI_Server_RelayEnqueue(tgt, &pb);
        }
    }
    return MI_OK;
}

MI_Result MI_CALL MI_Server_FlushRelay(void) {
    std::lock_guard<std::mutex> lock(g_state.mu);
    for (auto it = g_state.relay.begin(); it != g_state.relay.end(); ++it) {
        uint16_t tgt_len = static_cast<uint16_t>(it->first.size());
        for (auto& pkt : it->second) {
            std::vector<uint8_t> buf;
            buf.reserve(2 + tgt_len + pkt.size());
            buf.push_back(static_cast<uint8_t>(tgt_len & 0xFF));
            buf.push_back(static_cast<uint8_t>((tgt_len >> 8) & 0xFF));
            buf.insert(buf.end(), it->first.begin(), it->first.end());
            buf.insert(buf.end(), pkt.begin(), pkt.end());
            KCPRelaySendTo(it->first, buf.data(), buf.size());
        }
    }
    return MI_OK;
}

} // extern "C"
