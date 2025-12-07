#include "mi_client_api.h"

#include "crypto_stub.h"
#include "file_hmac.h"
#include "file_ops.h"
#include "sha256.h"
#include "kcp_transport.h"
#include "file_chunker.h"
#include "generated_keys.h"

#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <chrono>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <array>
#include <thread>
#include <condition_variable>
#include <queue>
#include <filesystem>
#include <fstream>

namespace {

struct EncHolder {
    std::vector<uint8_t> buf;
};

struct MessageEntry {
    EncJson enc;
    std::unique_ptr<EncHolder> holder;
    std::string from;
};

std::atomic<bool> g_initialized{false};
std::atomic<MI_KCPState> g_kcp_state{MI_KCP_DISCONNECTED};
std::atomic<uint64_t> g_nonce{1};
std::mutex g_mu;
std::vector<MessageEntry> g_incoming;
std::vector<MessageEntry> g_history;
std::vector<std::unique_ptr<EncHolder>> g_buffers;
uint8_t g_session_key[32] = {0};
uint8_t g_client_priv[32] = {0};
uint8_t g_client_pub[32] = {0};
uint8_t g_server_pub[32] = {0}; // placeholder, filled during connect
uint8_t g_server_sign_pub[32] = {0};
std::unordered_map<std::string, GroupKey> g_group_keys;
std::unordered_map<std::string, std::array<uint8_t, 32>> g_file_hmac;
struct FileChunkState {
    uint32_t total{0};
    uint32_t received{0};
};
std::unordered_map<std::string, FileChunkState> g_file_chunks;
struct FileAssembler {
    std::string filename;
    std::string path;
    uint32_t total{0};
    uint32_t received{0};
    uint32_t chunk_size{0};
    uint64_t file_size{0};
    std::array<uint8_t, 32> hmac{};
    std::fstream stream;
};
std::unordered_map<std::string, FileAssembler> g_file_assemblers;
std::vector<uint8_t> g_client_sig_priv(32);
std::vector<uint8_t> g_client_sig_pub(32);
uint8_t g_server_sign_priv[32] = {0};
const uint8_t kAlgoId = 1; // placeholder for XOR-based stream; replace with AES-256-GCM
constexpr size_t kAesGcmIvLen = 12;
constexpr size_t kAesGcmTagLen = 16;
// Simulated KCP channel (placeholder)
std::atomic<bool> g_kcp_thread_running{false};
std::thread g_kcp_thread;
std::mutex g_kcp_mu;
std::condition_variable g_kcp_cv;
std::queue<EncBuffer> g_kcp_queue;
KCPTransport g_kcp_transport;
MI_MessageCallback g_msg_cb = nullptr;
std::string g_work_dir = ".";
MI_SendRawCallback g_raw_send = nullptr;
MI_RecvRawCallback g_raw_recv = nullptr;

enum PacketType : uint8_t {
    PACKET_MESSAGE = 1,
    PACKET_FILE_CHUNK = 2,
    PACKET_AUTH = 3,
    PACKET_AUTH_ACK = 4,
    PACKET_ACK = 5
};

struct NonceEntry {
    uint64_t ts{0};
    uint64_t nonce{0};
};
std::vector<NonceEntry> g_seen;
constexpr uint64_t kReplayWindowMs = 5 * 60 * 1000; // 5 minutes
std::mutex g_auth_mu;
std::condition_variable g_auth_cv;
bool g_auth_pending = false;
bool g_auth_success = false;
std::string g_self_username;
struct GroupState {
    GroupKey key;
    uint32_t member_count{0};
    uint32_t acked{0};
};
std::unordered_map<std::string, GroupState> g_groups;
uint64_t g_replay_floor = 0;
std::filesystem::path g_replay_file;

// Forward declaration for message unwrap helper
EncJson unwrap_message_with_honey(const EncBuffer* input, std::unique_ptr<EncHolder>& holder);

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

bool validate_cfg(const ConfigStruct* cfg) {
    return cfg && cfg->server_ip && cfg->server_port > 0;
}

void load_replay_floor() {
    if (g_replay_file.empty()) return;
    std::error_code ec;
    if (!std::filesystem::exists(g_replay_file, ec)) return;
    std::ifstream in(g_replay_file);
    uint64_t val = 0;
    if (in.good()) {
        in >> val;
        g_replay_floor = val;
    }
}

void save_replay_floor() {
    if (g_replay_file.empty()) return;
    std::ofstream out(g_replay_file, std::ios::trunc);
    out << g_replay_floor;
}

bool is_replay(uint64_t ts, uint64_t nonce) {
    uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    if (ts + kReplayWindowMs < now || ts < g_replay_floor) {
        return true;
    }
    auto it = std::find_if(g_seen.begin(), g_seen.end(), [&](const NonceEntry& e) {
        return e.ts == ts && e.nonce == nonce;
    });
    if (it != g_seen.end()) return true;
    g_seen.push_back({ts, nonce});
    g_seen.erase(std::remove_if(g_seen.begin(), g_seen.end(), [&](const NonceEntry& e) {
        return e.ts + kReplayWindowMs < now;
    }), g_seen.end());
    return false;
}

std::string to_string(const EncString& enc) {
    if (!enc.data || enc.len == 0) {
        return {};
    }
    return std::string(reinterpret_cast<const char*>(enc.data),
                       reinterpret_cast<const char*>(enc.data) + enc.len);
}

void fill_pub_from_string(const std::string& s, PublicKey* key) {
    CryptoDeriveKey(reinterpret_cast<const uint8_t*>(s.data()), s.size(), key->data);
}

EncJson make_encjson_copy(const EncJson* input, EncHolder& holder) {
    holder.buf.assign(input->data, input->data + input->len);
    EncJson copy = *input;
    copy.data = holder.buf.data();
    return copy;
}

MI_Result ensure_initialized() {
    return g_initialized.load() ? MI_OK : MI_ERR_INVALID_CONFIG;
}

EncBuffer make_encbuffer_copy(const EncJson* input, EncHolder& holder) {
    holder.buf.assign(input->data, input->data + input->len);
    EncBuffer buf{};
    buf.len = input->len;
    buf.layout_id = input->layout_id;
    buf.algo_id = kAlgoId;
    buf.salt = input->salt;
    buf.data = holder.buf.data();
    return buf;
}

EncJson make_encjson_from_buffer(const EncBuffer* input, EncHolder& holder) {
    holder.buf.assign(input->data, input->data + input->len);
    EncJson out{};
    out.len = input->len;
    out.layout_id = input->layout_id;
    out.algo_id = input->algo_id;
    out.salt = input->salt;
    out.data = holder.buf.data();
    return out;
}

void ensure_session_key() {
    bool all_zero = true;
    for (uint8_t b : g_session_key) {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        CryptoRandomBytes(g_session_key, sizeof(g_session_key));
    }
}

void derive_msg_key(uint16_t salt, uint8_t out[32]) {
    uint8_t material[34];
    std::memcpy(material, g_session_key, 32);
    material[32] = static_cast<uint8_t>((salt >> 8) & 0xFF);
    material[33] = static_cast<uint8_t>(salt & 0xFF);
    CryptoDeriveKeyHkdf(material, sizeof(material), nullptr, 0, out);
}

std::filesystem::path inbox_dir() {
    std::filesystem::path base = g_work_dir.empty() ? "." : g_work_dir;
    return base / "inbox";
}

std::vector<uint8_t> make_message_packet(const EncBuffer& wrapped) {
    std::vector<uint8_t> pkt;
    uint32_t len = wrapped.len;
    pkt.reserve(1 + 4 + len);
    pkt.push_back(static_cast<uint8_t>(PACKET_MESSAGE));
    pkt.push_back(static_cast<uint8_t>(len & 0xFF));
    pkt.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    pkt.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    pkt.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    const uint8_t* p = wrapped.data;
    pkt.insert(pkt.end(), p, p + len);
    return pkt;
}

std::vector<uint8_t> make_file_packet(const EncString& target, const FileDescriptor* file, const uint8_t* chunk, size_t chunk_len, uint32_t idx, uint32_t total, const uint8_t hmac[32]) {
    const std::filesystem::path p(file->path);
    std::string name = p.filename().string();
    uint16_t target_len = static_cast<uint16_t>(target.len);
    uint16_t name_len = static_cast<uint16_t>(name.size());
    uint16_t salt = static_cast<uint16_t>(idx & 0xFFFF);

    uint8_t key[32];
    derive_msg_key(salt, key);
    std::vector<uint8_t> iv(kAesGcmIvLen);
    CryptoRandomBytes(iv.data(), iv.size());
    std::vector<uint8_t> ct;
    std::vector<uint8_t> tag;
    CryptoAesGcmEncrypt(key, iv.data(), iv.size(), nullptr, 0, chunk, chunk_len, ct, tag);

    std::vector<uint8_t> pkt;
    pkt.reserve(1 + 2 + target_len + 2 + name_len + 4 + 4 + 4 + 8 + 32 + 2 + 4 + kAesGcmIvLen + kAesGcmTagLen + ct.size());
    pkt.push_back(static_cast<uint8_t>(PACKET_FILE_CHUNK));
    auto append_u16 = [&](uint16_t v) {
        pkt.push_back(static_cast<uint8_t>(v & 0xFF));
        pkt.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    auto append_u32 = [&](uint32_t v) {
        pkt.push_back(static_cast<uint8_t>(v & 0xFF));
        pkt.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        pkt.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        pkt.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };
    auto append_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            pkt.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
        }
    };
    append_u16(target_len);
    pkt.insert(pkt.end(), target.data, target.data + target_len);
    append_u16(name_len);
    pkt.insert(pkt.end(), name.begin(), name.end());
    append_u32(total);
    append_u32(idx);
    append_u32(file->chunk_size);
    append_u64(file->size);
    pkt.insert(pkt.end(), hmac, hmac + 32);
    append_u16(salt);
    append_u32(static_cast<uint32_t>(ct.size()));
    pkt.insert(pkt.end(), iv.begin(), iv.end());
    pkt.insert(pkt.end(), tag.begin(), tag.end());
    pkt.insert(pkt.end(), ct.begin(), ct.end());
    return pkt;
}

bool ensure_inbox_open(const std::string& filename, uint32_t total, uint32_t chunk_size, uint64_t file_size, const uint8_t hmac[32], FileAssembler& assembler) {
    std::filesystem::path dir = inbox_dir();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    assembler.filename = filename;
    assembler.path = (dir / filename).string();
    assembler.total = total;
    assembler.chunk_size = chunk_size;
    assembler.file_size = file_size;
    std::memcpy(assembler.hmac.data(), hmac, 32);
    assembler.received = 0;
    assembler.stream.open(assembler.path, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
    return assembler.stream.is_open();
}

void handle_incoming_message(const uint8_t* data, size_t len) {
    EncBuffer buf{};
    buf.len = static_cast<uint32_t>(len);
    buf.data = data;
    buf.layout_id = 0;
    buf.algo_id = 3;
    buf.salt = 0;
    std::unique_ptr<EncHolder> holder;
    EncJson json = unwrap_message_with_honey(&buf, holder);
    if (json.data && json.len > 0) {
        MessageEntry entry{};
        entry.holder = std::move(holder);
        entry.enc = json;
        entry.from = "remote";
        std::lock_guard<std::mutex> lock_inner(g_mu);
        g_incoming.push_back(std::move(entry));
        if (g_msg_cb) {
            g_msg_cb(&g_incoming.back().enc);
        }
        // update replay floor
        uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        g_replay_floor = std::max(g_replay_floor, now);
    }
    if (!g_self_username.empty()) {
        uint16_t tgt_len = static_cast<uint16_t>(g_self_username.size());
        std::vector<uint8_t> ack;
        ack.reserve(2 + tgt_len + 2);
        ack.push_back(static_cast<uint8_t>(tgt_len & 0xFF));
        ack.push_back(static_cast<uint8_t>((tgt_len >> 8) & 0xFF));
        ack.insert(ack.end(), g_self_username.begin(), g_self_username.end());
        ack.push_back(PACKET_ACK);
        ack.push_back(0x00);
        if (g_raw_send) g_raw_send(ack.data(), ack.size());
        else g_kcp_transport.Send(ack.data(), ack.size());
    }
}

void handle_incoming_file(const uint8_t* data, size_t len) {
    const uint8_t* p = data;
    size_t remain = len;
    auto read_u16 = [&](uint16_t& v) -> bool {
        if (remain < 2) return false;
        v = static_cast<uint16_t>(p[0] | (p[1] << 8));
        p += 2; remain -= 2; return true;
    };
    auto read_u32 = [&](uint32_t& v) -> bool {
        if (remain < 4) return false;
        v = static_cast<uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
        p += 4; remain -= 4; return true;
    };
    auto read_u64 = [&](uint64_t& v) -> bool {
        if (remain < 8) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= (static_cast<uint64_t>(p[i]) << (8 * i));
        }
        p += 8; remain -= 8; return true;
    };
    uint16_t target_len = 0;
    uint16_t name_len = 0;
    uint32_t total = 0, idx = 0, chunk_size = 0, chunk_len = 0;
    uint16_t salt = 0;
    uint64_t file_size = 0;
    if (!read_u16(target_len)) return;
    if (remain < target_len) return;
    p += target_len; remain -= target_len; // skip target, not used here
    if (!read_u16(name_len)) return;
    if (remain < name_len) return;
    std::string filename(reinterpret_cast<const char*>(p), name_len);
    p += name_len; remain -= name_len;
    if (!read_u32(total)) return;
    if (!read_u32(idx)) return;
    if (!read_u32(chunk_size)) return;
    if (!read_u64(file_size)) return;
    if (remain < 32) return;
    std::array<uint8_t, 32> hmac{};
    std::memcpy(hmac.data(), p, 32);
    p += 32; remain -= 32;
    if (!read_u16(salt)) return;
    if (!read_u32(chunk_len)) return;
    if (remain < kAesGcmIvLen + kAesGcmTagLen + chunk_len) return;

    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_file_assemblers.find(filename);
    if (it == g_file_assemblers.end()) {
        FileAssembler assembler;
        if (!ensure_inbox_open(filename, total, chunk_size, file_size, hmac.data(), assembler)) {
            return;
        }
        it = g_file_assemblers.emplace(filename, std::move(assembler)).first;
    }
    FileAssembler& assem = it->second;
    if (!assem.stream.is_open()) {
        return;
    }
    const uint8_t* iv = p;
    const uint8_t* tag = p + kAesGcmIvLen;
    const uint8_t* ct = p + kAesGcmIvLen + kAesGcmTagLen;
    std::vector<uint8_t> plain;
    uint8_t key[32];
    derive_msg_key(salt, key);
    if (!CryptoAesGcmDecrypt(key, iv, kAesGcmIvLen, nullptr, 0, ct, chunk_len, tag, kAesGcmTagLen, plain)) {
        return;
    }

    assem.stream.seekp(static_cast<std::streamoff>(static_cast<uint64_t>(idx) * assem.chunk_size), std::ios::beg);
    assem.stream.write(reinterpret_cast<const char*>(plain.data()), plain.size());
    assem.stream.flush();
    assem.received = std::min(assem.received + 1, assem.total);
    if (assem.received >= assem.total) {
        assem.stream.close();
        std::vector<uint8_t> calc_hmac;
        uint8_t key[32];
        derive_msg_key(static_cast<uint16_t>(assem.file_size & 0xFFFF), key);
        ComputeFileHmac(assem.path.c_str(), key, calc_hmac, assem.chunk_size);
        if (calc_hmac.size() >= 32 && std::memcmp(calc_hmac.data(), assem.hmac.data(), 32) == 0) {
            // success: keep file
        } else {
            SecureEraseFile(assem.path.c_str(), assem.file_size);
        }
        g_file_assemblers.erase(filename);
        if (!g_self_username.empty()) {
            uint16_t tgt_len = static_cast<uint16_t>(g_self_username.size());
            std::vector<uint8_t> ack;
            ack.reserve(2 + tgt_len + 2);
            ack.push_back(static_cast<uint8_t>(tgt_len & 0xFF));
            ack.push_back(static_cast<uint8_t>((tgt_len >> 8) & 0xFF));
            ack.insert(ack.end(), g_self_username.begin(), g_self_username.end());
            ack.push_back(PACKET_ACK);
            ack.push_back(0x00);
            if (g_raw_send) g_raw_send(ack.data(), ack.size());
            else g_kcp_transport.Send(ack.data(), ack.size());
        }
    }
}

void handle_incoming_packet(const uint8_t* data, size_t len) {
    if (!data || len == 0) return;
    uint8_t type = data[0];
    if (type == PACKET_MESSAGE) {
        if (len < 5) return;
        uint32_t payload_len = static_cast<uint32_t>(data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24));
        if (payload_len + 5 > len) return;
        handle_incoming_message(data + 5, payload_len);
    } else if (type == PACKET_FILE_CHUNK) {
        handle_incoming_file(data + 1, len - 1);
    } else if (type == PACKET_AUTH_ACK) {
        if (len < 2) return;
        uint8_t status = data[1];
        if (status == 2 && len >= 2 + 64) {
        std::lock_guard<std::mutex> lock(g_auth_mu);
        std::memcpy(g_server_sign_priv, data + 2, 64); // reuse buffer to pass signature
        g_auth_success = true;
        g_auth_pending = false;
        g_auth_cv.notify_all();
    } else {
        std::lock_guard<std::mutex> lock(g_auth_mu);
        g_auth_success = (status == 0);
        g_auth_pending = false;
        g_auth_cv.notify_all();
    }
    }
}

EncBuffer encrypt_with_session(const EncJson* input, std::unique_ptr<EncHolder>& holder) {
    holder = std::make_unique<EncHolder>();
    uint16_t salt = 0;
    CryptoRandomBytes(reinterpret_cast<uint8_t*>(&salt), sizeof(salt));
    uint8_t key[32];
    derive_msg_key(salt, key);
    std::vector<uint8_t> out;
    std::vector<uint8_t> tag;
    std::vector<uint8_t> iv(kAesGcmIvLen);
    CryptoRandomBytes(iv.data(), iv.size());
    if (!CryptoAesGcmEncrypt(key, iv.data(), iv.size(), nullptr, 0, input->data, input->len, out, tag)) {
        holder->buf.clear();
    } else {
        holder->buf.reserve(iv.size() + out.size() + tag.size());
        holder->buf.insert(holder->buf.end(), iv.begin(), iv.end());
        holder->buf.insert(holder->buf.end(), out.begin(), out.end());
        holder->buf.insert(holder->buf.end(), tag.begin(), tag.end());
    }
    EncBuffer buf{};
    buf.len = static_cast<uint32_t>(holder->buf.size());
    buf.layout_id = input->layout_id;
    buf.algo_id = 2; // AES-256-GCM
    buf.salt = salt;
    buf.data = holder->buf.data();
    return buf;
}

EncJson decrypt_with_session(const EncBuffer* input, std::unique_ptr<EncHolder>& holder) {
    holder = std::make_unique<EncHolder>();
    if (input->len < kAesGcmIvLen + kAesGcmTagLen) {
        EncJson json{};
        json.len = 0;
        json.data = nullptr;
        return json;
    }
    const uint8_t* iv = input->data;
    size_t ct_len = input->len - kAesGcmIvLen - kAesGcmTagLen;
    const uint8_t* ct = input->data + kAesGcmIvLen;
    const uint8_t* tag = input->data + kAesGcmIvLen + ct_len;
    uint8_t key[32];
    derive_msg_key(input->salt, key);
    std::vector<uint8_t> out;
    if (!CryptoAesGcmDecrypt(key, iv, kAesGcmIvLen, nullptr, 0, ct, ct_len, tag, kAesGcmTagLen, out)) {
        holder->buf.clear();
    } else {
        holder->buf = std::move(out);
    }
    EncJson json{};
    json.len = static_cast<uint32_t>(holder->buf.size());
    json.layout_id = input->layout_id;
    json.algo_id = input->algo_id;
    json.salt = input->salt;
    json.data = holder->buf.data();
    return json;
}

EncBuffer wrap_message_with_honey(const EncString target_username, const EncJson message_content, std::unique_ptr<EncHolder>& holder) {
    holder = std::make_unique<EncHolder>();
    ensure_session_key();
    uint64_t nonce = g_nonce.fetch_add(1, std::memory_order_relaxed);
    uint64_t ts = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count());

    // Inner layer: encrypt message_content with target-bound key
    uint16_t inner_salt = 0;
    CryptoRandomBytes(reinterpret_cast<uint8_t*>(&inner_salt), sizeof(inner_salt));
    uint8_t inner_key[32];
    // derive inner key from session key + target username + salt
    std::vector<uint8_t> inner_material;
    inner_material.insert(inner_material.end(), g_session_key, g_session_key + 32);
    inner_material.insert(inner_material.end(), target_username.data, target_username.data + target_username.len);
    inner_material.push_back(static_cast<uint8_t>((inner_salt >> 8) & 0xFF));
    inner_material.push_back(static_cast<uint8_t>(inner_salt & 0xFF));
    CryptoDeriveKeyHkdf(nullptr, 0, inner_material.data(), inner_material.size(), inner_key);
    std::vector<uint8_t> inner_iv(kAesGcmIvLen);
    CryptoRandomBytes(inner_iv.data(), inner_iv.size());
    std::vector<uint8_t> inner_ct;
    std::vector<uint8_t> inner_tag;
    CryptoAesGcmEncrypt(inner_key, inner_iv.data(), inner_iv.size(), nullptr, 0, message_content.data, message_content.len, inner_ct, inner_tag);

    // Build real payload: [timestamp|nonce|inner_salt|inner_iv|inner_tag|inner_ct]
    std::vector<uint8_t> real;
    real.reserve(sizeof(ts) + sizeof(nonce) + sizeof(inner_salt) + inner_iv.size() + inner_tag.size() + inner_ct.size());
    auto append_raw = [&](const void* data, size_t len) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        real.insert(real.end(), p, p + len);
    };
    append_raw(&ts, sizeof(ts));
    append_raw(&nonce, sizeof(nonce));
    append_raw(&inner_salt, sizeof(inner_salt));
    append_raw(inner_iv.data(), inner_iv.size());
    append_raw(inner_tag.data(), inner_tag.size());
    append_raw(inner_ct.data(), inner_ct.size());

    // Encrypt real payload
    uint16_t salt = 0;
    CryptoRandomBytes(reinterpret_cast<uint8_t*>(&salt), sizeof(salt));
    uint8_t key[32];
    derive_msg_key(salt, key);
    std::vector<uint8_t> out;
    std::vector<uint8_t> tag;
    std::vector<uint8_t> iv(kAesGcmIvLen);
    CryptoRandomBytes(iv.data(), iv.size());
    CryptoAesGcmEncrypt(key, iv.data(), iv.size(), nullptr, 0, real.data(), real.size(), out, tag);

    // Honey fields
    std::vector<uint8_t> ip_port(message_content.len, 0);
    std::vector<uint8_t> strings(out.size(), 0);
    CryptoRandomBytes(ip_port.data(), ip_port.size());
    CryptoRandomBytes(strings.data(), strings.size());

    // Signature over (iv|ct|tag|salt)
    std::vector<uint8_t> sig_input;
    sig_input.reserve(iv.size() + out.size() + tag.size() + sizeof(salt));
    sig_input.insert(sig_input.end(), iv.begin(), iv.end());
    sig_input.insert(sig_input.end(), out.begin(), out.end());
    sig_input.insert(sig_input.end(), tag.begin(), tag.end());
    sig_input.push_back(static_cast<uint8_t>((salt >> 8) & 0xFF));
    sig_input.push_back(static_cast<uint8_t>(salt & 0xFF));
    std::vector<uint8_t> sig;
    CryptoEd25519Sign(g_client_sig_priv.data(), sig_input.data(), sig_input.size(), sig);

    // Assemble A-wrapper: [u16 user_len][user][u32 ip_len][ip][u32 strings_len][strings][u32 msg_len][iv|ct|tag][u32 sig_len][sig][sender_pub 32B]
    uint16_t user_len = static_cast<uint16_t>(target_username.len);
    uint32_t ip_len = static_cast<uint32_t>(ip_port.size());
    uint32_t strings_len = static_cast<uint32_t>(strings.size());
    uint32_t msg_len = static_cast<uint32_t>(iv.size() + out.size() + tag.size());
    uint32_t sig_len = static_cast<uint32_t>(sig.size());

    holder->buf.reserve(2 + user_len + 4 + ip_len + 4 + strings_len + 4 + msg_len + 4 + sig_len + 32);
    auto append = [&](const void* data, size_t len) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        holder->buf.insert(holder->buf.end(), p, p + len);
    };

    append(&user_len, sizeof(user_len));
    append(target_username.data, user_len);
    append(&ip_len, sizeof(ip_len));
    append(ip_port.data(), ip_port.size());
    append(&strings_len, sizeof(strings_len));
    append(strings.data(), strings.size());
    append(&msg_len, sizeof(msg_len));
    append(iv.data(), iv.size());
    append(out.data(), out.size());
    append(tag.data(), tag.size());
    append(&sig_len, sizeof(sig_len));
    append(sig.data(), sig.size());
    append(g_client_sig_pub.data(), g_client_sig_pub.size());

    EncBuffer buf{};
    buf.len = static_cast<uint32_t>(holder->buf.size());
    buf.layout_id = message_content.layout_id;
    buf.algo_id = 3; // A.json wrapper
    buf.salt = salt;
    buf.data = holder->buf.data();
    return buf;
}

// Forward declaration
EncJson unwrap_message_with_honey(const EncBuffer* input, std::unique_ptr<EncHolder>& holder);

EncJson unwrap_message_with_honey(const EncBuffer* input, std::unique_ptr<EncHolder>& holder) {
    holder = std::make_unique<EncHolder>();
    const uint8_t* p = input->data;
    size_t remaining = input->len;
    if (remaining < 2) {
        EncJson empty{};
        return empty;
    }
    uint16_t user_len;
    std::memcpy(&user_len, p, sizeof(user_len));
    p += 2;
    remaining -= 2;
    if (remaining < user_len + 4) {
        EncJson empty{};
        return empty;
    }
    p += user_len; // skip username
    remaining -= user_len;
    uint32_t ip_len;
    std::memcpy(&ip_len, p, sizeof(ip_len));
    p += 4;
    if (remaining < 4 + ip_len) {
        EncJson empty{};
        return empty;
    }
    remaining -= 4;
    p += ip_len;
    if (remaining < 4) {
        EncJson empty{};
        return empty;
    }
    uint32_t strings_len;
    std::memcpy(&strings_len, p, sizeof(strings_len));
    p += 4;
    if (remaining < 4 + strings_len) {
        EncJson empty{};
        return empty;
    }
    remaining -= 4;
    p += strings_len;
    if (remaining < 4) {
        EncJson empty{};
        return empty;
    }
    uint32_t msg_len;
    std::memcpy(&msg_len, p, sizeof(msg_len));
    p += 4;
    if (remaining - 4 < msg_len || msg_len < (kAesGcmIvLen + kAesGcmTagLen)) {
        EncJson empty{};
        return empty;
    }
    const uint8_t* iv = p;
    size_t ct_len = msg_len - kAesGcmIvLen - kAesGcmTagLen;
    const uint8_t* ct = p + kAesGcmIvLen;
    const uint8_t* tag = p + kAesGcmIvLen + ct_len;
    p += msg_len;
    remaining -= (4 + msg_len);
    if (remaining < 4) {
        EncJson empty{};
        return empty;
    }
    uint32_t sig_len;
    std::memcpy(&sig_len, p, sizeof(sig_len));
    p += 4;
    if (remaining - 4 < sig_len + 32 || sig_len == 0) {
        EncJson empty{};
        return empty;
    }
    const uint8_t* sig = p;
    p += sig_len;
    const uint8_t* sender_pub = p;

    uint8_t key[32];
    derive_msg_key(input->salt, key);
    std::vector<uint8_t> verify_buf;
    verify_buf.reserve(kAesGcmIvLen + ct_len + kAesGcmTagLen + sizeof(input->salt));
    verify_buf.insert(verify_buf.end(), iv, iv + kAesGcmIvLen);
    verify_buf.insert(verify_buf.end(), ct, ct + ct_len);
    verify_buf.insert(verify_buf.end(), tag, tag + kAesGcmTagLen);
    verify_buf.push_back(static_cast<uint8_t>((input->salt >> 8) & 0xFF));
    verify_buf.push_back(static_cast<uint8_t>(input->salt & 0xFF));
    if (!CryptoEd25519Verify(sender_pub, verify_buf.data(), verify_buf.size(), sig, sig_len)) {
        EncJson empty{};
        return empty;
    }

    std::vector<uint8_t> out;
    CryptoAesGcmDecrypt(key, iv, kAesGcmIvLen, nullptr, 0, ct, ct_len, tag, kAesGcmTagLen, out);

    // Strip timestamp + nonce + inner layer; return message payload
    size_t min_len = sizeof(uint64_t) * 2 + sizeof(uint16_t) + kAesGcmIvLen + kAesGcmTagLen;
    if (out.size() < min_len) {
        EncJson empty{};
        return empty;
    }
    const uint8_t* q = out.data();
    size_t remain = out.size();
    uint64_t ts = 0;
    uint64_t nonce = 0;
    std::memcpy(&ts, q, sizeof(ts));
    q += sizeof(uint64_t);
    std::memcpy(&nonce, q, sizeof(nonce));
    q += sizeof(uint64_t);
    remain -= sizeof(uint64_t) * 2;
    if (is_replay(ts, nonce)) {
        EncJson empty{};
        return empty;
    }
    uint16_t inner_salt = 0;
    std::memcpy(&inner_salt, q, sizeof(inner_salt));
    q += sizeof(inner_salt);
    remain -= sizeof(inner_salt);
    if (remain < kAesGcmIvLen + kAesGcmTagLen) {
        EncJson empty{};
        return empty;
    }
    const uint8_t* inner_iv = q;
    q += kAesGcmIvLen;
    remain -= kAesGcmIvLen;
    const uint8_t* inner_tag = q;
    q += kAesGcmTagLen;
    remain -= kAesGcmTagLen;
    const uint8_t* inner_ct = q;
    size_t inner_ct_len = remain;

    uint8_t inner_key[32];
    std::vector<uint8_t> inner_material;
    inner_material.insert(inner_material.end(), g_session_key, g_session_key + 32);
    inner_material.push_back(static_cast<uint8_t>((inner_salt >> 8) & 0xFF));
    inner_material.push_back(static_cast<uint8_t>(inner_salt & 0xFF));
    CryptoDeriveKeyHkdf(nullptr, 0, inner_material.data(), inner_material.size(), inner_key);
    std::vector<uint8_t> final_plain;
    if (!CryptoAesGcmDecrypt(inner_key, inner_iv, kAesGcmIvLen, nullptr, 0, inner_ct, inner_ct_len, inner_tag, kAesGcmTagLen, final_plain)) {
        EncJson empty{};
        return empty;
    }

    holder->buf = std::move(final_plain);

    EncJson json{};
    json.len = static_cast<uint32_t>(holder->buf.size());
    json.layout_id = input->layout_id;
    json.algo_id = 2; // recovered payload is plain JSON bytes
    json.salt = 0;
    json.data = holder->buf.data();
    return json;
}

} // namespace

extern "C" {

MI_Result MI_CALL MI_Init(const ConfigStruct* cfg) {
    if (!validate_cfg(cfg)) {
        return MI_ERR_INVALID_CONFIG;
    }
    if (cfg->work_dir && std::strlen(cfg->work_dir) > 0) {
        g_work_dir = cfg->work_dir;
    } else {
        g_work_dir = ".";
    }
    g_replay_file = std::filesystem::path(g_work_dir) / "replay.cache";
    load_replay_floor();
    // preload built-in server keys if provided at build time
    if (std::all_of(std::begin(g_server_pub), std::end(g_server_pub), [](uint8_t b) { return b == 0; })) {
        hex_to_bytes(MI_BUILTIN_SERVER_PUB_HEX, g_server_pub);
    }
    if (std::all_of(std::begin(g_server_sign_pub), std::end(g_server_sign_pub), [](uint8_t b) { return b == 0; })) {
        hex_to_bytes(MI_BUILTIN_SERVER_SIGN_PUB_HEX, g_server_sign_pub);
    }
    if (std::all_of(std::begin(g_server_sign_priv), std::end(g_server_sign_priv), [](uint8_t b) { return b == 0; })) {
        hex_to_bytes(MI_BUILTIN_SERVER_SIGN_PRIV_HEX, g_server_sign_priv);
    }
    g_initialized.store(true);
    g_kcp_state.store(MI_KCP_DISCONNECTED);
    std::memset(g_session_key, 0, sizeof(g_session_key));
    CryptoGenerateKeyPair(g_client_pub, g_client_priv);
    CryptoEd25519Generate(g_client_sig_pub.data(), g_client_sig_priv.data());
    return MI_OK;
}

void MI_CALL MI_Shutdown(void) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_incoming.clear();
    g_history.clear();
    g_buffers.clear();
    g_initialized.store(false);
    g_kcp_state.store(MI_KCP_DISCONNECTED);
    g_raw_send = nullptr;
    g_raw_recv = nullptr;
    g_self_username.clear();
    save_replay_floor();
}

MI_Result MI_CALL MI_Login(const EncString username, const EncString aes256_encrypted_password) {
    if (!username.data || username.len == 0 || !aes256_encrypted_password.data || aes256_encrypted_password.len == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    if (!g_initialized.load()) {
        return MI_ERR_INVALID_CONFIG;
    }
    // Expect AES-GCM blob: iv|ct|tag encrypted with session_key
    if (aes256_encrypted_password.len < kAesGcmIvLen + kAesGcmTagLen) {
        return MI_ERR_DECRYPT;
    }
    const uint8_t* iv = aes256_encrypted_password.data;
    size_t ct_len = aes256_encrypted_password.len - kAesGcmIvLen - kAesGcmTagLen;
    const uint8_t* ct = aes256_encrypted_password.data + kAesGcmIvLen;
    const uint8_t* tag = aes256_encrypted_password.data + kAesGcmIvLen + ct_len;
    ensure_session_key();
    std::vector<uint8_t> plain;
    if (!CryptoAesGcmDecrypt(g_session_key, iv, kAesGcmIvLen, nullptr, 0, ct, ct_len, tag, kAesGcmTagLen, plain)) {
        return MI_ERR_DECRYPT;
    }
    uint8_t hash[32];
    ComputeSHA256(plain.data(), plain.size(), hash);
    g_self_username = to_string(username);
    // Build auth packet: [target_len|target]["server"|PACKET_AUTH|u16 uname_len|uname|hash32]
    uint16_t uname_len = static_cast<uint16_t>(username.len);
    std::vector<uint8_t> pkt;
    const char* server_target = "server";
    uint16_t tgt_len = 6;
    pkt.reserve(2 + tgt_len + 1 + 2 + uname_len + 32);
    pkt.push_back(static_cast<uint8_t>(tgt_len & 0xFF));
    pkt.push_back(static_cast<uint8_t>((tgt_len >> 8) & 0xFF));
    pkt.insert(pkt.end(), server_target, server_target + tgt_len);
    pkt.push_back(static_cast<uint8_t>(PACKET_AUTH));
    pkt.push_back(static_cast<uint8_t>(uname_len & 0xFF));
    pkt.push_back(static_cast<uint8_t>((uname_len >> 8) & 0xFF));
    pkt.insert(pkt.end(), username.data, username.data + username.len);
    pkt.insert(pkt.end(), hash, hash + 32);

    {
        std::lock_guard<std::mutex> lock(g_auth_mu);
        g_auth_pending = true;
        g_auth_success = false;
    }
    if (g_raw_send) {
        g_raw_send(pkt.data(), pkt.size());
    } else {
        g_kcp_transport.Send(pkt.data(), pkt.size());
    }
    std::unique_lock<std::mutex> lk(g_auth_mu);
    if (!g_auth_cv.wait_for(lk, std::chrono::seconds(3), [] { return !g_auth_pending; })) {
        g_auth_pending = false;
        return MI_ERR_SERVER_UNAVAILABLE;
    }
    return g_auth_success ? MI_OK : MI_ERR_BAD_PASSWORD;
}

MI_Result MI_CALL MI_RequestUserPublicKey(const EncString username, PublicKey* key) {
    if (!username.data || username.len == 0 || !key) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::string name = to_string(username);
    fill_pub_from_string(name, key);
    return MI_OK;
}

MI_Result MI_CALL MI_KCP_Connect(const EncString server_ip, int port) {
    if (!server_ip.data || server_ip.len == 0 || port <= 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    if (std::all_of(std::begin(g_server_sign_pub), std::end(g_server_sign_pub), [](uint8_t b) { return b == 0; })) {
        return MI_ERR_INVALID_CONFIG;
    }
    if (std::all_of(std::begin(g_server_pub), std::end(g_server_pub), [](uint8_t b) { return b == 0; })) {
        return MI_ERR_INVALID_CONFIG;
    }
    if (!g_initialized.load()) {
        return MI_ERR_INVALID_CONFIG;
    }
    g_kcp_state.store(MI_KCP_CONNECTING);

    auto verifier = [](const uint8_t server_pub[32], const uint8_t server_sign_pub[32], const uint8_t* transcript, size_t len) -> bool {
        bool t_nonzero = false;
        for (size_t i = 0; i < len; ++i) {
            if (transcript[i] != 0) {
                t_nonzero = true;
                break;
            }
        }
        bool sign_nonzero = std::any_of(server_sign_pub, server_sign_pub + 32, [](uint8_t b) { return b != 0; });
        bool pub_nonzero = std::any_of(server_pub, server_pub + 32, [](uint8_t b) { return b != 0; });
        return t_nonzero && sign_nonzero && pub_nonzero;
    };
    auto signer = [](const uint8_t* data, size_t len, std::vector<uint8_t>& sig) -> bool {
        (void)data; (void)len; (void)sig;
        return false;
    };
    auto verifier_sig = [](const uint8_t* data, size_t len, const uint8_t* sig, size_t sig_len, const uint8_t server_sign_pub[32]) -> bool {
        return CryptoEd25519Verify(server_sign_pub, data, len, sig, sig_len);
    };

    KCPHandshakeResult hs{};
    auto server_sig_fetch = [&](const uint8_t nonce_in[16], uint8_t out_sig[64], size_t& sig_len) -> bool {
        std::vector<uint8_t> req;
        req.reserve(1 + 32 + 32 + 16);
        req.push_back(0x55);
        req.insert(req.end(), g_client_pub, g_client_pub + 32);
        req.insert(req.end(), g_server_pub, g_server_pub + 32);
        req.insert(req.end(), nonce_in, nonce_in + 16);
        if (g_raw_send) {
            g_raw_send(req.data(), req.size());
        } else {
            g_kcp_transport.Send(req.data(), req.size());
        }
        // Wait for reply (reuse auth flags)
        std::unique_lock<std::mutex> lk(g_auth_mu);
        g_auth_pending = true;
        g_auth_success = false;
        if (!g_auth_cv.wait_for(lk, std::chrono::milliseconds(500), [] { return !g_auth_pending; })) {
            g_auth_pending = false;
            return false;
        }
        if (!g_auth_success) return false;
        // signature delivered in g_server_sign_priv buffer
        sig_len = 64;
        std::memcpy(out_sig, g_server_sign_priv, sig_len);
        return true;
    };
    if (!g_kcp_transport.Connect(to_string(server_ip), port, g_client_pub, g_client_priv, g_server_pub, g_server_sign_pub, g_server_sign_priv, verifier, signer, verifier_sig, hs, server_sig_fetch)) {
        g_kcp_state.store(MI_KCP_DISCONNECTED);
        return MI_ERR_SERVER_UNAVAILABLE;
    }
    if (!hs.verified) {
        g_kcp_state.store(MI_KCP_DISCONNECTED);
        return MI_ERR_HANDSHAKE_FAILED;
    }
    std::memcpy(g_session_key, hs.session_key, sizeof(g_session_key));
    g_kcp_transport.SetReceive([](const uint8_t* data, size_t len) {
        if (len < 3) return;
        uint16_t tgt_len = static_cast<uint16_t>(data[0] | (data[1] << 8));
        if (2 + tgt_len >= len) return;
        const uint8_t* payload = data + 2 + tgt_len;
        size_t payload_len = len - 2 - tgt_len;
        handle_incoming_packet(payload, payload_len);
    });

    g_kcp_state.store(MI_KCP_CONNECTED);
    return MI_OK;
}

MI_Result MI_CALL MI_KCP_Disconnect(void) {
    g_kcp_state.store(MI_KCP_DISCONNECTED);
    g_kcp_transport.Disconnect();
    return MI_OK;
}

MI_KCPState MI_CALL MI_KCP_Status(void) {
    return g_kcp_state.load();
}

MI_Result MI_CALL MI_SetServerPublicKey(const PublicKey* key) {
    if (!key) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::memcpy(g_server_pub, key->data, sizeof(g_server_pub));
    return MI_OK;
}

MI_Result MI_CALL MI_GetClientPublicKey(PublicKey* key) {
    if (!key) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::memcpy(key->data, g_client_pub, sizeof(g_client_pub));
    return MI_OK;
}

MI_Result MI_CALL MI_SetServerSignPublicKey(const PublicKey* key) {
    if (!key) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::memcpy(g_server_sign_pub, key->data, sizeof(g_server_sign_pub));
    return MI_OK;
}

MI_Result MI_CALL MI_GetClientSignPublicKey(PublicKey* key) {
    if (!key) {
        return MI_ERR_INVALID_CONFIG;
    }
    if (g_client_sig_pub.size() < 32) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::memcpy(key->data, g_client_sig_pub.data(), 32);
    return MI_OK;
}

MI_Result MI_CALL MI_EncryptMessage(const EncJson* input, EncBuffer* output) {
    (void)input;
    (void)output;
    return MI_ERR_NOT_IMPLEMENTED; // 请使用 MI_SendMessage 包含 A.json 封装
}

MI_Result MI_CALL MI_DecryptMessage(const EncBuffer* input, EncJson* output) {
    (void)input;
    (void)output;
    return MI_ERR_NOT_IMPLEMENTED; // 请使用 MI_OnMessageReceived 统一解包
}

MI_Result MI_CALL MI_GenerateEphemeralKey(PublicKey* pub, PrivateKey* priv) {
    if (!pub || !priv) {
        return MI_ERR_INVALID_CONFIG;
    }
    CryptoRandomBytes(pub->data, sizeof(pub->data));
    CryptoRandomBytes(priv->data, sizeof(priv->data));
    return MI_OK;
}

MI_Result MI_CALL MI_SendMessage(const EncString target_username, const EncJson message_content) {
    if (!target_username.data || target_username.len == 0 || !message_content.data || message_content.len == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    if (g_kcp_state.load() != MI_KCP_CONNECTED) {
        return MI_ERR_SERVER_UNAVAILABLE;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    std::unique_ptr<EncHolder> holder;
    EncBuffer wrapped = wrap_message_with_honey(target_username, message_content, holder);
    // prepend target for server routing
    std::vector<uint8_t> pkt;
    uint16_t tgt_len = static_cast<uint16_t>(target_username.len);
    pkt.reserve(2 + tgt_len + 1 + wrapped.len);
    pkt.push_back(static_cast<uint8_t>(tgt_len & 0xFF));
    pkt.push_back(static_cast<uint8_t>((tgt_len >> 8) & 0xFF));
    pkt.insert(pkt.end(), target_username.data, target_username.data + tgt_len);
    std::vector<uint8_t> payload = make_message_packet(wrapped);
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    if (g_raw_send) {
        g_raw_send(pkt.data(), pkt.size());
    } else {
        g_kcp_transport.Send(pkt.data(), pkt.size());
    }
    return MI_OK;
}

MI_Result MI_CALL MI_OnMessageReceived(EncJson* out_message) {
    if (!out_message) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_incoming.empty()) {
        return MI_ERR_SERVER_UNAVAILABLE;
    }
    MessageEntry entry = std::move(g_incoming.front());
    g_incoming.erase(g_incoming.begin());
    *out_message = entry.enc;
    if (g_msg_cb) {
        g_msg_cb(&entry.enc);
    }
    return MI_OK;
}

MI_Result MI_CALL MI_SendFile(const EncString target_username, const FileDescriptor* file) {
    if (!target_username.data || target_username.len == 0 || !file || !file->path) {
        return MI_ERR_INVALID_CONFIG;
    }
    if (g_kcp_state.load() != MI_KCP_CONNECTED) {
        return MI_ERR_SERVER_UNAVAILABLE;
    }
    uint64_t file_size = file->size;
    if (file_size == 0) {
        std::error_code ec;
        file_size = std::filesystem::file_size(file->path, ec);
        if (ec) {
            return MI_ERR_STORAGE;
        }
    }
    // File HMAC using session key; reads file and aggregates chunk tags.
    uint8_t key[32];
    derive_msg_key(static_cast<uint16_t>(file_size & 0xFFFF), key);
    std::vector<uint8_t> hmac;
    uint32_t chunk_size = file->chunk_size > 0 ? file->chunk_size : 65536;
    if (!ComputeFileHmac(file->path, key, hmac, chunk_size)) {
        return MI_ERR_FILE_ENCRYPT;
    }
    std::array<uint8_t, 32> hmac_arr{};
    std::memcpy(hmac_arr.data(), hmac.data(), std::min<size_t>(32, hmac.size()));
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_file_hmac[file->path] = hmac_arr;
        uint32_t total = static_cast<uint32_t>((file_size + chunk_size - 1) / chunk_size);
        g_file_chunks[file->path] = FileChunkState{total, 0};
    }
    // copy HMAC into provided descriptor if writable
    if (file->hmac) {
        std::memcpy(const_cast<uint8_t*>(file->hmac), hmac_arr.data(), 32);
    }
    // Send chunks over KCP (or simulate)
    FileDescriptor fd_copy = *file;
    fd_copy.size = file_size;
    fd_copy.chunk_size = chunk_size;
    FileChunker::ForEachChunk(file->path, chunk_size, [&](const uint8_t* data, size_t len, uint32_t index, uint32_t total) {
        std::vector<uint8_t> pkt_body = make_file_packet(target_username, &fd_copy, data, len, index, total, hmac_arr.data());
        std::vector<uint8_t> pkt;
        uint16_t tgt_len = static_cast<uint16_t>(target_username.len);
        pkt.reserve(2 + tgt_len + pkt_body.size());
        pkt.push_back(static_cast<uint8_t>(tgt_len & 0xFF));
        pkt.push_back(static_cast<uint8_t>((tgt_len >> 8) & 0xFF));
        pkt.insert(pkt.end(), target_username.data, target_username.data + tgt_len);
        pkt.insert(pkt.end(), pkt_body.begin(), pkt_body.end());
        if (g_raw_send) {
            g_raw_send(pkt.data(), pkt.size());
        } else {
            g_kcp_transport.Send(pkt.data(), pkt.size());
        }
    });
    return MI_OK;
}

MI_Result MI_CALL MI_OnFileReceived(FileDescriptor* file) {
    if (!file) {
        return MI_ERR_INVALID_CONFIG;
    }
    uint8_t key[32];
    derive_msg_key(static_cast<uint16_t>(file->size & 0xFFFF), key);
    std::vector<uint8_t> hmac;
    uint32_t chunk_size = file->chunk_size > 0 ? file->chunk_size : 65536;
    if (!ComputeFileHmac(file->path, key, hmac, chunk_size)) {
        return MI_ERR_FILE_ENCRYPT;
    }
    std::array<uint8_t, 32> expect{};
    if (file->hmac) {
        std::memcpy(expect.data(), file->hmac, 32);
    } else {
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_file_hmac.find(file->path);
        if (it != g_file_hmac.end()) {
            expect = it->second;
        }
    }
    if ((file->hmac || !expect.empty()) && std::memcmp(expect.data(), hmac.data(), 32) != 0) {
        return MI_ERR_FILE_ENCRYPT;
    }
    uint32_t total = file->chunk_count > 0 ? file->chunk_count : 1;
    uint32_t idx = file->chunk_index;
    std::lock_guard<std::mutex> lock(g_mu);
    auto& st = g_file_chunks[file->path];
    if (st.total == 0) {
        st.total = total;
    }
    st.received = std::min(st.received + 1, st.total);
    if (st.received >= st.total) {
        g_file_chunks.erase(file->path);
        file->delivered = 1;
    } else {
        file->delivered = 0;
    }
    return MI_OK;
}

MI_Result MI_CALL MI_SaveLocalHistory(const EncJson message) {
    if (!message.data || message.len == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    MessageEntry entry{};
    entry.holder = std::make_unique<EncHolder>();
    entry.enc = make_encjson_copy(&message, *entry.holder);
    g_history.push_back(std::move(entry));
    return MI_OK;
}

MI_Result MI_CALL MI_LoadLocalHistory(const EncString target, EncJsonList* out_list) {
    if (!target.data || target.len == 0 || !out_list) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_history.empty()) {
        out_list->items = nullptr;
        out_list->count = 0;
        return MI_OK;
    }
    EncJson* arr = new EncJson[g_history.size()];
    for (size_t i = 0; i < g_history.size(); ++i) {
        const auto& src = g_history[i].enc;
        uint8_t* buf = new uint8_t[src.len];
        std::memcpy(buf, src.data, src.len);
        arr[i] = src;
        arr[i].data = buf;
    }
    out_list->items = arr;
    out_list->count = g_history.size();
    return MI_OK;
}

MI_Result MI_CALL MI_GetGroupKey(const EncString group_id, GroupKey* out) {
    if (!group_id.data || group_id.len == 0 || !out) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::string gid = to_string(group_id);
    auto it = g_groups.find(gid);
    if (it == g_groups.end()) {
        GroupState st{};
        CryptoRandomBytes(st.key.data, sizeof(st.key.data));
        st.key.version = 1;
        st.member_count = 1;
        g_groups[gid] = st;
        *out = st.key;
    } else {
        *out = it->second.key;
    }
    return MI_OK;
}

MI_Result MI_CALL MI_SendGroupMessage(const EncString group_id, const EncJson message) {
    if (!group_id.data || group_id.len == 0 || !message.data || message.len == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    GroupKey key{};
    MI_Result res = MI_GetGroupKey(group_id, &key);
    if (res != MI_OK) return res;
    // rotate key and reset acked
    auto& st = g_groups[to_string(group_id)];
    st.key.version += 1;
    CryptoRandomBytes(st.key.data, sizeof(st.key.data));
    st.acked = 1; // sender ack
    key = st.key;
    // broadcast new key fingerprint with version embedded in salt
    EncJson msg_with_meta = message;
    msg_with_meta.salt = static_cast<uint16_t>(key.version & 0xFFFF);
    return MI_SendMessage(group_id, msg_with_meta);
}

MI_Result MI_CALL MI_SetGroupMembers(const EncString group_id, uint32_t member_count) {
    if (!group_id.data || group_id.len == 0 || member_count == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::string gid = to_string(group_id);
    auto& st = g_groups[gid];
    bool changed = st.member_count != member_count;
    st.member_count = member_count;
    if (st.key.version == 0 || changed) {
        CryptoRandomBytes(st.key.data, sizeof(st.key.data));
        st.key.version = (st.key.version == 0) ? 1 : st.key.version + 1;
        st.acked = 0;
        // 成员变更时，发送一次“密钥更新提示”消息（仅携带版本信息）
        EncJson notice{};
        const char* payload = "{\"type\":\"group_key_update\"}";
        notice.data = reinterpret_cast<const uint8_t*>(payload);
        notice.len = static_cast<uint32_t>(std::strlen(payload));
        notice.layout_id = 0;
        notice.algo_id = 0;
        notice.salt = static_cast<uint16_t>(st.key.version & 0xFFFF);
        MI_SendMessage(group_id, notice);
    }
    return MI_OK;
}

MI_Result MI_CALL MI_GroupAck(const EncString group_id, uint32_t version) {
    if (!group_id.data || group_id.len == 0) return MI_ERR_INVALID_CONFIG;
    std::string gid = to_string(group_id);
    auto it = g_groups.find(gid);
    if (it == g_groups.end()) return MI_ERR_INVALID_CONFIG;
    if (it->second.key.version != version) return MI_ERR_KEY_MISMATCH;
    it->second.acked = std::min(it->second.acked + 1, it->second.member_count);
    if (it->second.acked >= it->second.member_count) {
        // all members acked, rotate key for forward secrecy
        it->second.key.version += 1;
        CryptoRandomBytes(it->second.key.data, sizeof(it->second.key.data));
        it->second.acked = 0;
    }
    return MI_OK;
}

MI_Result MI_CALL MI_GetUserInfo(const EncString username, UserInfo* out) {
    if (!username.data || username.len == 0 || !out) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::string name = to_string(username);
    static thread_local std::string cached;
    cached = name;
    out->username = cached.c_str();
    fill_pub_from_string(name, &out->pubkey);
    out->password_sha256 = nullptr;
    out->password_len = 0;
    return MI_OK;
}

int MI_CALL MI_ErasePlain(void* buf, size_t len) {
    if (!buf || len == 0) {
        return -1;
    }
    volatile uint8_t* p = static_cast<volatile uint8_t*>(buf);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0xFF;
    }
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
    return 0;
}

void MI_CALL MI_FreeEncJsonList(EncJsonList* list) {
    if (!list || !list->items) {
        return;
    }
    for (size_t i = 0; i < list->count; ++i) {
        if (list->items[i].data) {
            delete[] list->items[i].data;
            list->items[i].data = nullptr;
        }
    }
    delete[] list->items;
    list->items = nullptr;
    list->count = 0;
}

MI_Result MI_CALL MI_CreateEncString(const char* raw, EncString* out) {
    if (!raw || !out) {
        return MI_ERR_INVALID_CONFIG;
    }
    size_t len = std::strlen(raw);
    if (len == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    uint8_t* buf = new uint8_t[len];
    std::memcpy(buf, raw, len);
    out->len = static_cast<uint32_t>(len);
    out->layout_id = 0;
    out->algo_id = kAlgoId;
    CryptoRandomBytes(reinterpret_cast<uint8_t*>(&out->salt), sizeof(out->salt));
    out->data = buf;
    return MI_OK;
}

MI_Result MI_CALL MI_FreeEncString(EncString* enc) {
    if (!enc) return MI_ERR_INVALID_CONFIG;
    if (enc->data) {
        delete[] enc->data;
        enc->data = nullptr;
    }
    enc->len = 0;
    return MI_OK;
}

MI_Result MI_CALL MI_DecodeEncString(const EncString* enc, char* out_buf, size_t out_len) {
    if (!enc || !enc->data || !out_buf || out_len == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    size_t copy_len = std::min(static_cast<size_t>(enc->len), out_len - 1);
    std::memcpy(out_buf, enc->data, copy_len);
    out_buf[copy_len] = '\0';
    return MI_OK;
}

MI_Result MI_CALL MI_CreateEncJsonFromString(const char* raw_json, EncJson* out) {
    if (!raw_json || !out) {
        return MI_ERR_INVALID_CONFIG;
    }
    size_t len = std::strlen(raw_json);
    if (len == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    uint8_t* buf = new uint8_t[len];
    std::memcpy(buf, raw_json, len);
    out->len = static_cast<uint32_t>(len);
    out->layout_id = 0;
    out->algo_id = 0;
    CryptoRandomBytes(reinterpret_cast<uint8_t*>(&out->salt), sizeof(out->salt));
    out->data = buf;
    return MI_OK;
}

MI_Result MI_CALL MI_FreeEncJson(EncJson* enc) {
    if (!enc) return MI_ERR_INVALID_CONFIG;
    if (enc->data) {
        delete[] enc->data;
        enc->data = nullptr;
    }
    enc->len = 0;
    return MI_OK;
}

MI_Result MI_CALL MI_RegisterMessageCallback(MI_MessageCallback cb) {
    g_msg_cb = cb;
    return MI_OK;
}

MI_Result MI_CALL MI_SetRawSend(MI_SendRawCallback cb) {
    g_raw_send = cb;
    return MI_OK;
}

MI_Result MI_CALL MI_SecureEraseFile(const char* path, uint64_t size_hint) {
    return SecureEraseFile(path, size_hint);
}

MI_Result MI_CALL MI_DecodeEncJson(const EncJson* enc, char* out_buf, size_t out_len) {
    if (!enc || !enc->data || !out_buf || out_len == 0) {
        return MI_ERR_INVALID_CONFIG;
    }
    size_t copy_len = std::min(static_cast<size_t>(enc->len), out_len - 1);
    std::memcpy(out_buf, enc->data, copy_len);
    out_buf[copy_len] = '\0';
    return MI_OK;
}

MI_Result MI_CALL MI_SetRawReceive(MI_RecvRawCallback cb) {
    g_raw_recv = cb;
    return MI_OK;
}

} // extern "C"
