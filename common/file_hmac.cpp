#include "file_hmac.h"

#include "crypto_stub.h"

#include <fstream>
#include <cstring>
#include <vector>

bool ComputeFileHmac(const char* path, const uint8_t key[32], std::vector<uint8_t>& out_hmac, uint32_t chunk_size) {
    if (!path || !key || chunk_size == 0) {
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }
    std::vector<uint8_t> aggregate;
    std::vector<uint8_t> buffer(chunk_size);
    uint64_t idx = 0;
    while (in) {
        in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize read = in.gcount();
        if (read <= 0) break;
        uint8_t idx_bytes[8];
        for (int i = 0; i < 8; ++i) {
            idx_bytes[i] = static_cast<uint8_t>((idx >> (8 * i)) & 0xFF);
        }
        std::vector<uint8_t> chunk_tag = CryptoHmacSha256(key, 32, buffer.data(), static_cast<size_t>(read));
        aggregate.insert(aggregate.end(), idx_bytes, idx_bytes + 8);
        aggregate.insert(aggregate.end(), chunk_tag.begin(), chunk_tag.end());
        idx++;
    }
    out_hmac = CryptoHmacSha256(key, 32, aggregate.data(), aggregate.size());
    return true;
}

bool VerifyFileHmac(const char* path, const uint8_t key[32], const std::vector<uint8_t>& expect_hmac, uint32_t chunk_size) {
    std::vector<uint8_t> calc;
    if (!ComputeFileHmac(path, key, calc, chunk_size)) {
        return false;
    }
    return calc.size() == expect_hmac.size() && std::memcmp(calc.data(), expect_hmac.data(), calc.size()) == 0;
}
