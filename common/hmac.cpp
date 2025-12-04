#include "hmac.h"
#include "sha256.h"

#include <vector>

void HmacSha256(const uint8_t* key, size_t key_len,
                const uint8_t* data, size_t data_len,
                uint8_t out[32]) {
    const size_t block = 64;
    std::vector<uint8_t> k(block, 0);
    if (key_len > block) {
        ComputeSHA256(key, key_len, k.data());
    } else {
        std::copy(key, key + key_len, k.begin());
    }

    std::vector<uint8_t> o_key_pad(block);
    std::vector<uint8_t> i_key_pad(block);
    for (size_t i = 0; i < block; ++i) {
        o_key_pad[i] = static_cast<uint8_t>(k[i] ^ 0x5c);
        i_key_pad[i] = static_cast<uint8_t>(k[i] ^ 0x36);
    }

    // inner hash
    std::vector<uint8_t> inner;
    inner.reserve(block + data_len);
    inner.insert(inner.end(), i_key_pad.begin(), i_key_pad.end());
    inner.insert(inner.end(), data, data + data_len);
    uint8_t inner_hash[32];
    ComputeSHA256(inner.data(), inner.size(), inner_hash);

    // outer hash
    std::vector<uint8_t> outer;
    outer.reserve(block + sizeof(inner_hash));
    outer.insert(outer.end(), o_key_pad.begin(), o_key_pad.end());
    outer.insert(outer.end(), inner_hash, inner_hash + sizeof(inner_hash));
    ComputeSHA256(outer.data(), outer.size(), out);
}

std::vector<uint8_t> HmacSha256Vector(const uint8_t* key, size_t key_len,
                                      const uint8_t* data, size_t data_len) {
    std::vector<uint8_t> out(32);
    HmacSha256(key, key_len, data, data_len, out.data());
    return out;
}
