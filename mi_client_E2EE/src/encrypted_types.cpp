#include "mi_client_api.h"
#include "crypto_stub.h"
#include "sha256.h"

#include <array>
#include <cstring>

namespace {

static const uint8_t kPerms[16][4] = {
    {0,1,2,3},{0,1,3,2},{0,2,1,3},{0,2,3,1},
    {0,3,1,2},{0,3,2,1},{1,0,2,3},{1,0,3,2},
    {1,2,0,3},{1,3,0,2},{2,0,1,3},{2,1,0,3},
    {2,3,0,1},{3,0,1,2},{3,1,0,2},{3,2,0,1}
};

void derive_mask(uint16_t salt, uint8_t out[4]) {
    uint8_t buf[2];
    buf[0] = static_cast<uint8_t>((salt >> 8) & 0xFF);
    buf[1] = static_cast<uint8_t>(salt & 0xFF);
    uint8_t hash[32];
    ComputeSHA256(buf, sizeof(buf), hash);
    std::memcpy(out, hash, 4);
}

MI_Result encode_u32(uint32_t plain, EncInt* out) {
    if (!out) return MI_ERR_INVALID_CONFIG;
    uint16_t salt = 0;
    CryptoRandomBytes(reinterpret_cast<uint8_t*>(&salt), sizeof(salt));
    uint8_t mask[4];
    derive_mask(salt, mask);
    uint8_t bytes[4];
    bytes[0] = static_cast<uint8_t>(plain & 0xFF);
    bytes[1] = static_cast<uint8_t>((plain >> 8) & 0xFF);
    bytes[2] = static_cast<uint8_t>((plain >> 16) & 0xFF);
    bytes[3] = static_cast<uint8_t>((plain >> 24) & 0xFF);
    uint8_t layout = 0;
    CryptoRandomBytes(&layout, 1);
    layout &= 0x0F;
    const uint8_t* perm = kPerms[layout];
    uint8_t scrambled[4];
    for (int i = 0; i < 4; ++i) {
        scrambled[i] = bytes[perm[i]] ^ mask[i];
    }
    uint32_t payload = static_cast<uint32_t>(scrambled[0])
                     | (static_cast<uint32_t>(scrambled[1]) << 8)
                     | (static_cast<uint32_t>(scrambled[2]) << 16)
                     | (static_cast<uint32_t>(scrambled[3]) << 24);
    out->layout_id = layout;
    out->algo_id = 1; // AES-layout scramble marker
    out->salt = salt;
    out->payload = payload;
    return MI_OK;
}

MI_Result decode_u32(const EncInt* enc, uint32_t* out_val) {
    if (!enc || !out_val) return MI_ERR_INVALID_CONFIG;
    if (enc->layout_id >= 16) return MI_ERR_INVALID_CONFIG;
    uint8_t mask[4];
    derive_mask(enc->salt, mask);
    uint8_t scrambled[4];
    scrambled[0] = static_cast<uint8_t>(enc->payload & 0xFF);
    scrambled[1] = static_cast<uint8_t>((enc->payload >> 8) & 0xFF);
    scrambled[2] = static_cast<uint8_t>((enc->payload >> 16) & 0xFF);
    scrambled[3] = static_cast<uint8_t>((enc->payload >> 24) & 0xFF);
    uint8_t bytes[4];
    const uint8_t* perm = kPerms[enc->layout_id];
    for (int i = 0; i < 4; ++i) {
        bytes[perm[i]] = static_cast<uint8_t>(scrambled[i] ^ mask[i]);
    }
    *out_val = static_cast<uint32_t>(bytes[0])
             | (static_cast<uint32_t>(bytes[1]) << 8)
             | (static_cast<uint32_t>(bytes[2]) << 16)
             | (static_cast<uint32_t>(bytes[3]) << 24);
    return MI_OK;
}

} // namespace

extern "C" {

MI_Result MI_CALL MI_CreateEncInt32(uint32_t plain, EncInt* out) {
    return encode_u32(plain, out);
}

MI_Result MI_CALL MI_DecodeEncInt32(const EncInt* enc, uint32_t* out) {
    return decode_u32(enc, out);
}

MI_Result MI_CALL MI_CreateEncLong(uint64_t plain, EncLong* out) {
    if (!out) return MI_ERR_INVALID_CONFIG;
    uint32_t hi = static_cast<uint32_t>((plain >> 32) & 0xFFFFFFFFULL);
    uint32_t lo = static_cast<uint32_t>(plain & 0xFFFFFFFFULL);
    EncInt hi_enc{};
    EncInt lo_enc{};
    MI_Result r1 = encode_u32(lo, &lo_enc);
    MI_Result r2 = encode_u32(hi, &hi_enc);
    if (r1 != MI_OK || r2 != MI_OK) return MI_ERR_ENCRYPT;
    out->layout_id = (hi_enc.layout_id & 0x0F) | ((lo_enc.layout_id & 0x0F) << 4);
    out->algo_id = 1;
    out->salt = lo_enc.salt; // lower part salt
    out->payload = (static_cast<uint64_t>(hi_enc.payload) << 32) | lo_enc.payload;
    return MI_OK;
}

MI_Result MI_CALL MI_DecodeEncLong(const EncLong* enc, uint64_t* out) {
    if (!enc || !out) return MI_ERR_INVALID_CONFIG;
    EncInt lo_enc{};
    EncInt hi_enc{};
    lo_enc.layout_id = (enc->layout_id >> 4) & 0x0F;
    hi_enc.layout_id = enc->layout_id & 0x0F;
    lo_enc.algo_id = hi_enc.algo_id = enc->algo_id;
    lo_enc.salt = enc->salt;
    hi_enc.salt = enc->salt ^ 0x5A5A; // derive slightly different salt for high part
    lo_enc.payload = static_cast<uint32_t>(enc->payload & 0xFFFFFFFFULL);
    hi_enc.payload = static_cast<uint32_t>((enc->payload >> 32) & 0xFFFFFFFFULL);
    uint32_t lo = 0, hi = 0;
    if (decode_u32(&lo_enc, &lo) != MI_OK) return MI_ERR_DECRYPT;
    if (decode_u32(&hi_enc, &hi) != MI_OK) return MI_ERR_DECRYPT;
    *out = (static_cast<uint64_t>(hi) << 32) | lo;
    return MI_OK;
}

} // extern "C"
