#include "crypto_stub.h"
#include "sha256.h"
#include "hmac.h"

#include <array>
#include <cstring>
#include <random>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

#ifdef MI_USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

void CryptoRandomBytes(uint8_t* out, size_t len) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    for (size_t i = 0; i < len; ++i) {
        out[i] = static_cast<uint8_t>(dist(gen));
    }
}

void CryptoDeriveKey(const uint8_t* data, size_t len, uint8_t out[32]) {
    ComputeSHA256(data, len, out);
}

void CryptoXor(const uint8_t* in, size_t len, const uint8_t key[32], std::vector<uint8_t>& out) {
    out.resize(len);
    for (size_t i = 0; i < len; ++i) {
        out[i] = static_cast<uint8_t>(in[i] ^ key[i % 32]);
    }
}

std::string HexEncode(const uint8_t* data, size_t len) {
    static const char* lut = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(lut[(data[i] >> 4) & 0x0F]);
        s.push_back(lut[data[i] & 0x0F]);
    }
    return s;
}

void CryptoDeriveKeyHkdf(const uint8_t* salt, size_t salt_len,
                         const uint8_t* input, size_t input_len,
                         uint8_t out[32]) {
    std::vector<uint8_t> buf;
    buf.reserve(salt_len + input_len);
    buf.insert(buf.end(), salt, salt + salt_len);
    buf.insert(buf.end(), input, input + input_len);
    ComputeSHA256(buf.data(), buf.size(), out);
}

std::vector<uint8_t> CryptoHmacSha256(const uint8_t* key, size_t key_len,
                                      const uint8_t* data, size_t data_len) {
    return HmacSha256Vector(key, key_len, data, data_len);
}

void CryptoGenerateKeyPair(uint8_t pub[32], uint8_t priv[32]) {
    CryptoRandomBytes(priv, 32);
    uint8_t hash[32];
    ComputeSHA256(priv, 32, hash);
    std::memcpy(pub, hash, 32);
}

void CryptoECDH(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t out[32]) {
    uint8_t material[64];
    std::memcpy(material, priv, 32);
    std::memcpy(material + 32, peer_pub, 32);
    CryptoDeriveKeyHkdf(nullptr, 0, material, sizeof(material), out);
}

bool CryptoEd25519Generate(uint8_t pub[32], uint8_t priv[32]) {
#ifdef MI_USE_OPENSSL
    CryptoRandomBytes(priv, 32);
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, priv, 32);
    if (!pkey) return false;
    size_t pub_len = 32;
    int rc = EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);
    EVP_PKEY_free(pkey);
    return rc == 1 && pub_len == 32;
#else
    // fallback: derive pub as hash
    CryptoGenerateKeyPair(pub, priv);
    return true;
#endif
}

bool CryptoEd25519Sign(const uint8_t priv[32], const uint8_t* data, size_t len, std::vector<uint8_t>& sig) {
#ifdef MI_USE_OPENSSL
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, priv, 32);
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }
    int rc = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey);
    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    size_t sig_len = 64;
    sig.resize(sig_len);
    rc = EVP_DigestSign(ctx, sig.data(), &sig_len, data, len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    if (rc != 1) return false;
    sig.resize(sig_len);
    return true;
#else
    // fallback: HMAC with priv as key
    sig = CryptoHmacSha256(priv, 32, data, len);
    return true;
#endif
}

bool CryptoEd25519Verify(const uint8_t pub[32], const uint8_t* data, size_t len, const uint8_t* sig, size_t sig_len) {
#ifdef MI_USE_OPENSSL
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub, 32);
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }
    int rc = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey);
    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    rc = EVP_DigestVerify(ctx, sig, sig_len, data, len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc == 1;
#else
    std::vector<uint8_t> expected = CryptoHmacSha256(pub, 32, data, len);
    return expected.size() == sig_len && std::memcmp(expected.data(), sig, sig_len) == 0;
#endif
}

bool CryptoAesGcmEncrypt(const uint8_t key[32],
                         const uint8_t* iv, size_t iv_len,
                         const uint8_t* aad, size_t aad_len,
                         const uint8_t* plaintext, size_t len,
                         std::vector<uint8_t>& ciphertext,
                         std::vector<uint8_t>& tag) {
#ifdef MI_USE_OPENSSL
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv_len), nullptr);
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    rc = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int outlen = 0;
    if (aad && aad_len > 0) {
        rc = EVP_EncryptUpdate(ctx, nullptr, &outlen, aad, static_cast<int>(aad_len));
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }
    ciphertext.resize(len);
    rc = EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext, static_cast<int>(len));
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int tmplen = 0;
    rc = EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &tmplen);
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext.resize(outlen + tmplen);
    tag.resize(16);
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);
    return rc == 1;
#elif defined(_WIN32)
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status < 0) return false;
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 32, 0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    ULONG tag_len = 16;
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT tagLengths{};
    ULONG res = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_AUTH_TAG_LENGTH, (PUCHAR)&tagLengths, sizeof(tagLengths), &res, 0);
    if (status == 0) {
        tag_len = tagLengths.dwMinLength;
    }
    ciphertext.resize(len);
    tag.resize(tag_len);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)iv;
    info.cbNonce = (ULONG)iv_len;
    info.pbAuthData = (PUCHAR)aad;
    info.cbAuthData = (ULONG)aad_len;
    info.pbTag = tag.data();
    info.cbTag = tag_len;

    ULONG out_len = 0;
    status = BCryptEncrypt(hKey,
                           (PUCHAR)plaintext,
                           (ULONG)len,
                           &info,
                           nullptr,
                           0,
                           ciphertext.data(),
                           (ULONG)ciphertext.size(),
                           &out_len,
                           0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (status < 0) return false;
    ciphertext.resize(out_len);
    return true;
#else
    return false;
#endif
}

bool CryptoAesGcmDecrypt(const uint8_t key[32],
                         const uint8_t* iv, size_t iv_len,
                         const uint8_t* aad, size_t aad_len,
                         const uint8_t* ciphertext, size_t len,
                         const uint8_t* tag, size_t tag_len,
                         std::vector<uint8_t>& plaintext) {
#ifdef MI_USE_OPENSSL
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int rc = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv_len), nullptr);
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    rc = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int outlen = 0;
    if (aad && aad_len > 0) {
        rc = EVP_DecryptUpdate(ctx, nullptr, &outlen, aad, static_cast<int>(aad_len));
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }
    plaintext.resize(len);
    rc = EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext, static_cast<int>(len));
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_len), const_cast<uint8_t*>(tag));
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int tmplen = 0;
    rc = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1) {
        return false;
    }
    plaintext.resize(outlen + tmplen);
    return true;
#elif defined(_WIN32)
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status < 0) return false;
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 32, 0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    plaintext.resize(len);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)iv;
    info.cbNonce = (ULONG)iv_len;
    info.pbAuthData = (PUCHAR)aad;
    info.cbAuthData = (ULONG)aad_len;
    info.pbTag = (PUCHAR)tag;
    info.cbTag = (ULONG)tag_len;

    ULONG out_len = 0;
    status = BCryptDecrypt(hKey,
                           (PUCHAR)ciphertext,
                           (ULONG)len,
                           &info,
                           nullptr,
                           0,
                           plaintext.data(),
                           (ULONG)plaintext.size(),
                           &out_len,
                           0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (status < 0) return false;
    plaintext.resize(out_len);
    return true;
#else
    return false;
#endif
}
