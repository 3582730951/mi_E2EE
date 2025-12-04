#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

void CryptoRandomBytes(uint8_t* out, size_t len);
void CryptoDeriveKey(const uint8_t* data, size_t len, uint8_t out[32]);
void CryptoXor(const uint8_t* in, size_t len, const uint8_t key[32], std::vector<uint8_t>& out);
std::string HexEncode(const uint8_t* data, size_t len);

bool CryptoAesGcmEncrypt(const uint8_t key[32],
                         const uint8_t* iv, size_t iv_len,
                         const uint8_t* aad, size_t aad_len,
                         const uint8_t* plaintext, size_t len,
                         std::vector<uint8_t>& ciphertext,
                         std::vector<uint8_t>& tag);

bool CryptoAesGcmDecrypt(const uint8_t key[32],
                         const uint8_t* iv, size_t iv_len,
                         const uint8_t* aad, size_t aad_len,
                         const uint8_t* ciphertext, size_t len,
                         const uint8_t* tag, size_t tag_len,
                         std::vector<uint8_t>& plaintext);

void CryptoDeriveKeyHkdf(const uint8_t* salt, size_t salt_len,
                         const uint8_t* input, size_t input_len,
                         uint8_t out[32]);

std::vector<uint8_t> CryptoHmacSha256(const uint8_t* key, size_t key_len,
                                      const uint8_t* data, size_t data_len);

// ECDH placeholder (X25519-like interface using HKDF over concatenated secrets)
void CryptoGenerateKeyPair(uint8_t pub[32], uint8_t priv[32]);
void CryptoECDH(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t out[32]);

// Ed25519 signing (requires OpenSSL); fallback uses HMAC with pub as key
bool CryptoEd25519Generate(uint8_t pub[32], uint8_t priv[32]);
bool CryptoEd25519Sign(const uint8_t priv[32], const uint8_t* data, size_t len, std::vector<uint8_t>& sig);
bool CryptoEd25519Verify(const uint8_t pub[32], const uint8_t* data, size_t len, const uint8_t* sig, size_t sig_len);
