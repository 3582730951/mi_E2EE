#pragma once

#include <stddef.h>
#include <stdint.h>
#include <vector>

// HMAC-SHA256
void HmacSha256(const uint8_t* key, size_t key_len,
                const uint8_t* data, size_t data_len,
                uint8_t out[32]);

std::vector<uint8_t> HmacSha256Vector(const uint8_t* key, size_t key_len,
                                      const uint8_t* data, size_t data_len);
