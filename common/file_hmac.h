#pragma once

#include <stdint.h>
#include <vector>

bool ComputeFileHmac(const char* path, const uint8_t key[32], std::vector<uint8_t>& out_hmac, uint32_t chunk_size = 65536);
bool VerifyFileHmac(const char* path, const uint8_t key[32], const std::vector<uint8_t>& expect_hmac, uint32_t chunk_size = 65536);
