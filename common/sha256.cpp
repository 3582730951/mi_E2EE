#include "sha256.h"
#include "picosha2.h"

void ComputeSHA256(const uint8_t* data, size_t len, uint8_t out[32]) {
    std::vector<uint8_t> digest;
    picosha2::hash256(data, data + len, digest);
    for (size_t i = 0; i < 32; ++i) {
        out[i] = digest[i];
    }
}
