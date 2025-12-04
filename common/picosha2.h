#pragma once

#include <algorithm>
#include <iterator>
#include <sstream>
#include <vector>
#include <stdint.h>

namespace picosha2 {

typedef uint32_t word_t;
typedef uint8_t byte_t;

namespace detail {

inline word_t ch(word_t x, word_t y, word_t z) {
    return (x & y) ^ ((~x) & z);
}

inline word_t maj(word_t x, word_t y, word_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline word_t rotr(word_t x, word_t n) {
    return (x >> n) | (x << (32 - n));
}

inline word_t bsig0(word_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline word_t bsig1(word_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline word_t ssig0(word_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline word_t ssig1(word_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

} // namespace detail

static const word_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

class hash256_one_by_one {
public:
    hash256_one_by_one() { init(); }

    void init() {
        buffer_.clear();
        transformed_bytes_ = 0;
        h_[0] = 0x6a09e667;
        h_[1] = 0xbb67ae85;
        h_[2] = 0x3c6ef372;
        h_[3] = 0xa54ff53a;
        h_[4] = 0x510e527f;
        h_[5] = 0x9b05688c;
        h_[6] = 0x1f83d9ab;
        h_[7] = 0x5be0cd19;
    }

    template<typename RaIter>
    void process(RaIter first, RaIter last) {
        while (first != last) {
            buffer_.push_back(static_cast<byte_t>(*first));
            ++first;
            if (buffer_.size() == 64) {
                transform();
                transformed_bytes_ += 64;
                buffer_.clear();
            }
        }
    }

    void finish() {
        uint64_t total_bits = transformed_bytes_ * 8 + buffer_.size() * 8;
        buffer_.push_back(0x80);
        if (buffer_.size() > 56) {
            buffer_.resize(64, 0);
            transform();
            buffer_.clear();
        }
        buffer_.resize(56, 0);
        for (int i = 0; i < 8; ++i) {
            buffer_.push_back(static_cast<byte_t>((total_bits >> ((7 - i) * 8)) & 0xff));
        }
        transform();
        buffer_.clear();
    }

    void get_hash_bytes(std::vector<byte_t>& dst) const {
        dst.clear();
        for (int i = 0; i < 8; ++i) {
            dst.push_back(static_cast<byte_t>((h_[i] >> 24) & 0xff));
            dst.push_back(static_cast<byte_t>((h_[i] >> 16) & 0xff));
            dst.push_back(static_cast<byte_t>((h_[i] >> 8) & 0xff));
            dst.push_back(static_cast<byte_t>(h_[i] & 0xff));
        }
    }

private:
    void transform() {
        word_t w[64];
        for (size_t i = 0; i < 16; ++i) {
            w[i] = (static_cast<word_t>(buffer_[4 * i]) << 24) |
                   (static_cast<word_t>(buffer_[4 * i + 1]) << 16) |
                   (static_cast<word_t>(buffer_[4 * i + 2]) << 8) |
                   (static_cast<word_t>(buffer_[4 * i + 3]));
        }
        for (size_t i = 16; i < 64; ++i) {
            w[i] = detail::ssig1(w[i - 2]) + w[i - 7] + detail::ssig0(w[i - 15]) + w[i - 16];
        }

        word_t a = h_[0];
        word_t b = h_[1];
        word_t c = h_[2];
        word_t d = h_[3];
        word_t e = h_[4];
        word_t f = h_[5];
        word_t g = h_[6];
        word_t h = h_[7];

        for (size_t i = 0; i < 64; ++i) {
            word_t t1 = h + detail::bsig1(e) + detail::ch(e, f, g) + k[i] + w[i];
            word_t t2 = detail::bsig0(a) + detail::maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
        h_[5] += f;
        h_[6] += g;
        h_[7] += h;
    }

    std::vector<byte_t> buffer_;
    uint64_t transformed_bytes_;
    word_t h_[8];
};

template<typename RaIter>
void hash256(RaIter first, RaIter last, std::vector<byte_t>& digest) {
    hash256_one_by_one hasher;
    hasher.process(first, last);
    hasher.finish();
    hasher.get_hash_bytes(digest);
}

inline std::string bytes_to_hex_string(const std::vector<byte_t>& bytes) {
    static const char* lut = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (byte_t b : bytes) {
        s.push_back(lut[(b >> 4) & 0x0F]);
        s.push_back(lut[b & 0x0F]);
    }
    return s;
}

} // namespace picosha2
