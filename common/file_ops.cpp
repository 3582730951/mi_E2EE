#include "file_ops.h"

#include <algorithm>
#include <fstream>
#include <random>

namespace {

bool write_ff(std::fstream& fs, uint64_t offset, size_t len) {
    fs.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!fs.good()) return false;
    for (size_t i = 0; i < len; ++i) {
        fs.put(static_cast<char>(0xFF));
    }
    return fs.good();
}

size_t rand_len() {
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0x10, 0x100);
    return static_cast<size_t>(dist(rd));
}

} // namespace

MI_Result SecureEraseFile(const char* path, uint64_t size_hint) {
    if (!path) {
        return MI_ERR_INVALID_CONFIG;
    }
    std::fstream fs(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!fs.is_open()) {
        return MI_ERR_STORAGE;
    }
    fs.seekg(0, std::ios::end);
    uint64_t size = size_hint > 0 ? size_hint : static_cast<uint64_t>(fs.tellg());
    fs.seekg(0, std::ios::beg);

    const uint64_t large_threshold = 1024 * 1024; // 1MB
    if (size > large_threshold) {
        size_t len = rand_len();
        if (!write_ff(fs, 0, len)) return MI_ERR_FILE_WIPE;
        if (!write_ff(fs, size / 2, len)) return MI_ERR_FILE_WIPE;
        if (!write_ff(fs, size > len ? size - len : 0, len)) return MI_ERR_FILE_WIPE;
    } else {
        fs.seekp(0, std::ios::beg);
        for (uint64_t i = 0; i < size; ++i) {
            fs.put(static_cast<char>(0xFF));
        }
    }
    fs.close();
    std::remove(path);
    return MI_OK;
}
