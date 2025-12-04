#include "file_chunker.h"

#include <fstream>
#include <vector>

bool FileChunker::ForEachChunk(const std::string& path, uint32_t chunk_size, ChunkCallback cb) {
    if (chunk_size == 0 || !cb) {
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }
    in.seekg(0, std::ios::end);
    uint64_t size = static_cast<uint64_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    uint32_t total = static_cast<uint32_t>((size + chunk_size - 1) / chunk_size);
    std::vector<uint8_t> buf(chunk_size);
    uint32_t idx = 0;
    while (in && idx < total) {
        in.read(reinterpret_cast<char*>(buf.data()), buf.size());
        std::streamsize read = in.gcount();
        if (read <= 0) break;
        cb(buf.data(), static_cast<size_t>(read), idx, total);
        ++idx;
    }
    return true;
}
