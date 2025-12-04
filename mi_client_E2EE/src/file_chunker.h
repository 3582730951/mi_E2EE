#pragma once

#include <cstdint>
#include <functional>
#include <string>

class FileChunker {
public:
    using ChunkCallback = std::function<void(const uint8_t* data, size_t len, uint32_t index, uint32_t total)>;

    static bool ForEachChunk(const std::string& path, uint32_t chunk_size, ChunkCallback cb);
};
