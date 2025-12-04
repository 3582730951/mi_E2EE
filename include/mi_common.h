#pragma once

#include <stddef.h>
#include <stdint.h>

#define MI_DEFAULT_PORT 19999

#if defined(_WIN32)
#  if defined(MI_BUILD)
#    define MI_API __declspec(dllexport)
#  else
#    define MI_API __declspec(dllimport)
#  endif
#else
#  define MI_API __attribute__((visibility("default")))
#endif

#define MI_CALL

#include "generated_keys.h"
#include "generated_cert.h"

typedef enum MI_Result {
    MI_OK = 0,
    MI_ERR_USER_NOT_FOUND = 1001,
    MI_ERR_BAD_PASSWORD = 1002,
    MI_ERR_SERVER_UNAVAILABLE = 1003,
    MI_ERR_ENCRYPT = 2001,
    MI_ERR_DECRYPT = 2002,
    MI_ERR_KEY_MISMATCH = 2003,
    MI_ERR_KCP_DISCONNECTED = 3001,
    MI_ERR_HANDSHAKE_FAILED = 3002,
    MI_ERR_FILE_ENCRYPT = 4001,
    MI_ERR_FILE_WIPE = 4002,
    MI_ERR_STORAGE = 5001,
    MI_ERR_INVALID_CONFIG = 9001,
    MI_ERR_NOT_IMPLEMENTED = 9002
} MI_Result;

typedef enum MI_KCPState {
    MI_KCP_DISCONNECTED = 0,
    MI_KCP_CONNECTING = 1,
    MI_KCP_CONNECTED = 2
} MI_KCPState;

typedef struct ConfigStruct {
    const char* work_dir;
    int log_level;
    int enable_hardware_crypto;
    const char* server_ip;
    int server_port;
} ConfigStruct;

typedef struct EncString {
    uint32_t len;
    uint8_t layout_id;
    uint8_t algo_id;
    uint16_t salt;
    const uint8_t* data;
} EncString;

typedef struct EncInt {
    uint8_t layout_id;
    uint8_t algo_id;
    uint16_t salt;
    uint32_t payload;
} EncInt;

typedef struct EncLong {
    uint8_t layout_id;
    uint8_t algo_id;
    uint16_t salt;
    uint64_t payload;
} EncLong;

typedef struct EncJson {
    uint32_t len;
    uint8_t layout_id;
    uint8_t algo_id;
    uint16_t salt;
    const uint8_t* data;
} EncJson;

typedef struct EncBuffer {
    uint32_t len;
    uint8_t layout_id;
    uint8_t algo_id;
    uint16_t salt;
    const uint8_t* data;
} EncBuffer;

typedef struct PublicKey {
    uint8_t data[32];
} PublicKey;

typedef struct PrivateKey {
    uint8_t data[32];
} PrivateKey;

typedef struct GroupKey {
    uint8_t data[32];
    uint32_t version;
} GroupKey;

typedef struct FileDescriptor {
    const char* path;
    uint64_t size;
    uint8_t hash[32];
    uint8_t hmac[32];
    uint32_t chunk_size;
    uint32_t chunk_count;
    uint32_t chunk_index;
    int encrypted;
    int delivered;
} FileDescriptor;

typedef struct UserInfo {
    const char* username;
    PublicKey pubkey;
    const uint8_t* password_sha256; // optional; length must be 32 when provided
    size_t password_len;
} UserInfo;

typedef struct SessionInfo {
    const char* username;
    int status;
} SessionInfo;

typedef struct SessionList {
    SessionInfo* items;
    size_t count;
} SessionList;

typedef struct EncJsonList {
    EncJson* items;
    size_t count;
} EncJsonList;
