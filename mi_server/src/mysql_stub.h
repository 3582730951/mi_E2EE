#pragma once

#include <stdint.h>
#include <string>

struct MySQLConfig {
    std::string host;
    int port;
    std::string user;
    std::string password;
    std::string db;
};

bool MySQLAvailable();
bool MySQLVerifyPassword(const MySQLConfig& cfg, const std::string& username, const uint8_t password_sha256[32]);
bool MySQLStoreUser(const MySQLConfig& cfg, const std::string& username, const uint8_t password_sha256[32]);
bool MySQLRemoveUser(const MySQLConfig& cfg, const std::string& username);
