#include "mysql_stub.h"

#ifdef MI_USE_MYSQL
#include <mysql.h>
#endif

bool MySQLAvailable() {
#ifdef MI_USE_MYSQL
    return true;
#else
    return false;
#endif
}

#ifdef MI_USE_MYSQL

static MYSQL* open_conn(const MySQLConfig& cfg) {
    MYSQL* conn = mysql_init(nullptr);
    if (!conn) return nullptr;
    if (!mysql_real_connect(conn, cfg.host.c_str(), cfg.user.c_str(), cfg.password.c_str(),
                            cfg.db.c_str(), cfg.port, nullptr, 0)) {
        mysql_close(conn);
        return nullptr;
    }
    return conn;
}

#endif

bool MySQLVerifyPassword(const MySQLConfig& cfg, const std::string& username, const uint8_t password_sha256[32]) {
#ifdef MI_USE_MYSQL
    MYSQL* conn = open_conn(cfg);
    if (!conn) return false;
    std::string query = "SELECT password_sha256 FROM users WHERE username='" + username + "'";
    if (mysql_query(conn, query.c_str()) != 0) {
        mysql_close(conn);
        return false;
    }
    MYSQL_RES* res = mysql_store_result(conn);
    if (!res) {
        mysql_close(conn);
        return false;
    }
    MYSQL_ROW row = mysql_fetch_row(res);
    bool ok = false;
    if (row && row[0]) {
        std::string db_hash(row[0]);
        std::string input_hash(reinterpret_cast<const char*>(password_sha256), 32);
        ok = db_hash.size() == 32 && std::memcmp(db_hash.data(), input_hash.data(), 32) == 0;
    }
    mysql_free_result(res);
    mysql_close(conn);
    return ok;
#else
    (void)cfg;
    (void)username;
    (void)password_sha256;
    return false;
#endif
}

bool MySQLStoreUser(const MySQLConfig& cfg, const std::string& username, const uint8_t password_sha256[32]) {
#ifdef MI_USE_MYSQL
    MYSQL* conn = open_conn(cfg);
    if (!conn) return false;
    char hash_hex[65];
    static const char* lut = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hash_hex[i * 2] = lut[(password_sha256[i] >> 4) & 0x0F];
        hash_hex[i * 2 + 1] = lut[password_sha256[i] & 0x0F];
    }
    hash_hex[64] = '\0';
    std::string query = "INSERT INTO users(username, password_sha256) VALUES('" + username + "', UNHEX('" + std::string(hash_hex) + "'))";
    bool ok = mysql_query(conn, query.c_str()) == 0;
    mysql_close(conn);
    return ok;
#else
    (void)cfg;
    (void)username;
    (void)password_sha256;
    return false;
#endif
}

bool MySQLRemoveUser(const MySQLConfig& cfg, const std::string& username) {
#ifdef MI_USE_MYSQL
    MYSQL* conn = open_conn(cfg);
    if (!conn) return false;
    std::string query = "DELETE FROM users WHERE username='" + username + "'";
    bool ok = mysql_query(conn, query.c_str()) == 0;
    mysql_close(conn);
    return ok;
#else
    (void)cfg;
    (void)username;
    return false;
#endif
}
