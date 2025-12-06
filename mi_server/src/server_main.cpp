#include "mi_server_api.h"
#include "mi_common.h"
#include "kcp_stub.h"

#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <tuple>

struct MySQLConfigIni {
    std::string host;
    int port{3306};
    std::string db;
    std::string user;
    std::string passwd;
};

struct ServerConfigIni {
    int port{MI_DEFAULT_PORT};
};

static std::string trim(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

static void load_config(const std::filesystem::path& path, MySQLConfigIni& out) {
    std::ifstream in(path);
    if (!in.is_open()) {
        std::cerr << "[server] config.ini not found at " << path.string() << ", using defaults (mysql disabled)\n";
        return;
    }
    std::cerr << "[server] loading config.ini from " << path.string() << "\n";
    std::string line;
    bool in_mysql = false;
    bool in_server = false;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        if (line.front() == '[' && line.back() == ']') {
            std::string sec = line.substr(1, line.size() - 2);
            in_mysql = (sec == "mysql");
            in_server = (sec == "server");
            continue;
        }
        if (!in_mysql && !in_server) continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string key = trim(line.substr(0, pos));
        std::string val = trim(line.substr(pos + 1));
        if (in_mysql) {
            if (key == "mysql_ip") out.host = val;
            else if (key == "mysql_port") {
                try { out.port = std::stoi(val); } catch (...) {}
            }
            else if (key == "database") out.db = val;
            else if (key == "username") out.user = val;
            else if (key == "passwd") out.passwd = val;
        } else if (in_server) {
            if (key == "port") {
                try { out.port = std::stoi(val); } catch (...) {}
            }
        }
    }
}

static void load_server_config(const std::filesystem::path& path, ServerConfigIni& out) {
    std::ifstream in(path);
    if (!in.is_open()) return;
    std::string line;
    bool in_server = false;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        if (line.front() == '[' && line.back() == ']') {
            std::string sec = line.substr(1, line.size() - 2);
            in_server = (sec == "server");
            continue;
        }
        if (!in_server) continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string key = trim(line.substr(0, pos));
        std::string val = trim(line.substr(pos + 1));
        if (key == "port") {
            try { out.port = std::stoi(val); } catch (...) {}
        }
    }
}

int main(int argc, char** argv) {
    std::ios::sync_with_stdio(false);
    std::cerr << "[server] mi_server_app starting...\n";

    ConfigStruct cfg{};
    cfg.work_dir = ".";
    cfg.log_level = 1; // minimal internal logging
    cfg.enable_hardware_crypto = 0;
    cfg.server_ip = "0.0.0.0";
    cfg.server_port = MI_DEFAULT_PORT;

    std::cerr << "[server] init with listen " << cfg.server_ip << ":" << cfg.server_port
              << " work_dir=" << cfg.work_dir << "\n";
    if (MI_Server_Init(&cfg) != MI_OK) {
        std::cerr << "[server][fatal] MI_Server_Init failed\n";
        return 1;
    }

    std::filesystem::path exe_dir = std::filesystem::current_path();
    if (argc > 0) {
        std::error_code ec;
        exe_dir = std::filesystem::absolute(argv[0], ec).parent_path();
    }
    std::filesystem::path cfg_path = (argc > 1) ? argv[1] : (exe_dir / "config.ini");

    MySQLConfigIni mycfg;
    ServerConfigIni srvCfg;
    load_config(cfg_path, mycfg);
    load_server_config(cfg_path, srvCfg);
    cfg.server_port = srvCfg.port;
    std::cerr << "[server] listen port set to " << cfg.server_port << "\n";
    if (!mycfg.host.empty() && !mycfg.db.empty() && !mycfg.user.empty()) {
        std::cerr << "[server] mysql config: host=" << mycfg.host << " port=" << mycfg.port
                  << " db=" << mycfg.db << " user=" << mycfg.user << "\n";
        MI_Result r1 = MI_Server_SetMySQLConfig(
            mycfg.host.c_str(), mycfg.port, mycfg.user.c_str(), mycfg.passwd.c_str(), mycfg.db.c_str());
        std::cerr << "[server] MI_Server_SetMySQLConfig => " << static_cast<int>(r1) << "\n";
        MI_Result r2 = MI_Server_EnableMySQL(1);
        std::cerr << "[server] MI_Server_EnableMySQL => " << static_cast<int>(r2) << "\n";
    } else {
        std::cerr << "[server] mysql config incomplete, mysql disabled\n";
    }

    std::cerr << "[server] entering poll loop...\n";

    while (true) {
        MI_Server_PollKCP();
        MI_Server_FlushRelay();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    MI_Server_Shutdown();
    return 0;
}
