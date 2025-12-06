# MI E2EE

## 构建与依赖
- CMake ≥ 3.16，C/C++17
- OpenSSL（AES-GCM/Ed25519）
- 可选：KCP（ikcp）、MySQL 客户端

## MySQL 初始化示例
```sql
CREATE DATABASE IF NOT EXISTS mie2ee CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE mie2ee;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_sha256 BINARY(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 示例：插入用户（将明文密码先取 SHA-256，填入 64 位 hex）
INSERT INTO users (username, password_sha256) VALUES
('admin', UNHEX('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF'));

  INSERT INTO users (username, password_sha256) VALUES
  ('admin', UNHEX(SHA2('123456', 256)));
    INSERT INTO users (username, password_sha256) VALUES
  ('test', UNHEX(SHA2('123456', 256)));
```

## 关键说明
- 握手：SIGN_REQ/SIGN_ACK 使用 Ed25519，需在构建时注入服务器公钥/签名密钥（MI_SERVER_*）。
- KCP：默认开启 MI_USE_KCP 时使用 ikcp，支持 per-peer 会话、ACK 收齐擦除；未启用时退回 UDP loopback。
- 前端：Electron 通过 `mi_bridge.node` 调用，提供 `setRawSend/setRawReceive` 以接入自定义 KCP socket；消息/文件接收后自动 ACK。
- 重放防护：维护时间窗口，最大时间戳持久化到 `work_dir/replay.cache`。
- MySQL 远程配置：启动服务器时调用 `MI_Server_SetMySQLConfig(host, port, user, password, db)`，随后 `MI_Server_EnableMySQL(1)`；host 可为公网/内网地址，账号/密码/库名均由部署者提供。
- 配置文件：可在可执行程序同级放置 `config.ini`：
```
[mysql]
mysql_ip=127.0.0.1
mysql_port=3306
database=mie2ee
username=dbuser
passwd=dbpass
```
服务器可执行文件（`mi_server_app`）会读取该文件并自动配置 MySQL。
- 证书：CI 构建时自动使用 OpenSSL 生成自签名 RSA 证书与私钥，base64 写入 `include/generated_cert.h`（宏 `MI_BUILTIN_CERT_PEM_B64` / `MI_BUILTIN_CERT_KEY_PEM_B64`）。若需自定义，可在本地 configure 时传入 `-DMI_CERT_PEM_B64=... -DMI_CERT_KEY_PEM_B64=...`。
- 传输层加密：KCP UDP 数据报已二次封装 AES-GCM（magic `0xEE01` + client_pub + IV + TAG + CT），密钥由 client_pub 和内置服务器签名私钥经 HKDF 派生；纯明文数据报仍被兼容，但将绕过加密。

## Electron 客户端（Windows）
- 真实连接必须加载 `mi_bridge.node`，默认不再自动降级到 Mock；若仅需演示，可显式设置 `MI_ALLOW_BRIDGE_MOCK=1` 才允许使用 Mock。
- 发行包中的 `resources/app.asar.unpacked/mi_bridge/build/Release` 需同时包含 `mi_bridge.node` 及依赖 DLL（`libssl-*.dll`、`libcrypto-*.dll`、可选 `libmysql.dll`、`vcruntime140*.dll`、`msvcp140*.dll`），CI 已随包注入。
- 本地构建顺序：先 `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMI_USE_OPENSSL=ON -DMI_USE_KCP=ON -DMI_USE_MYSQL=ON && cmake --build build --config Release --target mi_client_e2ee mi_server_app`，再 `cd mi_client_E2EE/mi_bridge && npm install && npx node-gyp rebuild --target=28.0.0 --dist-url=https://electronjs.org/headers`，最后 `cd mi_client_E2EE/src/E2EE_Client_Windows && npm install && npx electron .`（或 `npm run build`）。
