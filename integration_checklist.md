# 联调检查清单（Stage 3）

## 构建与链接
- 根目录：`cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build` 可生成占位库 `mi_client_e2ee` 与 `mi_server`（当前返回未实现）。
- 头文件：公共类型 `include/mi_common.h`，客户端接口 `mi_client_E2EE/include/mi_client_api.h`，服务器接口 `mi_server/include/mi_server_api.h`。
- 定义：编译时已设置 `MI_BUILD` 导出符号；调用侧仅需包含头文件并链接对应库。
- KCP 状态码：`MI_KCP_DISCONNECTED`/`MI_KCP_CONNECTING`/`MI_KCP_CONNECTED`。
- Mock 行为：当前实现为离线桩，校验参数后返回 `MI_OK`，消息/历史以本地内存回环。联调可先行验证绑定与调用链，再替换为真实加密与网络逻辑。
- 资源释放：`MI_LoadLocalHistory`/`MI_Server_ListSessions` 返回的数组需调用侧使用 `delete[]` 释放；其中 `username` 字段非空时需逐一 `delete[] username`。
- 加解密：Win 下使用 CNG AES-256-GCM；如定义 `MI_USE_OPENSSL` 则跨平台走 OpenSSL AES-GCM（默认 ON，非 Windows 缺失时构建报错以避免不安全回退）。
- 历史数据：`EncJsonList.items[i].data` 为新分配的缓冲，消费后需调用侧 `delete[]` 逐个释放。
- 释放辅助：提供 `MI_FreeEncJsonList`、`MI_Server_FreeSessionList`，调用后指针与计数被清零。
- 消息封装：`MI_SendMessage` 对载荷加盐派生子密钥做 AES-256-GCM，并封装 A-wrapper（username + 蜜罐 ip_port/strings + IV|CT|TAG + Ed25519 签名 + sender_pub），algo_id=3；`MI_DecryptMessage` 自动验签/解封装并返回原始 EncJson。
- 登录与认证：`MI_Server_AuthLogin` 校验用户名+SHA256 密码哈希（内存态数据库），需前端先对密码做 SHA-256（或传入已加密后再哈希）。
- 会话密钥：`MI_KCP_Connect` 走 KCP 抽象（默认回环），ECDH 派生会话密钥；需将 `MI_USE_KCP` 打开并提供 ikcp 库以使用真实 KCP 通道与公钥验证。
- 群密钥：`MI_GetGroupKey` 在客户端维护版本并随机刷新；`MI_SendGroupMessage` 将群密钥版本塞入 salt，后续应由服务器统一分发与滚动。
- MySQL：提供 `MI_Server_SetMySQLConfig`、`MI_Server_EnableMySQL`；若定义 `MI_USE_MYSQL` 并链接 mysqlclient 则可对接真实数据库；默认回退内存哈希。
- 文件：`MI_SendFile` 读取文件并计算基于会话派生键的 HMAC（按 chunk 聚合），`MI_OnFileReceived` 会重新计算并校验；仍未实现分片传输与擦除流程，需后续接入。
- 文件擦除：接收端校验通过后调用 SecureEraseFile 覆盖并删除本地文件。

## 前端（Gemini）调用约束
- 只使用 Enc* 类型与后端交互：用户名/密码/消息/文件均需 Enc 包装。
- UI 渲染前使用解密接口，渲染后调用 `MI_ErasePlain` 覆写明文。
- 保持异步封装（Promise/Future），避免阻塞渲染线程。

## 连接与认证流程
1) 启动时调用 `MI_Init` 传入工作目录、日志等级、默认端点（127.0.0.1:19999）。
2) 登录：前端 AES-256 加密密码 → `MI_Login` → 成功后再进行 KCP 连接。
3) 握手：`MI_KCP_Connect` 后检查 `MI_KCP_Status`；失败则回退到未连接状态。
4) 消息：`MI_EncryptMessage` → `MI_SendMessage`；接收用 `MI_OnMessageReceived` + `MI_DecryptMessage`。
5) 群聊：`MI_GetGroupKey` 获取群密钥版本；发送用 `MI_SendGroupMessage`。
6) 文件：`MI_SendFile` / `MI_OnFileReceived`；确认全部送达后由客户端擦除。

## 数据与存储
- 聊天记录：`MI_SaveLocalHistory` / `MI_LoadLocalHistory`，返回 `EncJsonList`，渲染后立即覆写。
- 文件擦除：遵循头/中/尾 0xFF 覆盖后删除，小文件全量 0xFF。

## 待实现标记
- 目前库函数返回 `MI_ERR_NOT_IMPLEMENTED`，实现需补齐：白盒 AES-256-GCM、ECDH 握手、KCP 收发、MySQL 认证、群密钥滚动、文件分片/HMAC。
- 白盒加密与侧信道加固需要专项实现与测试。
