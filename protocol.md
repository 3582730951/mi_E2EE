# 协议与数据封装规范（Stage 1）

## 1. 设计目标
- 服务器零信任前提下实现端到端身份校验与机密性。
- 支持单聊、群聊、文件传输，跨平台一致。

## 2. 身份与密钥体系
- 用户标识：username + 公钥指纹（fingerprint = SHA256(pubkey)）。
- 根密钥：用户长周期公私钥对（不落盘私钥）；会话密钥：握手时 ECDH 导出。
- 群密钥：群主生成，随成员变更滚动；成员用自己私钥对群消息签名。

## 3. 登录与认证
- 前端：输入密码 → AES-256 加密后发送 MI_Login。
- 服务器：解密后取 SHA-256，与 MySQL 中存储的 SHA-256 对比。
- 登录成功后下发当前服务器公钥指纹与时间偏移（便于重放防护）。

## 4. KCP 握手流程
1) C → S：client_nonce、client_pub、协议版本。
2) S → C：echo(client_nonce)、server_pub、server_sig(server_pub || client_nonce)。
3) C：校验签名、做 ECDH，得到 k_session；后续 KCP 包用白盒 AES-256-GCM(k_session)。

## 5. 消息封装（A.json 蜜罐）
- 内层真实 JSON（RealMsg）：
  - from_fpr、timestamp、nonce、msg_type、payload。
- 外层 A.json：
  - username：目标用户名（明示目标）
  - ip_port：等长随机密文（蜜罐）
  - strings：随机填充，长度与加密后 RealMsg 相同
  - message：加密后的 RealMsg
- 加密顺序：RealMsg 用接收方公钥 → A.json 打包 → A.json 再用白盒 AES-256-GCM。
- 校验：接收端验证 from_fpr 是否匹配缓存的目标公钥；timestamp 与 nonce 去重放。

## 6. 单聊流程
1) 获取目标公钥：MI_RequestUserPublicKey。
2) UI 数据 → EncJson → MI_EncryptMessage → MI_SendMessage。
3) 接收：MI_OnMessageReceived → MI_DecryptMessage → 校验指纹/时间 → UI 显示 → 明文覆写。

## 7. 群聊流程
- 群主分发群密钥（群密钥用成员公钥包裹）。
- 发送：payload 用群密钥加密，发送者私钥签名；包内携带群密钥版本号。
- 接收：验证签名 + 版本号，若版本过期则请求最新群密钥。

## 8. 文件传输
- 发送前本地加密文件体（与消息同层次的白盒 AES-256-GCM）；文件元数据走消息通道。
- 群聊文件：收到确认率 100% 后触发擦除（头/中/尾 0xFF → 删除）。
- 传输信令仍走 KCP；大文件可分片，每片含索引与 HMAC。

## 9. 时间与重放防护
- 每条消息包含 timestamp（ms）与 nonce；允许 ±120s 窗口；nonce 由会话随机种子 + 递增计数。
- 维护最近 nonce 列表，重复即丢弃。

## 10. 错误与恢复
- 握手失败：清除会话密钥与状态，回到未连接。
- 解密失败：丢弃消息，记录指纹与 nonce 供告警，不回显明文错误。
- 时钟偏移：使用服务器提供的偏移值校准本地校验窗口。
