# Android 前端接入说明（Stub）

## 目标
- 使用 Flutter/Compose/Qt 任一开源框架，UI 100% 仿 QQ 风格（苹果化 icon/配色）。
- 所有业务调用通过 SO 接口，不使用明文类型，统一使用 Enc*。

## 接口绑定（JNI/FFI）
- 导出库：`libmi_client_e2ee.so`（编译自 mi_client_E2EE）。
- 关键 API：
  - `MI_Init(ConfigStruct*)`：传入工作目录（Android 可用 `getFilesDir()`），日志等级，默认 server IP/port。
  - `MI_KCP_Connect(EncString ip, int port)`、`MI_Login(EncString user, EncString pass_cipher)`。
  - 消息：`MI_SendMessage(EncString target, EncJson content)`；回调 `MI_RegisterMessageCallback`。
  - 文件：`MI_SendFile` / `MI_OnFileReceived`。
  - 群聊：`MI_SetGroupMembers`、`MI_GroupAck`、`MI_SendGroupMessage`。
  - 自定义收发：`MI_SetRawSend`、`MI_SetRawReceive`（建议在 native 层创建 UDP/KCP socket，Java 侧仅传递 Buffer）。
  - Enc helpers：`MI_CreateEncString/Json/Int32/Long` 与对应 Free/Decode。

## JNI 封装建议
- 使用 `byte[]` 与 `DirectByteBuffer` 传递原始包数据到 RawReceive，避免多次拷贝。
- 在 native 层维护 socket + KCP（类似 Windows），JNI 层暴露 `setRawSend`/`setRawReceive` 绑定。
- 禁止在 Java 层持久化明文；日志仅打印指纹/长度。

## 构建
- CMake 构建 Android ABI：`-DANDROID_ABI=arm64-v8a -DMI_USE_OPENSSL=ON -DMI_USE_KCP=ON`。
- 依赖：OpenSSL（NDK 预编译或自行编译）、ikcp 源可内置到 CMake。

## UI 注意
- 聊天/文件列表用假数据占位时也需 Enc 类型包装，防止前端泄露明文。
- 收到消息/文件后自动发送 ACK（native 已处理），UI 仅展示。
