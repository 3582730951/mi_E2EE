========================================
EncryptedBasicTypes.md —— 加密基础类型设计文档
版本：v1.1
说明：Codex 提供给前端（Gemini）使用的 Enc 基础类型与接口定义，跨 Windows / Linux / Android 一致。
========================================

# 目录
1. 设计目标与约束
2. 威胁模型与假设
3. 基础类型定义
4. 内存布局与对齐
5. 创建 / 解密 / 显示流程
6. DLL/SO 导出接口
7. 性能优化与擦除策略
8. 前端交互规则（Gemini 必读）
9. 示例调用序列

----------------------------------------
# 1. 设计目标与约束
----------------------------------------
- 抗静态/动态分析：随机化内存布局 + 加密方式标记 + 时间种子混淆。
- 跨平台一致：统一对齐与字节序，Win/Linux/Android 输出一致。
- 对前端透明：前端只拿 Enc 类型句柄/结构体，不操作明文。
- 安全擦除：明文出现即刻覆写。

----------------------------------------
# 2. 威胁模型与假设
----------------------------------------
攻击者能力：
- 反编译、内存扫描、Hook API、替换 DLL/SO。
假设：
- 运行设备可能被截获，但高熵随机源可用；服务器可被窥探（零信任）。

----------------------------------------
# 3. 基础类型定义
----------------------------------------
EncInt、EncLong、EncString、EncJson、EncBuffer。
公共字段：
- len（明文字节长）、salt（2~3B）、algo_id（1B）、layout_id（1B，16 种打散之一）。
- payload（加密/打散后的数据）。

----------------------------------------
# 4. 内存布局与对齐
----------------------------------------
- EncInt：原始 4B → 16 种排列之一 + algo_id + salt；总长 7~8B，对齐 4B。
- EncLong：原始 8B → 16 种排列之一 + algo_id + salt；总长 11~12B，对齐 8B。
- EncString：存 len（4B）+ algo_id + salt + 加密后字节；末尾填充随机字节以 8B 对齐。
- EncJson/EncBuffer：存 len（4B）+ algo_id + salt + AES-256-GCM 密文 + tag；8B 对齐。

----------------------------------------
# 5. 创建 / 解密 / 显示流程
----------------------------------------
- Create：输入明文 → 取高熵随机数生成 layout_id + salt → 打散或加密 → 输出 Enc*。
- Decode：读取 layout_id + salt + algo_id → 还原字节顺序/解密 → 写入调用方缓冲；完成后立即显式覆写明文缓冲。
- Display：EncString/EncJson 必须通过 DecodeForDisplay() 暂时解密，用后立刻覆写。

----------------------------------------
# 6. DLL/SO 导出接口
----------------------------------------
EncInt    MI_CreateEncInt(int v);
int       MI_DecodeEncInt(const EncInt* v);

EncLong   MI_CreateEncLong(int64_t v);
int64_t   MI_DecodeEncLong(const EncLong* v);

EncString MI_CreateEncString(const char* raw, size_t len);
int       MI_DecodeEncString(const EncString* enc, char* out, size_t out_len);

EncJson   MI_CreateEncJsonFromRaw(const char* raw_json, size_t len);
int       MI_DecodeEncJson(const EncJson* enc, char* out, size_t out_len);

EncBuffer MI_WrapBuffer(const uint8_t* buf, size_t len);
int       MI_UnwrapBuffer(const EncBuffer* enc, uint8_t* out, size_t out_len);

通用：
int MI_ErasePlain(void* buf, size_t len); // 显式 0xFF 覆写后再置 0

----------------------------------------
# 7. 性能优化与擦除策略
----------------------------------------
- 缓存解密结果仅限短生命周期；超过 100ms 需再次覆写并重解密。
- 使用平台内存屏障阻止编译器优化掉擦除（memset_s / SecureZeroMemory）。
- 热点路径尽量批量操作，减少重复随机数获取。

----------------------------------------
# 8. 前端交互规则（Gemini 必读）
----------------------------------------
- 前端不得自行构造 Enc*；所有 Enc* 由 DLL/SO 创建。
- UI 展示前调用 DecodeForDisplay；禁止在 UI 缓存明文。
- 与业务 API 交互时一律传 Enc*；禁止 string/int 直传。
- Electron/Qt/Flutter 绑定层：提供 Promise/Future 异步包装，避免阻塞渲染。

----------------------------------------
# 9. 示例调用序列
----------------------------------------
登录：
1) 前端获取用户输入密码 → 调用 MI_CreateEncString → 再调用 AES-256 加密密码 → MI_Login。
发送消息：
1) UI 数据 → MI_CreateEncJsonFromRaw
2) 调用 MI_EncryptMessage → 得到 EncBuffer
3) 调用 MI_SendMessage 发送。
显示消息：
1) MI_OnMessageReceived → EncJson
2) MI_DecodeEncJson → UI 渲染 → 立即 MI_ErasePlain。
