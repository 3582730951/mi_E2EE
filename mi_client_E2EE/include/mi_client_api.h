#pragma once

#include "mi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

MI_API MI_Result MI_CALL MI_Init(const ConfigStruct* cfg);
MI_API void MI_CALL MI_Shutdown(void);

MI_API MI_Result MI_CALL MI_Login(const EncString username, const EncString aes256_encrypted_password);
MI_API MI_Result MI_CALL MI_RequestUserPublicKey(const EncString username, PublicKey* key);

MI_API MI_Result MI_CALL MI_KCP_Connect(const EncString server_ip, int port);
MI_API MI_Result MI_CALL MI_KCP_Disconnect(void);
MI_API MI_KCPState MI_CALL MI_KCP_Status(void);
MI_API MI_Result MI_CALL MI_SetServerPublicKey(const PublicKey* key);
MI_API MI_Result MI_CALL MI_GetClientPublicKey(PublicKey* key);
MI_API MI_Result MI_CALL MI_SetServerSignPublicKey(const PublicKey* key);
MI_API MI_Result MI_CALL MI_GetClientSignPublicKey(PublicKey* key);

MI_API MI_Result MI_CALL MI_EncryptMessage(const EncJson* input, EncBuffer* output);
MI_API MI_Result MI_CALL MI_DecryptMessage(const EncBuffer* input, EncJson* output);
MI_API MI_Result MI_CALL MI_GenerateEphemeralKey(PublicKey* pub, PrivateKey* priv);

MI_API MI_Result MI_CALL MI_SendMessage(const EncString target_username, const EncJson message_content);
MI_API MI_Result MI_CALL MI_OnMessageReceived(EncJson* out_message);

MI_API MI_Result MI_CALL MI_SendFile(const EncString target_username, const FileDescriptor* file);
MI_API MI_Result MI_CALL MI_OnFileReceived(FileDescriptor* file);

MI_API MI_Result MI_CALL MI_SaveLocalHistory(const EncJson message);
MI_API MI_Result MI_CALL MI_LoadLocalHistory(const EncString target, EncJsonList* out_list);

MI_API MI_Result MI_CALL MI_GetGroupKey(const EncString group_id, GroupKey* out);
MI_API MI_Result MI_CALL MI_SendGroupMessage(const EncString group_id, const EncJson message);
MI_API MI_Result MI_CALL MI_SetGroupMembers(const EncString group_id, uint32_t member_count);
MI_API MI_Result MI_CALL MI_GroupAck(const EncString group_id, uint32_t version);

MI_API MI_Result MI_CALL MI_GetUserInfo(const EncString username, UserInfo* out);

MI_API int MI_CALL MI_ErasePlain(void* buf, size_t len);
MI_API void MI_CALL MI_FreeEncJsonList(EncJsonList* list);

// Helper creators for bridges (N-API/FFI)
MI_API MI_Result MI_CALL MI_CreateEncString(const char* raw, EncString* out);
MI_API MI_Result MI_CALL MI_FreeEncString(EncString* enc);
MI_API MI_Result MI_CALL MI_DecodeEncString(const EncString* enc, char* out_buf, size_t out_len);
MI_API MI_Result MI_CALL MI_CreateEncJsonFromString(const char* raw_json, EncJson* out);
MI_API MI_Result MI_CALL MI_FreeEncJson(EncJson* enc);
MI_API MI_Result MI_CALL MI_DecodeEncJson(const EncJson* enc, char* out_buf, size_t out_len);

// Callbacks
typedef void(*MI_MessageCallback)(const EncJson* msg);
MI_API MI_Result MI_CALL MI_RegisterMessageCallback(MI_MessageCallback cb);

// Secure delete
MI_API MI_Result MI_CALL MI_SecureEraseFile(const char* path, uint64_t size_hint);

// Encrypted primitive helpers (layout-aware)
MI_API MI_Result MI_CALL MI_CreateEncInt32(uint32_t plain, EncInt* out);
MI_API MI_Result MI_CALL MI_DecodeEncInt32(const EncInt* enc, uint32_t* out);
MI_API MI_Result MI_CALL MI_CreateEncLong(uint64_t plain, EncLong* out);
MI_API MI_Result MI_CALL MI_DecodeEncLong(const EncLong* enc, uint64_t* out);

// Relay hook for custom transports (e.g., external KCP socket)
typedef bool(*MI_SendRawCallback)(const uint8_t* data, size_t len);
MI_API MI_Result MI_CALL MI_SetRawSend(MI_SendRawCallback cb);
// Hook raw receive (for external socket pump)
typedef void(*MI_RecvRawCallback)(const uint8_t* data, size_t len);
MI_API MI_Result MI_CALL MI_SetRawReceive(MI_RecvRawCallback cb);

#ifdef __cplusplus
}
#endif
