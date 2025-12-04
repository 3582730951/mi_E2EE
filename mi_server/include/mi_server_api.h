#pragma once

#include "mi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

MI_API MI_Result MI_CALL MI_Server_Init(const ConfigStruct* cfg);
MI_API void MI_CALL MI_Server_Shutdown(void);

MI_API MI_Result MI_CALL MI_Server_AddUser(const UserInfo* user);
MI_API MI_Result MI_CALL MI_Server_RemoveUser(const EncString username);
MI_API MI_Result MI_CALL MI_Server_ListSessions(SessionList* out);
MI_API MI_Result MI_CALL MI_Server_FreeSessionList(SessionList* list);
MI_API MI_Result MI_CALL MI_Server_AuthLogin(const EncString username, const uint8_t password_sha256[32]);
MI_API MI_Result MI_CALL MI_Server_SetMySQLConfig(const char* host, int port, const char* user, const char* password, const char* db);
MI_API MI_Result MI_CALL MI_Server_EnableMySQL(int enable);

// Relay cache: enqueue packets for target, dequeue for delivery
MI_API MI_Result MI_CALL MI_Server_RelayEnqueue(const EncString target, const EncBuffer* packet);
MI_API MI_Result MI_CALL MI_Server_RelayDequeue(const EncString target, EncBuffer* out_packet);
MI_API MI_Result MI_CALL MI_Server_RelayMarkDelivered(const EncString target);
MI_API MI_Result MI_CALL MI_Server_RelayPendingCount(const EncString target, uint32_t* out_count);
// KCP polling/flush helpers (stub for daemon loop)
MI_API MI_Result MI_CALL MI_Server_PollKCP(void);
MI_API MI_Result MI_CALL MI_Server_FlushRelay(void);

#ifdef __cplusplus
}
#endif
