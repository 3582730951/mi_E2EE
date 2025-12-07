#pragma once

#include <QObject>
#include <QVariant>
#include <QLibrary>
#include <QString>
#include <QFuture>

class MessageReceiverThread;

// 占位类型：实际应链接到后端导出的密文结构体
using EncString = void*;
using EncJson = void*;

// API 函数指针类型定义
typedef int (*MI_Init_Func)(void* /* cfg */);
typedef void (*MI_Shutdown_Func)();
typedef int (*MI_Login_Func)(EncString username, EncString password);
typedef int (*MI_LoadLocalHistory_Func)(EncString target, EncJson* out_list);
typedef int (*MI_SendMessage_Func)(EncString target_username, EncJson message_content);
typedef int (*MI_OnMessageReceived_Func)(EncJson* out_message);

// 假设后端提供了这些用于转换的辅助函数
typedef EncString (*MI_CreateEncString_Func)(const char*);
typedef void (*MI_FreeEncString_Func)(EncString);
typedef EncJson (*MI_CreateEncJsonFromString_Func)(const char*);
typedef void (*MI_FreeEncJson_Func)(EncJson);
typedef int (*MI_DecodeEncJsonToString_Func)(EncJson input, char** output);
typedef void (*MI_FreeDecodedString_Func)(char* str);


class BackendService : public QObject
{
    Q_OBJECT
public:
    // Struct to hold related message functions for the receiver thread
    struct MI_OnMessage_Funcs {
        MI_OnMessageReceived_Func onMessageReceived = nullptr;
        MI_DecodeEncJsonToString_Func decodeEncJsonToString = nullptr;
        MI_FreeDecodedString_Func freeDecodedString = nullptr;
    };

    static BackendService* instance();

    QFuture<int> login(const QString& username, const QString& password);
    QFuture<QVariantList> getConversations();
    QFuture<QVariantList> getHistory(const QString& conversationId);
    QFuture<int> sendMessage(const QString& conversationId, const QString& text);

signals:
    void conversationsReady(const QVariantList& conversations);
    void historyReady(const QString& conversationId, const QVariantList& messages);
    void newMessageReceived(const QVariantMap& message);

private:
    explicit BackendService(QObject *parent = nullptr);
    ~BackendService();

    bool loadBackendLibrary();
    void startMessagePolling();
    QVariantList parseJsonList(EncJson jsonList);

    QLibrary m_library;
    bool m_isLoaded = false;
    MessageReceiverThread* m_messageReceiver = nullptr;

    // 函数指针
    MI_Init_Func MI_Init = nullptr;
    MI_Shutdown_Func MI_Shutdown = nullptr;
    MI_Login_Func MI_Login = nullptr;
    MI_LoadLocalHistory_Func MI_LoadLocalHistory = nullptr;
    MI_SendMessage_Func MI_SendMessage = nullptr;

    // Helper/conversion functions
    MI_CreateEncString_Func MI_CreateEncString = nullptr;
    MI_FreeEncString_Func MI_FreeEncString = nullptr;
    MI_CreateEncJsonFromString_Func MI_CreateEncJsonFromString = nullptr;
    MI_FreeEncJson_Func MI_FreeEncJson = nullptr;
    MI_DecodeEncJsonToString_Func MI_DecodeEncJsonToString = nullptr;
    MI_FreeDecodedString_Func MI_FreeDecodedString = nullptr;

    // For message receiver thread
    MI_OnMessage_Funcs m_onMessageFuncs;
};
