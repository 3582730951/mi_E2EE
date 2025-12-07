#include "qt_ui/BackendService.h"
#include "qt_ui/MessageReceiverThread.h"
#include <QtConcurrent>
#include <QDebug>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QFutureInterface>

BackendService* BackendService::instance()
{
    static BackendService service;
    return &service;
}

BackendService::BackendService(QObject *parent) : QObject(parent)
{
    m_isLoaded = loadBackendLibrary();
    if (m_isLoaded) {
        // 根据开发要求.txt，在UI加载前初始化
        // 假设 MI_Init(nullptr) 使用默认配置
        MI_Init(nullptr);
        qInfo() << "BackendService: Backend DLL loaded and initialized successfully.";
    } else {
        qCritical() << "BackendService: FAILED to load or resolve backend DLL.";
    }

    // 确保在程序退出时调用后端关闭函数
    connect(qApp, &QCoreApplication::aboutToQuit, this, [this](){
        if (m_isLoaded && MI_Shutdown) {
            MI_Shutdown();
            qInfo() << "BackendService: Backend shutdown.";
        }
    });
}

BackendService::~BackendService()
{
    if (m_messageReceiver) {
        m_messageReceiver->stop();
        m_messageReceiver->wait();
    }
}

bool BackendService::loadBackendLibrary()
{
    m_library.setFileName("mi_client_e2ee"); // .dll/.so 会被自动添加
    if (!m_library.load()) {
        qCritical() << "Failed to load mi_client_e2ee:" << m_library.errorString();
        return false;
    }

    // 解析所有需要的函数
    MI_Init = (MI_Init_Func)m_library.resolve("MI_Init");
    MI_Shutdown = (MI_Shutdown_Func)m_library.resolve("MI_Shutdown");
    MI_Login = (MI_Login_Func)m_library.resolve("MI_Login");
    MI_LoadLocalHistory = (MI_LoadLocalHistory_Func)m_library.resolve("MI_LoadLocalHistory");
    MI_SendMessage = (MI_SendMessage_Func)m_library.resolve("MI_SendMessage");

    // 解析辅助函数
    MI_CreateEncString = (MI_CreateEncString_Func)m_library.resolve("MI_CreateEncString");
    MI_FreeEncString = (MI_FreeEncString_Func)m_library.resolve("MI_FreeEncString");
    MI_CreateEncJsonFromString = (MI_CreateEncJsonFromString_Func)m_library.resolve("MI_CreateEncJsonFromString");
    MI_FreeEncJson = (MI_FreeEncJson_Func)m_library.resolve("MI_FreeEncJson");
    MI_DecodeEncJsonToString = (MI_DecodeEncJsonToString_Func)m_library.resolve("MI_DecodeEncJsonToString");
    MI_FreeDecodedString = (MI_FreeDecodedString_Func)m_library.resolve("MI_FreeDecodedString");

    // 解析消息接收函数
    m_onMessageFuncs.onMessageReceived = (MI_OnMessageReceived_Func)m_library.resolve("MI_OnMessageReceived");
    m_onMessageFuncs.decodeEncJsonToString = MI_DecodeEncJsonToString;
    m_onMessageFuncs.freeDecodedString = MI_FreeDecodedString;

    // 必须确保核心函数都已找到
    bool core_ok = MI_Init && MI_Shutdown && MI_Login && MI_LoadLocalHistory && MI_SendMessage;
    bool helpers_ok = MI_CreateEncString && MI_FreeEncString && MI_CreateEncJsonFromString && MI_FreeEncJson && MI_DecodeEncJsonToString && MI_FreeDecodedString;
    bool receiver_ok = m_onMessageFuncs.onMessageReceived;
    return core_ok && helpers_ok && receiver_ok;
}

QFuture<int> BackendService::login(const QString& username, const QString& password)
{
    if (!m_isLoaded) {
        // 返回一个立即完成并带有错误码的Future
        QFuture<int> future;
        QFutureInterface<int> promise;
        promise.reportResult(-1); // 自定义错误码，表示DLL加载失败
        promise.reportFinished();
        future = promise.future();
        return future;
    }

    // 使用QtConcurrent在工作线程中执行阻塞的登录操作
    return QtConcurrent::run([this, username, password]() {
        // 注意：EncString的创建和销毁必须在同一个线程中，且与调用它的API在同一个线程
        EncString encUser = MI_CreateEncString(username.toUtf8().constData());
        EncString encPass = MI_CreateEncString(password.toUtf8().constData());

        int result = MI_Login(encUser, encPass);

        if (result == 0) {
            // 登录成功后，启动消息轮询
            QMetaObject::invokeMethod(this, "startMessagePolling", Qt::QueuedConnection);
        }

        MI_FreeEncString(encUser);
        MI_FreeEncString(encPass);

        return result;
    });
}

void BackendService::startMessagePolling()
{
    if (!m_messageReceiver) {
        m_messageReceiver = new MessageReceiverThread(
            m_onMessageFuncs.onMessageReceived,
            m_onMessageFuncs.decodeEncJsonToString,
            m_onMessageFuncs.freeDecodedString,
            this
        );
        connect(m_messageReceiver, &MessageReceiverThread::messageJsonReceived, this, [this](const QString& jsonString){
            const auto& doc = QJsonDocument::fromJson(jsonString.toUtf8());
            if (doc.isObject()) {
                emit newMessageReceived(doc.object().toVariantMap());
            }
        });
        m_messageReceiver->start();
        qInfo() << "Message polling thread started.";
    }
}

QVariantList BackendService::parseJsonList(EncJson jsonList)
{
    if (!jsonList) return {};

    char* decoded_json_str = nullptr;
    if (MI_DecodeEncJsonToString(jsonList, &decoded_json_str) == 0) {
        const auto& doc = QJsonDocument::fromJson(QByteArray(decoded_json_str));
        MI_FreeDecodedString(decoded_json_str);
        if (doc.isArray()) {
            return doc.array().toVariantList();
        }
    }
    return {};
}

QFuture<QVariantList> BackendService::getConversations()
{
    // bdtd.txt 中没有直接获取会话列表的API，我们复用 MI_LoadLocalHistory
    // 假设传入空的 target 表示获取会话列表
    return QtConcurrent::run([this]() {
        EncString encTarget = MI_CreateEncString("");
        EncJson out_list = nullptr;
        MI_LoadLocalHistory(encTarget, &out_list);
        MI_FreeEncString(encTarget);

        QVariantList result = parseJsonList(out_list);
        // MI_FreeEncJson(out_list); // 假设后端会处理 out_list 的释放
        return result;
    });
}

QFuture<QVariantList> BackendService::getHistory(const QString& conversationId)
{
    return QtConcurrent::run([this, conversationId]() {
        EncString encTarget = MI_CreateEncString(conversationId.toUtf8().constData());
        EncJson out_list = nullptr;
        MI_LoadLocalHistory(encTarget, &out_list);
        MI_FreeEncString(encTarget);

        QVariantList result = parseJsonList(out_list);
        // MI_FreeEncJson(out_list);
        return result;
    });
}

QFuture<int> BackendService::sendMessage(const QString& conversationId, const QString& text)
{
    return QtConcurrent::run([this, conversationId, text]() {
        EncString encTarget = MI_CreateEncString(conversationId.toUtf8().constData());

        // 将要发送的消息构造成 JSON
        QJsonObject msgObj;
        msgObj["type"] = "text";
        msgObj["content"] = text;
        QJsonDocument doc(msgObj);
        QString jsonString = doc.toJson(QJsonDocument::Compact);

        EncJson encMessage = MI_CreateEncJsonFromString(jsonString.toUtf8().constData());

        int result = -1;
        if (encMessage) {
            result = MI_SendMessage(encTarget, encMessage);
        }

        MI_FreeEncString(encTarget);
        if (encMessage) {
            MI_FreeEncJson(encMessage);
        }

        return result;
    });
}
