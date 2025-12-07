#include "qt_ui/MessageReceiverThread.h"
#include <QDebug>

MessageReceiverThread::MessageReceiverThread(
    const BackendService::MI_OnMessage_Funcs& funcs,
    QObject* parent)
    : QThread(parent), m_funcs(funcs)
{
}

void MessageReceiverThread::stop()
{
    m_stopped = true;
}

void MessageReceiverThread::run()
{
    while (!m_stopped)
    {
        EncJson out_message = nullptr;
        // Poll the backend for a new message. 0 means success and a message was retrieved.
        if (m_funcs.onMessageReceived && m_funcs.onMessageReceived(&out_message) == 0 && out_message)
        {
            char* decoded_json_str = nullptr;
            if (m_funcs.decodeEncJsonToString && m_funcs.decodeEncJsonToString(out_message, &decoded_json_str) == 0) {
                emit messageJsonReceived(QString::fromUtf8(decoded_json_str));
                m_funcs.freeDecodedString(decoded_json_str); // Release the string memory as per API contract
            }
        }
        QThread::msleep(200); // Poll every 200ms to be responsive without burning CPU
    }
}
