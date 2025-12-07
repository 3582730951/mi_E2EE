#pragma once

#include <QThread>
#include "qt_ui/BackendService.h" // For function pointer types

class MessageReceiverThread : public QThread
{
    Q_OBJECT

public:
    explicit MessageReceiverThread(
        const BackendService::MI_OnMessage_Funcs& funcs,
        QObject* parent = nullptr
    );

    void stop();

protected:
    void run() override;

signals:
    void messageJsonReceived(const QString& jsonString);

private:
    BackendService::MI_OnMessage_Funcs m_funcs;
    volatile bool m_stopped = false;
};
