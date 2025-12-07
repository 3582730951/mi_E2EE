#pragma once

#include <QWidget>
#include <QVariant>
#include <QListView>
#include <QTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include "qt_ui/MessageModel.h"

class ChatWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ChatWidget(QWidget *parent = nullptr);
    ~ChatWidget();

    QString currentConversationId() const;

public slots:
    void setCurrentConversation(const QString& conversationId);
    void displayHistory(const QVariantList& messages);
    void appendMessage(const QVariantMap& message);

private slots:
    void onSendButtonClicked();

private:
    QListView* messageListView = nullptr;
    QTextEdit* messageInput = nullptr;
    QPushButton* sendButton = nullptr;
    MessageModel* m_messageModel;
    QString m_currentConversationId;
};
