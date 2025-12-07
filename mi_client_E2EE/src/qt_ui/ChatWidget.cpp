#include "qt_ui/ChatWidget.h"
#include "qt_ui/MessageModel.h"
#include "qt_ui/MessageDelegate.h"
#include "qt_ui/BackendService.h"
#include <QFutureWatcher>
#include <QAbstractItemView>

ChatWidget::ChatWidget(QWidget *parent) :
    QWidget(parent)
{
    m_messageModel = new MessageModel(this);

    // UI 构建
    messageListView = new QListView(this);
    messageListView->setModel(m_messageModel);
    messageListView->setItemDelegate(new MessageDelegate(this));
    messageListView->setSelectionMode(QAbstractItemView::NoSelection);
    messageListView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

    messageInput = new QTextEdit(this);
    messageInput->setPlaceholderText(tr("输入消息..."));
    messageInput->setFixedHeight(80);

    sendButton = new QPushButton(tr("发送"), this);
    connect(sendButton, &QPushButton::clicked, this, &ChatWidget::onSendButtonClicked);

    auto inputLayout = new QHBoxLayout();
    inputLayout->addWidget(messageInput, 1);
    inputLayout->addWidget(sendButton);

    auto layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(6);
    layout->addWidget(messageListView, 1);
    layout->addLayout(inputLayout);
    setLayout(layout);
}

ChatWidget::~ChatWidget() = default;

QString ChatWidget::currentConversationId() const
{
    return m_currentConversationId;
}

void ChatWidget::setCurrentConversation(const QString& conversationId)
{
    m_currentConversationId = conversationId;
    m_messageModel->clear();
    messageInput->clear();
    messageInput->setEnabled(true);
    sendButton->setEnabled(true);
}

void ChatWidget::displayHistory(const QVariantList& messages)
{
    m_messageModel->addMessages(messages);
    messageListView->scrollToBottom();
}

void ChatWidget::appendMessage(const QVariantMap& message)
{
    m_messageModel->addMessage(message);
    messageListView->scrollToBottom();
}

void ChatWidget::onSendButtonClicked()
{
    QString text = messageInput->toPlainText().trimmed();
    if (text.isEmpty() || m_currentConversationId.isEmpty()) {
        return;
    }

    // Optimistically add to UI immediately
    // In a real app, you'd wait for a confirmation from the backend
    // appendMessage({{"text", text}, {"isMine", true}, ...});

    BackendService::instance()->sendMessage(m_currentConversationId, text);
    messageInput->clear();
}
