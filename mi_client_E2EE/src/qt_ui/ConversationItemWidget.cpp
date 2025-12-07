#include "qt_ui/ConversationItemWidget.h"
#include <QPixmap>

ConversationItemWidget::ConversationItemWidget(const QIcon &avatar, const QString &name, const QString &lastMessage, const QString &timestamp, QWidget *parent) :
    QWidget(parent)
{
    avatarLabel = new QLabel(this);
    avatarLabel->setPixmap(avatar.pixmap(40, 40));
    avatarLabel->setFixedSize(40, 40);

    nameLabel = new QLabel(name, this);
    nameLabel->setStyleSheet("font-weight: 600;");

    lastMessageLabel = new QLabel(lastMessage, this);
    lastMessageLabel->setStyleSheet("color: #a0a0a0; font-size: 12px;");

    timestampLabel = new QLabel(timestamp, this);
    timestampLabel->setStyleSheet("color: #888888; font-size: 11px;");

    auto textLayout = new QVBoxLayout();
    textLayout->setContentsMargins(0, 0, 0, 0);
    textLayout->addWidget(nameLabel);
    textLayout->addWidget(lastMessageLabel);

    auto mainLayout = new QHBoxLayout(this);
    mainLayout->setContentsMargins(8, 6, 8, 6);
    mainLayout->addWidget(avatarLabel);
    mainLayout->addLayout(textLayout, 1);
    mainLayout->addWidget(timestampLabel, 0, Qt::AlignRight | Qt::AlignTop);

    setLayout(mainLayout);
}

ConversationItemWidget::~ConversationItemWidget() = default;
