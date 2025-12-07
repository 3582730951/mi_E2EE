#pragma once

#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QIcon>

class ConversationItemWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ConversationItemWidget(const QIcon &avatar, const QString &name, const QString &lastMessage, const QString &timestamp, QWidget *parent = nullptr);
    ~ConversationItemWidget();

private:
    QLabel* avatarLabel = nullptr;
    QLabel* nameLabel = nullptr;
    QLabel* lastMessageLabel = nullptr;
    QLabel* timestampLabel = nullptr;
};
