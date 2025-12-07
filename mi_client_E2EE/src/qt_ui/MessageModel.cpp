#include "MessageModel.h"

MessageModel::MessageModel(QObject *parent)
    : QAbstractListModel(parent)
{
}

int MessageModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return m_messages.count();
}

QVariant MessageModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_messages.count())
        return QVariant();

    const QVariantMap &message = m_messages.at(index.row());

    switch (role) {
    case TextRole:
        return message.value("content");
    case TimestampRole:
        return message.value("timestamp");
    case IsMineRole:
        // This needs to be determined by comparing senderId with own user id
        // For now, let's assume the backend provides an "isMine" field.
        return message.value("isMine", false);
    case SenderNameRole:
        return message.value("senderName");
    default:
        return QVariant();
    }
}

QHash<int, QByteArray> MessageModel::roleNames() const
{
    QHash<int, QByteArray> roles;
    roles[TextRole] = "text";
    roles[TimestampRole] = "timestamp";
    roles[IsMineRole] = "isMine";
    roles[SenderNameRole] = "senderName";
    return roles;
}

void MessageModel::addMessage(const QVariantMap& message)
{
    beginInsertRows(QModelIndex(), rowCount(), rowCount());
    m_messages.append(message);
    endInsertRows();
}

void MessageModel::addMessages(const QVariantList& messages)
{
    if (messages.isEmpty())
        return;
    beginInsertRows(QModelIndex(), rowCount(), rowCount() + messages.count() - 1);
    for(const QVariant& msg : messages) {
        m_messages.append(msg.toMap());
    }
    endInsertRows();
}

void MessageModel::clear()
{
    beginResetModel();
    m_messages.clear();
    endResetModel();
}