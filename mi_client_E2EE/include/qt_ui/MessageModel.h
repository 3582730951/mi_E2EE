#pragma once
#include <QAbstractListModel>
#include <QVariant>
#include <QList>

class MessageModel : public QAbstractListModel
{
    Q_OBJECT
public:
    enum MessageRoles {
        TextRole = Qt::UserRole + 1,
        TimestampRole,
        IsMineRole,
        SenderNameRole
    };

    explicit MessageModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

public slots:
    void addMessage(const QVariantMap& message);
    void addMessages(const QVariantList& messages);
    void clear();

private:
    QList<QVariantMap> m_messages;
};
