#include "qt_ui/MessageDelegate.h"
#include "qt_ui/MessageModel.h"
#include <QPainter>
#include <QTextDocument>
#include <QApplication>

MessageDelegate::MessageDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}

void MessageDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);

    bool isMine = index.data(MessageModel::IsMineRole).toBool();
    QString text = index.data(MessageModel::TextRole).toString();

    // Bubble colors
    QColor bubbleColor = isMine ? QColor(0, 122, 255) : QColor(60, 60, 60);
    QColor textColor = Qt::white;

    // Text document for rich text layout and word wrapping
    QTextDocument doc;
    doc.setHtml(text);
    doc.setTextWidth(option.rect.width() * 0.7); // Max width for the bubble
    doc.setDefaultTextColor(textColor);

    // Paddings and margins
    const int padding = 10;
    const int margin = 5;
    const int avatarSize = 0; // No avatar for simplicity

    QRect contentRect = option.rect.adjusted(margin, margin, -margin, -margin);
    QSize bubbleSize(doc.idealWidth() + 2 * padding, doc.size().height() + 2 * padding);

    // Position the bubble
    QRect bubbleRect;
    if (isMine) {
        bubbleRect = QRect(QPoint(contentRect.right() - bubbleSize.width() - avatarSize, contentRect.top()), bubbleSize);
    } else {
        bubbleRect = QRect(QPoint(contentRect.left() + avatarSize, contentRect.top()), bubbleSize);
    }

    // Draw the bubble
    painter->setPen(Qt::NoPen);
    painter->setBrush(bubbleColor);
    painter->drawRoundedRect(bubbleRect, 10, 10);

    // Draw the text
    painter->translate(bubbleRect.left() + padding, bubbleRect.top() + padding);
    doc.drawContents(painter);

    painter->restore();
}

QSize MessageDelegate::sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QString text = index.data(MessageModel::TextRole).toString();

    QTextDocument doc;
    doc.setHtml(text);
    doc.setTextWidth(option.rect.width() * 0.7);

    const int padding = 10;
    const int margin = 5;

    return QSize(doc.idealWidth() + 2 * padding, doc.size().height() + 2 * padding + 2 * margin);
}
