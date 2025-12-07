#pragma once

#include <QMainWindow>
#include <QVariant>
#include <QListWidget>
#include <QGridLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QToolButton>
#include <QPoint>

class ChatWidget;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    // 用于拖动无边框窗口
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;

private slots:
    void onConversationsReady(const QVariantList& conversations);
    void onHistoryReady(const QString& conversationId, const QVariantList& messages);
    void onNewMessageReceived(const QVariantMap& message);
    void onConversationSelected(QListWidgetItem* current, QListWidgetItem* previous);

private:
    QWidget* titleBarWidget = nullptr;
    QListWidget* conversationListWidget = nullptr;
    ChatWidget* m_chatWidget = nullptr;
    QGridLayout* mainLayout = nullptr;
    QPoint m_dragPosition;
    bool m_dragging = false;

    void setupUiStyle();
    void loadInitialData();
    void setupConnections();
    void updateConversationItem(const QVariantMap& conversationData);
};
