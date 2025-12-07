#include "qt_ui/MainWindow.h"
#include "qt_ui/ChatWidget.h"
#include "qt_ui/BackendService.h"
#include "qt_ui/ConversationItemWidget.h"
#include <QFile>
#include <QDebug>
#include <QMouseEvent>
#include <QListWidgetItem>
#include <QFutureWatcher>
#include <QSpacerItem>
#include <QToolButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QAbstractItemView>
#include <QStringList>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    // 设置无边框窗口
    setWindowFlags(Qt::FramelessWindowHint);

    // Title bar
    titleBarWidget = new QWidget(this);
    titleBarWidget->setObjectName("titleBarWidget");
    auto titleLayout = new QHBoxLayout(titleBarWidget);
    titleLayout->setContentsMargins(10, 4, 10, 4);
    auto titleLabel = new QLabel(tr("E2EE Chat"), titleBarWidget);
    auto closeBtn = new QToolButton(titleBarWidget);
    closeBtn->setText("×");
    connect(closeBtn, &QToolButton::clicked, this, &QMainWindow::close);
    titleLayout->addWidget(titleLabel);
    titleLayout->addStretch();
    titleLayout->addWidget(closeBtn);

    // Left list
    conversationListWidget = new QListWidget(this);
    conversationListWidget->setObjectName("conversationListWidget");
    conversationListWidget->setSpacing(4);
    conversationListWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    conversationListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    conversationListWidget->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

    // Chat area
    m_chatWidget = new ChatWidget(this);

    // Layout
    auto central = new QWidget(this);
    mainLayout = new QGridLayout(central);
    mainLayout->setContentsMargins(0,0,0,0);
    mainLayout->setSpacing(0);
    mainLayout->addWidget(titleBarWidget, 0, 0, 1, 2);
    mainLayout->addWidget(conversationListWidget, 1, 0);
    mainLayout->addWidget(m_chatWidget, 1, 1);
    mainLayout->setColumnStretch(1, 1);
    mainLayout->setRowStretch(1, 1);
    setCentralWidget(central);

    setupUiStyle();
    setupConnections();
    loadInitialData();
}

MainWindow::~MainWindow()
{
}

void MainWindow::setupUiStyle()
{
    QStringList candidates = {
        ":/styles/main.qss",
        ":/main.qss",
        "main.qss"
    };
    for (const auto& path : candidates) {
        QFile file(path);
        if (file.open(QFile::ReadOnly)) {
            this->setStyleSheet(QLatin1String(file.readAll()));
            break;
        }
    }
}

void MainWindow::setupConnections()
{
    BackendService* backend = BackendService::instance();
    connect(backend, &BackendService::conversationsReady, this, &MainWindow::onConversationsReady);
    connect(backend, &BackendService::historyReady, this, &MainWindow::onHistoryReady);
    connect(backend, &BackendService::newMessageReceived, this, &MainWindow::onNewMessageReceived);

    connect(conversationListWidget, &QListWidget::currentItemChanged, this, &MainWindow::onConversationSelected);
}

void MainWindow::loadInitialData()
{
    conversationListWidget->clear();

    auto watcher = new QFutureWatcher<QVariantList>(this);
    connect(watcher, &QFutureWatcher<QVariantList>::finished, this, [this, watcher](){
        onConversationsReady(watcher->result());
        watcher->deleteLater();
    });
    watcher->setFuture(BackendService::instance()->getConversations());
}

void MainWindow::onConversationsReady(const QVariantList& conversations)
{
    conversationListWidget->clear();
    for (const QVariant& item : conversations) {
        updateConversationItem(item.toMap());
    }
}

void MainWindow::onHistoryReady(const QString& conversationId, const QVariantList& messages)
{
    // 确保这个历史记录是给当前打开的聊天窗口的
    if (m_chatWidget->currentConversationId() == conversationId) {
        m_chatWidget->displayHistory(messages);
    }
}

void MainWindow::onNewMessageReceived(const QVariantMap& message)
{
    QString conversationId = message.value("conversationId").toString();
    updateConversationItem(message);

    if (m_chatWidget->currentConversationId() == conversationId) {
        m_chatWidget->appendMessage(message);
    }
}

void MainWindow::onConversationSelected(QListWidgetItem* current, QListWidgetItem* previous)
{
    if (!current) return;

    QString conversationId = current->data(Qt::UserRole).toString();
    m_chatWidget->setCurrentConversation(conversationId);

    auto watcher = new QFutureWatcher<QVariantList>(this);
    connect(watcher, &QFutureWatcher<QVariantList>::finished, this, [this, watcher, conversationId](){
        onHistoryReady(conversationId, watcher->result());
        watcher->deleteLater();
    });
    watcher->setFuture(BackendService::instance()->getHistory(conversationId));
}

void MainWindow::updateConversationItem(const QVariantMap& conversationData)
{
    // 此处省略查找现有 Item 的逻辑，简化为直接添加/更新
    // 实际项目中应先查找，再更新或插入
    auto itemWidget = new ConversationItemWidget(
        QIcon(":/icons/avatar_placeholder.svg"),
        conversationData.value("name").toString(),
        conversationData.value("lastMessage").toString(),
        conversationData.value("timestamp").toString()
    );
    auto* listItem = new QListWidgetItem();
    listItem->setData(Qt::UserRole, conversationData.value("id").toString());
    listItem->setSizeHint(itemWidget->sizeHint());
    conversationListWidget->insertItem(0, listItem); // 新消息置顶
    conversationListWidget->setItemWidget(listItem, itemWidget);
}

// 实现无边框窗口拖动
void MainWindow::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton && titleBarWidget->geometry().contains(event->pos())) {
        m_dragging = true;
        m_dragPosition = event->globalPos() - frameGeometry().topLeft();
        event->accept();
    }
}

void MainWindow::mouseMoveEvent(QMouseEvent *event)
{
    if (event->buttons() & Qt::LeftButton && m_dragging) {
        move(event->globalPos() - m_dragPosition);
        event->accept();
    }
}

void MainWindow::mouseReleaseEvent(QMouseEvent *event)
{
    m_dragging = false;
    event->accept();
}
