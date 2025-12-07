#include "qt_ui/LoginWindow.h"
#include "qt_ui/BackendService.h"
#include <QFile>
#include <QDebug>
#include <QMessageBox>
#include <QFutureWatcher>
#include <QStringList>

LoginWindow::LoginWindow(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("登录"));
    setWindowFlags(Qt::FramelessWindowHint | Qt::WindowSystemMenuHint);
    setAttribute(Qt::WA_TranslucentBackground);

    auto titleLabel = new QLabel(tr("E2EE 登录"), this);
    titleLabel->setAlignment(Qt::AlignCenter);

    usernameLineEdit = new QLineEdit(this);
    usernameLineEdit->setPlaceholderText(tr("用户名"));

    passwordLineEdit = new QLineEdit(this);
    passwordLineEdit->setPlaceholderText(tr("密码"));
    passwordLineEdit->setEchoMode(QLineEdit::Password);

    loginButton = new QPushButton(tr("登录"), this);
    connect(loginButton, &QPushButton::clicked, this, &LoginWindow::on_loginButton_clicked);

    auto layout = new QVBoxLayout(this);
    layout->setContentsMargins(24, 24, 24, 24);
    layout->setSpacing(12);
    layout->addWidget(titleLabel);
    layout->addWidget(usernameLineEdit);
    layout->addWidget(passwordLineEdit);
    layout->addWidget(loginButton);

    applyStylesheet();
}

LoginWindow::~LoginWindow() = default;

void LoginWindow::applyStylesheet()
{
    QStringList candidates = {
        ":/styles/login.qss",
        ":/main.qss",
        ":/login.qss",
        "login.qss",
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

void LoginWindow::on_loginButton_clicked()
{
    // 阶段 3: 对接真实登录逻辑
    loginButton->setEnabled(false);
    loginButton->setText(tr("登录中..."));

    QString username = usernameLineEdit->text();
    QString password = passwordLineEdit->text();

    auto watcher = new QFutureWatcher<int>(this);
    connect(watcher, &QFutureWatcher<int>::finished, this, [this, watcher]() {
        int result = watcher->result();
        if (result == 0) { // 0 代表成功
            accept(); // 关闭登录对话框，主程序将继续
        } else {
            // 根据 bdtd.txt 的错误码显示信息
            QMessageBox::critical(this, "登录失败", QString("错误码: %1").arg(result));
            loginButton->setEnabled(true);
            loginButton->setText(tr("登录"));
        }
        watcher->deleteLater();
    });

    QFuture<int> future = BackendService::instance()->login(username, password);
    watcher->setFuture(future);
}
