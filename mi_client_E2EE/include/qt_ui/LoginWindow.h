#pragma once

#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>

class LoginWindow : public QDialog
{
    Q_OBJECT

public:
    LoginWindow(QWidget *parent = nullptr);
    ~LoginWindow();

private slots:
    void on_loginButton_clicked();

private:
    QLineEdit* usernameLineEdit = nullptr;
    QLineEdit* passwordLineEdit = nullptr;
    QPushButton* loginButton = nullptr;

    void applyStylesheet();
};
