#include <QApplication>
#include "qt_ui/LoginWindow.h"
#include "qt_ui/MainWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    LoginWindow login;
    if (login.exec() == QDialog::Accepted) {
        MainWindow w;
        w.show();
        return app.exec();
    }
    return 0;
}
 
