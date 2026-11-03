#include <QApplication>
#include <QFile>
#include "mainwindow.h"
#include "../service/AntiTamper.h"

int main(int argc, char* argv[]) {
    // 1. Anti-Tamper check on UI startup
    vantor::antitamper::AntiTamper::Instance().Initialize();
    vantor::antitamper::AntiTamper::HideThreadFromDebugger(GetCurrentThread());

    QApplication app(argc, argv);
    app.setApplicationName("Vantor Antivirus");
    app.setOrganizationName("Vantor Security");

    // 2. Load Dark Theme Stylesheet
    QFile styleFile(":/style.qss");
    if (styleFile.open(QFile::ReadOnly)) {
        QString styleSheet = QLatin1String(styleFile.readAll());
        app.setStyleSheet(styleSheet);
        styleFile.close();
    } else {
        // Fallback: load directly from local theme directory
        QFile localStyle("theme/style.qss");
        if (localStyle.open(QFile::ReadOnly)) {
            QString styleSheet = QLatin1String(localStyle.readAll());
            app.setStyleSheet(styleSheet);
            localStyle.close();
        }
    }

    vantor::ui::MainWindow w;
    w.show();

    return app.exec();
}
