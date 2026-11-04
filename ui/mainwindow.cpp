#include "mainwindow.h"
#include "QuarantineDialog.h"
#include "SettingsDialog.h"
#include "../service/AntiTamper.h"
#include "../common/Common.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFrame>
#include <QFileDialog>
#include <QMessageBox>
#include <QDragEnterEvent>
#include <QMimeData>
#include <QMenu>
#include <QAction>
#include <QFontMetrics>
#include <QApplication>
#include <cmath>

namespace vantor {
namespace ui {

// =================== ScannerRingWidget Implementation ===================

ScannerRingWidget::ScannerRingWidget(QWidget* parent)
    : QWidget(parent) {
    setFixedSize(220, 220);
    animTimer_ = new QTimer(this);
    connect(animTimer_, &QTimer::timeout, this, [this]() {
        if (limiter_.ShouldRender()) {
            angle_ += 3.5f;
            if (angle_ >= 360.0f) angle_ -= 360.0f;
            update();
        }
    });
}

void ScannerRingWidget::StartAnimation() {
    angle_ = 0.0f;
    animTimer_->start(limiter_.GetTargetIntervalMs());
}

void ScannerRingWidget::StopAnimation() {
    animTimer_->stop();
}

void ScannerRingWidget::SetTargetFps(int fps) {
    limiter_.SetTargetFps(fps);
    if (animTimer_->isActive()) {
        animTimer_->setInterval(limiter_.GetTargetIntervalMs());
    }
}

void ScannerRingWidget::paintEvent(QPaintEvent* /*event*/) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    int cx = width() / 2;
    int cy = height() / 2;
    float radius = 80.0f;

    // Draw 72 dots ring
    constexpr int DOT_COUNT = 72;
    for (int i = 0; i < DOT_COUNT; ++i) {
        float dotAngle = static_cast<float>(i * (360.0 / DOT_COUNT));
        float rad = dotAngle * 3.14159265f / 180.0f;
        float x = cx + radius * std::cos(rad);
        float y = cy + radius * std::sin(rad);

        float diff = std::fabs(dotAngle - angle_);
        if (diff > 180.0f) diff = 360.0f - diff;

        if (diff < 30.0f) {
            float intensity = 1.0f - (diff / 30.0f);
            p.setBrush(QColor(56, 189, 248, static_cast<int>(255 * intensity)));
            p.setPen(Qt::NoPen);
            p.drawEllipse(QPointF(x, y), 3.0, 3.0);
        } else {
            p.setBrush(QColor(51, 65, 85, 120));
            p.setPen(Qt::NoPen);
            p.drawEllipse(QPointF(x, y), 1.5, 1.5);
        }
    }

    // Inner glowing ring
    QPen innerPen(QColor(14, 165, 233, 40), 2.0);
    p.setPen(innerPen);
    p.setBrush(Qt::NoBrush);
    p.drawEllipse(QPoint(cx, cy), 65, 65);
}

// =================== MainWindow Implementation ===================

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent) {
    setWindowFlags(Qt::FramelessWindowHint | Qt::Window);
    resize(980, 640);
    setAcceptDrops(true);

    SetupUi();
    SetupSystemTray();

    scanPollTimer_ = new QTimer(this);
    connect(scanPollTimer_, &QTimer::timeout, this, &MainWindow::OnScanTimerTick);
}

void MainWindow::SetupUi() {
    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* rootLayout = new QVBoxLayout(central);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    // Custom Draggable Title Bar (Minor 31: Maximize button)
    SetupTitleBar(rootLayout);

    // Main Body (Sidebar + Stacked Pages)
    auto* contentLayout = new QHBoxLayout();
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(0);

    SetupSidebar(contentLayout);

    pages_ = new QStackedWidget(this);
    pages_->addWidget(CreateDashboardPage());  // Index 0
    pages_->addWidget(CreateScanningPage());   // Index 1
    pages_->addWidget(CreateSummaryPage());    // Index 2

    contentLayout->addWidget(pages_, 1);
    rootLayout->addLayout(contentLayout, 1);

    // Minor 31: Add QSizeGrip in bottom right
    auto* bottomRow = new QHBoxLayout();
    bottomRow->setContentsMargins(0, 0, 4, 4);
    bottomRow->addStretch();
    sizeGrip_ = new QSizeGrip(central);
    bottomRow->addWidget(sizeGrip_);
    rootLayout->addLayout(bottomRow);
}

void MainWindow::SetupTitleBar(QVBoxLayout* rootLayout) {
    auto* titleBar = new QFrame(this);
    titleBar->setFixedHeight(40);
    titleBar->setStyleSheet("background-color: #070a12; border-bottom: 1px solid #1e293b;");

    auto* titleLayout = new QHBoxLayout(titleBar);
    titleLayout->setContentsMargins(16, 0, 8, 0);

    auto* appTitle = new QLabel("VANTOR // ENDPOINT SECURITY SUITE", titleBar);
    appTitle->setStyleSheet("font-weight: 700; font-size: 11px; letter-spacing: 1px; color: #38bdf8;");
    titleLayout->addWidget(appTitle);
    titleLayout->addStretch();

    auto* btnMin = new QPushButton("—", titleBar);
    btnMin->setFixedSize(28, 28);
    btnMin->setStyleSheet("background: transparent; border: none; font-size: 12px; color: #94a3b8;");
    connect(btnMin, &QPushButton::clicked, this, &QMainWindow::showMinimized);

    btnMax_ = new QPushButton("□", titleBar);
    btnMax_->setFixedSize(28, 28);
    btnMax_->setStyleSheet("background: transparent; border: none; font-size: 12px; color: #94a3b8;");
    connect(btnMax_, &QPushButton::clicked, this, &MainWindow::OnToggleMaximize);

    auto* btnClose = new QPushButton("✕", titleBar);
    btnClose->setFixedSize(28, 28);
    btnClose->setStyleSheet("background: transparent; border: none; font-size: 12px; color: #94a3b8;");
    connect(btnClose, &QPushButton::clicked, this, &QMainWindow::close);

    titleLayout->addWidget(btnMin);
    titleLayout->addWidget(btnMax_);
    titleLayout->addWidget(btnClose);
    rootLayout->addWidget(titleBar);
}

void MainWindow::OnToggleMaximize() {
    if (isMaximized()) {
        showNormal();
        btnMax_->setText("□");
    } else {
        showMaximized();
        btnMax_->setText("❐");
    }
}

void MainWindow::SetupSidebar(QHBoxLayout* contentLayout) {
    auto* sidebar = new QFrame(this);
    sidebar->setFixedWidth(200);
    sidebar->setObjectName("sidebarPanel");

    auto* sideLayout = new QVBoxLayout(sidebar);
    sideLayout->setContentsMargins(12, 20, 12, 20);
    sideLayout->setSpacing(8);

    // Minor 34: Navigation buttons are checkable
    btnNavDash_ = new QPushButton("Dashboard", sidebar);
    btnNavDash_->setObjectName("navButton");
    btnNavDash_->setCheckable(true);
    btnNavDash_->setChecked(true);
    connect(btnNavDash_, &QPushButton::clicked, this, &MainWindow::OnNavDashboard);

    btnNavQuar_ = new QPushButton("Quarantine Vault", sidebar);
    btnNavQuar_->setObjectName("navButton");
    btnNavQuar_->setCheckable(true);
    connect(btnNavQuar_, &QPushButton::clicked, this, &MainWindow::OnNavQuarantine);

    btnNavSett_ = new QPushButton("Settings", sidebar);
    btnNavSett_->setObjectName("navButton");
    btnNavSett_->setCheckable(true);
    connect(btnNavSett_, &QPushButton::clicked, this, &MainWindow::OnNavSettings);

    auto* btnAudit = new QPushButton("Integrity Audit", sidebar);
    btnAudit->setObjectName("navButton");
    connect(btnAudit, &QPushButton::clicked, this, &MainWindow::OnRunIntegrityAudit);

    sideLayout->addWidget(btnNavDash_);
    sideLayout->addWidget(btnNavQuar_);
    sideLayout->addWidget(btnNavSett_);
    sideLayout->addWidget(btnAudit);
    sideLayout->addStretch();

    // Minor 40: Use VANTOR_VERSION
    auto* verLabel = new QLabel(QString("v%1 (C++20)").arg(VANTOR_VERSION), sidebar);
    verLabel->setStyleSheet("color: #475569; font-size: 10px; font-weight: 600; padding: 6px;");
    sideLayout->addWidget(verLabel);

    contentLayout->addWidget(sidebar);
}

// Major 4: Windows System Tray Integration
void MainWindow::SetupSystemTray() {
    trayIcon_ = new QSystemTrayIcon(this);
    
    // Draw programmatic shield icon
    QPixmap pixmap(32, 32);
    pixmap.fill(Qt::transparent);
    QPainter p(&pixmap);
    p.setRenderHint(QPainter::Antialiasing);
    p.setBrush(QColor(2, 132, 199));
    p.setPen(Qt::NoPen);
    p.drawRoundedRect(4, 4, 24, 24, 6, 6);
    p.setPen(QPen(Qt::white, 2));
    p.drawLine(10, 16, 14, 20);
    p.drawLine(14, 20, 22, 12);
    p.end();

    trayIcon_->setIcon(QIcon(pixmap));
    trayIcon_->setToolTip("Vantor Antivirus Endpoint Security");

    trayMenu_ = new QMenu(this);
    trayMenu_->addAction("Open Vantor Dashboard", this, [this]() {
        showNormal();
        activateWindow();
    });
    trayMenu_->addAction("Quick Scan", this, &MainWindow::OnStartQuickScan);
    trayMenu_->addSeparator();
    trayMenu_->addAction("Exit Vantor", qApp, &QCoreApplication::quit);

    trayIcon_->setContextMenu(trayMenu_);
    connect(trayIcon_, &QSystemTrayIcon::activated, this, &MainWindow::OnTrayIconActivated);
    trayIcon_->show();
}

void MainWindow::OnTrayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::DoubleClick || reason == QSystemTrayIcon::Trigger) {
        if (isVisible()) {
            hide();
        } else {
            showNormal();
            activateWindow();
        }
    }
}

void MainWindow::changeEvent(QEvent* event) {
    if (event->type() == QEvent::ActivationChange) {
        // Minor 36: Drop FPS to 15 when window is inactive
        if (!isActiveWindow() && scannerRing_) {
            scannerRing_->SetTargetFps(15);
        } else if (scannerRing_) {
            scannerRing_->SetTargetFps(60);
        }
    } else if (event->type() == QEvent::WindowStateChange) {
        // Major 4: Minimize to tray
        if (isMinimized()) {
            hide();
            if (trayIcon_) {
                trayIcon_->showMessage("Vantor Antivirus", "Minimized to tray. Real-Time Protection remains active.", QSystemTrayIcon::Information, 2000);
            }
        }
    }
    QMainWindow::changeEvent(event);
}

QWidget* MainWindow::CreateDashboardPage() {
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(35, 30, 35, 30);
    layout->setSpacing(25);

    statusCard_ = new QFrame(page);
    statusCard_->setObjectName("statusCardSafe");
    statusCard_->setFixedHeight(110);

    auto* cardLayout = new QVBoxLayout(statusCard_);
    cardLayout->setContentsMargins(24, 20, 24, 20);

    statusTitle_ = new QLabel("SYSTEM PROTECTED", statusCard_);
    statusTitle_->setStyleSheet("font-size: 20px; font-weight: 800; color: #ffffff; letter-spacing: 0.5px;");

    statusSubtitle_ = new QLabel("Real-Time Filesystem & Anti-Tamper Defenses Active", statusCard_);
    statusSubtitle_->setStyleSheet("font-size: 13px; color: #a7f3d0;");

    cardLayout->addWidget(statusTitle_);
    cardLayout->addWidget(statusSubtitle_);
    layout->addWidget(statusCard_);

    auto* scanHeader = new QLabel("On-Demand Malware Scanning", page);
    scanHeader->setStyleSheet("font-size: 16px; font-weight: 700; color: #f8fafc;");
    layout->addWidget(scanHeader);

    auto* grid = new QGridLayout();
    grid->setSpacing(16);

    auto makeScanCard = [this](const QString& title, const QString& desc, auto slot) {
        auto* card = new QFrame();
        card->setObjectName("card");
        auto* cl = new QVBoxLayout(card);
        cl->setContentsMargins(20, 20, 20, 20);

        auto* t = new QLabel(title, card);
        t->setStyleSheet("font-size: 15px; font-weight: 700; color: #f8fafc;");
        auto* d = new QLabel(desc, card);
        d->setStyleSheet("font-size: 12px; color: #94a3b8; margin-top: 4px;");
        d->setWordWrap(true);

        auto* btn = new QPushButton("Start Scan", card);
        btn->setObjectName("btnPrimary");
        connect(btn, &QPushButton::clicked, this, slot);

        cl->addWidget(t);
        cl->addWidget(d);
        cl->addStretch();
        cl->addWidget(btn);
        return card;
    };

    grid->addWidget(makeScanCard("Quick Scan", "Scans common system startup locations, running processes, memory, and critical directories.", &MainWindow::OnStartQuickScan), 0, 0);
    grid->addWidget(makeScanCard("Full System Scan", "Comprehensive scan inspecting all local partitions, archives, boot structures, and storage media.", &MainWindow::OnStartFullScan), 0, 1);
    grid->addWidget(makeScanCard("Custom Path Scan", "Target a specific folder or drive for isolated inspection, heuristics, and hash comparison.", &MainWindow::OnStartCustomScan), 0, 2);

    layout->addLayout(grid);
    layout->addStretch();
    return page;
}

QWidget* MainWindow::CreateScanningPage() {
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);
    layout->setAlignment(Qt::AlignCenter);
    layout->setSpacing(20);

    scannerRing_ = new ScannerRingWidget(page);
    layout->addWidget(scannerRing_, 0, Qt::AlignCenter);

    scanPercentLabel_ = new QLabel("0%", page);
    scanPercentLabel_->setStyleSheet("font-size: 24px; font-weight: 800; color: #38bdf8;");
    layout->addWidget(scanPercentLabel_, 0, Qt::AlignCenter);

    scanPathLabel_ = new QLabel("Preparing scan engine...", page);
    scanPathLabel_->setStyleSheet("color: #94a3b8; font-size: 12px;");
    scanPathLabel_->setAlignment(Qt::AlignCenter);
    layout->addWidget(scanPathLabel_, 0, Qt::AlignCenter);

    scanProgressBar_ = new QProgressBar(page);
    scanProgressBar_->setFixedWidth(400);
    scanProgressBar_->setFixedHeight(6);
    scanProgressBar_->setTextVisible(false);
    layout->addWidget(scanProgressBar_, 0, Qt::AlignCenter);

    auto* countersLayout = new QHBoxLayout();
    countersLayout->setSpacing(30);

    auto makeCounter = [](const QString& label, QLabel*& valLabel) {
        auto* frame = new QFrame();
        auto* l = new QVBoxLayout(frame);
        l->setContentsMargins(0, 0, 0, 0);
        l->setSpacing(2);
        l->setAlignment(Qt::AlignCenter);

        valLabel = new QLabel("0", frame);
        valLabel->setStyleSheet("font-size: 18px; font-weight: 700; color: #f8fafc;");
        valLabel->setAlignment(Qt::AlignCenter);

        auto* t = new QLabel(label, frame);
        t->setStyleSheet("font-size: 11px; color: #64748b; font-weight: 600; text-transform: uppercase;");
        t->setAlignment(Qt::AlignCenter);

        l->addWidget(valLabel);
        l->addWidget(t);
        return frame;
    };

    countersLayout->addWidget(makeCounter("Files Scanned", countScannedLabel_));
    countersLayout->addWidget(makeCounter("Threats Detected", countThreatsLabel_));
    countersLayout->addWidget(makeCounter("Quarantined", countQuarantinedLabel_));

    layout->addLayout(countersLayout);

    btnCancelScan_ = new QPushButton("Cancel Scan", page);
    btnCancelScan_->setObjectName("btnDanger");
    btnCancelScan_->setFixedWidth(140);
    connect(btnCancelScan_, &QPushButton::clicked, this, &MainWindow::OnCancelScan);
    layout->addWidget(btnCancelScan_, 0, Qt::AlignCenter);

    return page;
}

QWidget* MainWindow::CreateSummaryPage() {
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);
    layout->setAlignment(Qt::AlignCenter);
    layout->setSpacing(20);

    auto* icon = new QLabel("🛡️", page);
    icon->setStyleSheet("font-size: 48px;");
    layout->addWidget(icon, 0, Qt::AlignCenter);

    auto* title = new QLabel("Scan Completed", page);
    title->setStyleSheet("font-size: 22px; font-weight: 800; color: #f8fafc;");
    layout->addWidget(title, 0, Qt::AlignCenter);

    summaryScannedLabel_ = new QLabel("Files Scanned: 0", page);
    summaryScannedLabel_->setStyleSheet("font-size: 14px; color: #94a3b8;");
    layout->addWidget(summaryScannedLabel_, 0, Qt::AlignCenter);

    summaryThreatsLabel_ = new QLabel("Threats Detected: 0", page);
    summaryThreatsLabel_->setStyleSheet("font-size: 14px; color: #ef4444; font-weight: 700;");
    layout->addWidget(summaryThreatsLabel_, 0, Qt::AlignCenter);

    summaryQuarantinedLabel_ = new QLabel("Files Quarantined: 0", page);
    summaryQuarantinedLabel_->setStyleSheet("font-size: 14px; color: #f59e0b;");
    layout->addWidget(summaryQuarantinedLabel_, 0, Qt::AlignCenter);

    // Minor 38: "View Threats" button on summary page
    btnViewThreats_ = new QPushButton("View Detected Threats", page);
    btnViewThreats_->setObjectName("btnDanger");
    btnViewThreats_->setFixedWidth(200);
    btnViewThreats_->setVisible(false);
    connect(btnViewThreats_, &QPushButton::clicked, this, &MainWindow::OnViewThreatsClicked);
    layout->addWidget(btnViewThreats_, 0, Qt::AlignCenter);

    auto* btnDone = new QPushButton("Return to Dashboard", page);
    btnDone->setObjectName("btnPrimary");
    btnDone->setFixedWidth(180);
    connect(btnDone, &QPushButton::clicked, this, &MainWindow::OnNavDashboard);
    layout->addWidget(btnDone, 0, Qt::AlignCenter);

    return page;
}

void MainWindow::OnViewThreatsClicked() {
    OnNavQuarantine();
}

// =================== Navigation Slots ===================

void MainWindow::OnNavDashboard() {
    btnNavDash_->setChecked(true);
    btnNavQuar_->setChecked(false);
    btnNavSett_->setChecked(false);
    pages_->setCurrentIndex(0);
}

void MainWindow::OnNavQuarantine() {
    btnNavDash_->setChecked(false);
    btnNavQuar_->setChecked(true);
    btnNavSett_->setChecked(false);
    QuarantineDialog dlg(this);
    dlg.exec();
    btnNavDash_->setChecked(true);
    btnNavQuar_->setChecked(false);
}

void MainWindow::OnNavSettings() {
    btnNavDash_->setChecked(false);
    btnNavQuar_->setChecked(false);
    btnNavSett_->setChecked(true);
    SettingsDialog dlg(this);
    dlg.exec();
    btnNavDash_->setChecked(true);
    btnNavSett_->setChecked(false);
}

void MainWindow::OnRunIntegrityAudit() {
    auto alert = antitamper::AntiTamper::Instance().RunComprehensiveIntegrityCheck();
    if (alert.tampered) {
        QMessageBox::critical(
            this,
            "Security Integrity Alert",
            QString("Tampering Detected!\n\nReason: %1\nTarget: %2\nDetection: %3")
                .arg(QString::fromStdString(alert.reason))
                .arg(QString::fromStdString(alert.affectedTarget))
                .arg(QString::fromStdString(alert.detectionMechanism))
        );
    } else {
        QMessageBox::information(
            this,
            "Integrity Verification Passed",
            "All runtime in-memory code signatures, baseline hashes, and anti-debug protections are intact and unmodified."
        );
    }
}

// =================== Scanning Slots ===================

void MainWindow::OnStartQuickScan() {
    StartScan("quick");
}

void MainWindow::OnStartFullScan() {
    StartScan("full");
}

void MainWindow::OnStartCustomScan() {
    QString dir = QFileDialog::getExistingDirectory(this, "Select Directory to Scan");
    if (!dir.isEmpty()) {
        StartScan("custom", dir.toStdString());
    }
}

void MainWindow::StartScan(const std::string& type, const std::string& path) {
    isScanning_ = true;
    pages_->setCurrentIndex(1);

    scannerRing_->StartAnimation();
    scanProgressBar_->setValue(0);
    scanPercentLabel_->setText("0%");
    scanPathLabel_->setText("Initiating secure scan...");
    countScannedLabel_->setText("0");
    countThreatsLabel_->setText("0");
    countQuarantinedLabel_->setText("0");

    GrpcClient::Instance().TriggerScan(type, path);
    scanPollTimer_->start(150);
}

void MainWindow::OnCancelScan() {
    GrpcClient::Instance().CancelScan();
    scannerRing_->StopAnimation();
    scanPollTimer_->stop();
    isScanning_ = false;
    OnNavDashboard();
}

void MainWindow::OnScanTimerTick() {
    scan::ScanProgressInfo info;
    if (GrpcClient::Instance().GetScanStatus(info)) {
        int percent = static_cast<int>(info.percentComplete);
        scanProgressBar_->setValue(percent);
        scanPercentLabel_->setText(QString::number(percent) + "%");
        countScannedLabel_->setText(QString::number(info.filesScanned));
        countThreatsLabel_->setText(QString::number(info.threatsDetected));

        if (!info.currentFile.empty()) {
            QString path = QString::fromStdString(info.currentFile);
            // Minor 35: Elide path text using QFontMetrics
            QFontMetrics fm(scanPathLabel_->font());
            int labelWidth = scanPathLabel_->width() > 100 ? scanPathLabel_->width() : 500;
            QString elided = fm.elidedText(path, Qt::ElideLeft, labelWidth);
            scanPathLabel_->setText(elided);
        }

        if (info.isComplete) {
            scannerRing_->StopAnimation();
            scanPollTimer_->stop();
            isScanning_ = false;
            ShowSummary(info.filesScanned, info.threatsDetected, info.filesQuarantined);
            
            // Major 4: Notification on scan completion
            if (trayIcon_) {
                QString msg = QString("Scan complete. %1 files checked, %2 threats detected.")
                                  .arg(info.filesScanned).arg(info.threatsDetected);
                trayIcon_->showMessage("Vantor Antivirus", msg,
                                      (info.threatsDetected > 0) ? QSystemTrayIcon::Warning : QSystemTrayIcon::Information, 3000);
            }
        }
    }
}

void MainWindow::ShowSummary(int scanned, int threats, int quarantined) {
    summaryScannedLabel_->setText(QString("Files Scanned: %1").arg(scanned));
    summaryThreatsLabel_->setText(QString("Threats Detected: %1").arg(threats));
    summaryQuarantinedLabel_->setText(QString("Files Quarantined: %1").arg(quarantined));
    
    // Minor 38: Show "View Threats" button if threats > 0
    btnViewThreats_->setVisible(threats > 0);
    pages_->setCurrentIndex(2);
}

// =================== Drag & Drop / Window Drag ===================

void MainWindow::dragEnterEvent(QDragEnterEvent* event) {
    // Minor 37: Extension & local file filter on dragEnterEvent
    if (event->mimeData()->hasUrls()) {
        const auto urls = event->mimeData()->urls();
        if (!urls.isEmpty() && urls.first().isLocalFile()) {
            event->acceptProposedAction();
        }
    }
}

void MainWindow::dropEvent(QDropEvent* event) {
    const auto urls = event->mimeData()->urls();
    if (urls.isEmpty()) return;

    QString localPath = urls.first().toLocalFile();
    if (localPath.isEmpty()) return;

    std::string stdPath = localPath.toStdString();

    // Zip-Bomb Inspection Guard
    auto check = ZipBombGuard::Instance().PreCheckFile(stdPath);
    if (check.isArchive && !check.isSafe) {
        QMessageBox::critical(
            this,
            "Zip-Bomb Detected!",
            QString("Warning: This archive has been flagged by Vantor Zip-Bomb Protection.\n\n%1\n\nExpansion rejected for safety.")
                .arg(QString::fromStdString(check.warningMessage))
        );
        return;
    }

    StartScan("custom", stdPath);
}

void MainWindow::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        dragPosition_ = event->globalPosition().toPoint() - frameGeometry().topLeft();
        event->accept();
    }
}

void MainWindow::mouseMoveEvent(QMouseEvent* event) {
    if (event->buttons() & Qt::LeftButton && !isMaximized()) {
        move(event->globalPosition().toPoint() - dragPosition_);
        event->accept();
    }
}

} // namespace ui
} // namespace vantor
