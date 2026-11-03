#include "mainwindow.h"
#include "QuarantineDialog.h"
#include "SettingsDialog.h"
#include "../service/AntiTamper.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFrame>
#include <QFileDialog>
#include <QMessageBox>
#include <QDragEnterEvent>
#include <QMimeData>
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

        // Calculate angular difference from sweep angle
        float diff = std::fabs(dotAngle - angle_);
        if (diff > 180.0f) diff = 360.0f - diff;

        if (diff < 30.0f) {
            // Bright sweeping radar highlight
            float intensity = 1.0f - (diff / 30.0f);
            p.setBrush(QColor(56, 189, 248, static_cast<int>(255 * intensity)));
            p.setPen(Qt::NoPen);
            p.drawEllipse(QPointF(x, y), 3.0, 3.0);
        } else {
            // Dim background dot
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

    scanPollTimer_ = new QTimer(this);
    connect(scanPollTimer_, &QTimer::timeout, this, &MainWindow::OnScanTimerTick);
}

void MainWindow::SetupUi() {
    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* rootLayout = new QVBoxLayout(central);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    // Custom Draggable Title Bar
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

    auto* btnClose = new QPushButton("✕", titleBar);
    btnClose->setFixedSize(28, 28);
    btnClose->setStyleSheet("background: transparent; border: none; font-size: 12px; color: #94a3b8;");
    connect(btnClose, &QPushButton::clicked, this, &QMainWindow::close);

    titleLayout->addWidget(btnMin);
    titleLayout->addWidget(btnClose);
    rootLayout->addWidget(titleBar);
}

void MainWindow::SetupSidebar(QHBoxLayout* contentLayout) {
    auto* sidebar = new QFrame(this);
    sidebar->setFixedWidth(200);
    sidebar->setObjectName("sidebarPanel");

    auto* sideLayout = new QVBoxLayout(sidebar);
    sideLayout->setContentsMargins(12, 20, 12, 20);
    sideLayout->setSpacing(8);

    btnNavDash_ = new QPushButton("Dashboard", sidebar);
    btnNavDash_->setObjectName("navButton");
    btnNavDash_->setChecked(true);
    connect(btnNavDash_, &QPushButton::clicked, this, &MainWindow::OnNavDashboard);

    btnNavQuar_ = new QPushButton("Quarantine Vault", sidebar);
    btnNavQuar_->setObjectName("navButton");
    connect(btnNavQuar_, &QPushButton::clicked, this, &MainWindow::OnNavQuarantine);

    btnNavSett_ = new QPushButton("Settings", sidebar);
    btnNavSett_->setObjectName("navButton");
    connect(btnNavSett_, &QPushButton::clicked, this, &MainWindow::OnNavSettings);

    auto* btnAudit = new QPushButton("Integrity Audit", sidebar);
    btnAudit->setObjectName("navButton");
    connect(btnAudit, &QPushButton::clicked, this, &MainWindow::OnRunIntegrityAudit);

    sideLayout->addWidget(btnNavDash_);
    sideLayout->addWidget(btnNavQuar_);
    sideLayout->addWidget(btnNavSett_);
    sideLayout->addWidget(btnAudit);
    sideLayout->addStretch();

    auto* verLabel = new QLabel("v2.0.0-PROD (C++20)", sidebar);
    verLabel->setStyleSheet("color: #475569; font-size: 10px; font-weight: 600; padding: 6px;");
    sideLayout->addWidget(verLabel);

    contentLayout->addWidget(sidebar);
}

QWidget* MainWindow::CreateDashboardPage() {
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(35, 30, 35, 30);
    layout->setSpacing(25);

    // Security Status Card
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

    // Section Header
    auto* scanHeader = new QLabel("On-Demand Malware Scanning", page);
    scanHeader->setStyleSheet("font-size: 16px; font-weight: 700; color: #f8fafc;");
    layout->addWidget(scanHeader);

    // Scan Actions Grid
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

    grid->addWidget(makeScanCard("Quick Scan", "Inspects active user directories, downloads, desktop, and startup locations.", &MainWindow::OnStartQuickScan), 0, 0);
    grid->addWidget(makeScanCard("Full System Scan", "Exhaustive traversal across all local fixed drives and system partitions.", &MainWindow::OnStartFullScan), 0, 1);
    grid->addWidget(makeScanCard("Custom Scan", "Select specific folder or file for deep structural heuristic evaluation.", &MainWindow::OnStartCustomScan), 0, 2);

    layout->addLayout(grid);
    layout->addStretch();

    // Drop Zone Hint
    auto* dropHint = new QLabel("Tip: Drag and drop files or ZIP archives anywhere onto this window to inspect.", page);
    dropHint->setStyleSheet("color: #64748b; font-size: 12px; text-align: center;");
    dropHint->setAlignment(Qt::AlignCenter);
    layout->addWidget(dropHint);

    return page;
}

QWidget* MainWindow::CreateScanningPage() {
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(40, 30, 40, 30);
    layout->setSpacing(20);

    layout->addStretch();

    // Centered Scanner Radar Ring
    auto* ringHolder = new QHBoxLayout();
    scannerRing_ = new ScannerRingWidget(page);
    ringHolder->addStretch();
    ringHolder->addWidget(scannerRing_);
    ringHolder->addStretch();
    layout->addLayout(ringHolder);

    // Percentage Label
    scanPercentLabel_ = new QLabel("0%", page);
    scanPercentLabel_->setAlignment(Qt::AlignCenter);
    scanPercentLabel_->setStyleSheet("font-size: 32px; font-weight: 800; color: #38bdf8;");
    layout->addWidget(scanPercentLabel_);

    // Progress Bar
    scanProgressBar_ = new QProgressBar(page);
    scanProgressBar_->setRange(0, 100);
    scanProgressBar_->setValue(0);
    layout->addWidget(scanProgressBar_);

    // File Path Ticker
    scanPathLabel_ = new QLabel("Initializing engine...", page);
    scanPathLabel_->setAlignment(Qt::AlignCenter);
    scanPathLabel_->setStyleSheet("color: #94a3b8; font-size: 12px;");
    layout->addWidget(scanPathLabel_);

    // Counters Bar
    auto* countersLayout = new QHBoxLayout();
    countersLayout->setSpacing(30);
    countersLayout->setAlignment(Qt::AlignCenter);

    auto makeCounter = [](const QString& label, QLabel*& valueLabel, const QString& color) {
        auto* holder = new QVBoxLayout();
        auto* l = new QLabel(label);
        l->setStyleSheet("font-size: 11px; color: #64748b; font-weight: 600; text-align: center;");
        l->setAlignment(Qt::AlignCenter);

        valueLabel = new QLabel("0");
        valueLabel->setStyleSheet(QString("font-size: 20px; font-weight: 800; color: %1;").arg(color));
        valueLabel->setAlignment(Qt::AlignCenter);

        holder->addWidget(l);
        holder->addWidget(valueLabel);
        return holder;
    };

    countersLayout->addLayout(makeCounter("FILES SCANNED", countScannedLabel_, "#f8fafc"));
    countersLayout->addLayout(makeCounter("SUSPICIOUS", countThreatsLabel_, "#f59e0b"));
    countersLayout->addLayout(makeCounter("QUARANTINED", countQuarantinedLabel_, "#ef4444"));
    layout->addLayout(countersLayout);

    layout->addStretch();

    // Cancel Button
    auto* btnHolder = new QHBoxLayout();
    btnCancelScan_ = new QPushButton("Cancel Scan", page);
    btnCancelScan_->setObjectName("btnDanger");
    btnCancelScan_->setFixedWidth(140);
    connect(btnCancelScan_, &QPushButton::clicked, this, &MainWindow::OnCancelScan);
    btnHolder->addStretch();
    btnHolder->addWidget(btnCancelScan_);
    btnHolder->addStretch();
    layout->addLayout(btnHolder);

    return page;
}

QWidget* MainWindow::CreateSummaryPage() {
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(40, 40, 40, 40);
    layout->setSpacing(25);

    auto* title = new QLabel("Scan Complete", page);
    title->setStyleSheet("font-size: 24px; font-weight: 800; color: #f8fafc;");
    layout->addWidget(title);

    auto* card = new QFrame(page);
    card->setObjectName("card");
    auto* cardLayout = new QVBoxLayout(card);
    cardLayout->setContentsMargins(30, 30, 30, 30);
    cardLayout->setSpacing(16);

    summaryScannedLabel_ = new QLabel("Files Scanned: 0", card);
    summaryScannedLabel_->setStyleSheet("font-size: 16px; color: #e2e8f0;");

    summaryThreatsLabel_ = new QLabel("Threats Detected: 0", card);
    summaryThreatsLabel_->setStyleSheet("font-size: 16px; color: #f59e0b;");

    summaryQuarantinedLabel_ = new QLabel("Files Quarantined: 0", card);
    summaryQuarantinedLabel_->setStyleSheet("font-size: 16px; color: #ef4444; font-weight: bold;");

    cardLayout->addWidget(summaryScannedLabel_);
    cardLayout->addWidget(summaryThreatsLabel_);
    cardLayout->addWidget(summaryQuarantinedLabel_);
    layout->addWidget(card);

    layout->addStretch();

    auto* doneBtn = new QPushButton("Back to Dashboard", page);
    doneBtn->setObjectName("btnPrimary");
    doneBtn->setFixedWidth(160);
    connect(doneBtn, &QPushButton::clicked, this, &MainWindow::OnNavDashboard);
    layout->addWidget(doneBtn);

    return page;
}

// =================== Navigation Slots ===================

void MainWindow::OnNavDashboard() {
    pages_->setCurrentIndex(0);
    btnNavDash_->setChecked(true);
    btnNavQuar_->setChecked(false);
    btnNavSett_->setChecked(false);
}

void MainWindow::OnNavQuarantine() {
    QuarantineDialog dlg(this);
    dlg.exec();
}

void MainWindow::OnNavSettings() {
    SettingsDialog dlg(this);
    dlg.exec();
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
    pages_->setCurrentIndex(1); // Switch to Scan View

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
            if (path.length() > 50) {
                path = "..." + path.right(47);
            }
            scanPathLabel_->setText(path);
        }

        if (info.isComplete) {
            scannerRing_->StopAnimation();
            scanPollTimer_->stop();
            isScanning_ = false;
            ShowSummary(info.filesScanned, info.threatsDetected, info.filesQuarantined);
        }
    }
}

void MainWindow::ShowSummary(int scanned, int threats, int quarantined) {
    summaryScannedLabel_->setText(QString("Files Scanned: %1").arg(scanned));
    summaryThreatsLabel_->setText(QString("Threats Detected: %1").arg(threats));
    summaryQuarantinedLabel_->setText(QString("Files Quarantined: %1").arg(quarantined));
    pages_->setCurrentIndex(2); // Switch to Summary View
}

// =================== Drag & Drop / Window Drag ===================

void MainWindow::dragEnterEvent(QDragEnterEvent* event) {
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
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
    if (event->buttons() & Qt::LeftButton) {
        move(event->globalPosition().toPoint() - dragPosition_);
        event->accept();
    }
}

} // namespace ui
} // namespace vantor
