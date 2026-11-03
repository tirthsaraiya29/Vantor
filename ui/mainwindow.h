#pragma once

#include <QMainWindow>
#include <QStackedWidget>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QTimer>
#include <QPainter>
#include "performance/FrameRateLimiter.h"
#include "ZipBombGuard.h"
#include "GrpcClient.h"

namespace vantor {
namespace ui {

// Custom smooth animated radar scanner ring widget
class ScannerRingWidget : public QWidget {
    Q_OBJECT

public:
    explicit ScannerRingWidget(QWidget* parent = nullptr);
    void StartAnimation();
    void StopAnimation();

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    float angle_ = 0.0f;
    QTimer* animTimer_ = nullptr;
    FrameRateLimiter limiter_{60};
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override = default;

protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;

private slots:
    void OnNavDashboard();
    void OnNavQuarantine();
    void OnNavSettings();
    void OnRunIntegrityAudit();

    void OnStartQuickScan();
    void OnStartFullScan();
    void OnStartCustomScan();
    void OnCancelScan();
    void OnScanTimerTick();

private:
    void SetupUi();
    void SetupTitleBar(QVBoxLayout* rootLayout);
    void SetupSidebar(QHBoxLayout* contentLayout);
    void SetupPages();
    QWidget* CreateDashboardPage();
    QWidget* CreateScanningPage();
    QWidget* CreateSummaryPage();

    void StartScan(const std::string& type, const std::string& path = "");
    void ShowSummary(int scanned, int threats, int quarantined);

    // Navigation & Pages
    QStackedWidget* pages_ = nullptr;
    QPushButton* btnNavDash_ = nullptr;
    QPushButton* btnNavQuar_ = nullptr;
    QPushButton* btnNavSett_ = nullptr;

    // Scan View Widgets
    ScannerRingWidget* scannerRing_ = nullptr;
    QLabel* scanPathLabel_ = nullptr;
    QLabel* scanPercentLabel_ = nullptr;
    QProgressBar* scanProgressBar_ = nullptr;
    QLabel* countScannedLabel_ = nullptr;
    QLabel* countThreatsLabel_ = nullptr;
    QLabel* countQuarantinedLabel_ = nullptr;
    QPushButton* btnCancelScan_ = nullptr;

    // Summary View Widgets
    QLabel* summaryScannedLabel_ = nullptr;
    QLabel* summaryThreatsLabel_ = nullptr;
    QLabel* summaryQuarantinedLabel_ = nullptr;

    // Status Banner
    QFrame* statusCard_ = nullptr;
    QLabel* statusTitle_ = nullptr;
    QLabel* statusSubtitle_ = nullptr;

    // Polling & Animation Timer
    QTimer* scanPollTimer_ = nullptr;
    bool isScanning_ = false;

    // Window Dragging Support
    QPoint dragPosition_;
};

} // namespace ui
} // namespace vantor
