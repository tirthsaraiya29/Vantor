#include "SettingsDialog.h"
#include "GrpcClient.h"
#include "../backend/SignatureUpdater.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFileDialog>
#include <QMessageBox>
#include <QUrl>

namespace vantor {
namespace ui {

SettingsDialog::SettingsDialog(QWidget* parent)
    : QDialog(parent) {
    setWindowTitle("Vantor - Security & Protection Settings");
    resize(650, 600);
    SetupUi();
    LoadSettings();
}

void SettingsDialog::SetupUi() {
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(15);

    // 1. Protection Shields Group
    auto* shieldGroup = new QGroupBox("Active Protection Modules", this);
    auto* shieldLayout = new QVBoxLayout(shieldGroup);

    rtpCheck_ = new QCheckBox("Real-Time Filesystem & Process Protection (RTP)", shieldGroup);
    antiTamperCheck_ = new QCheckBox("Enforce User-Mode Anti-Tamper & Integrity Watchdog", shieldGroup);

    shieldLayout->addWidget(rtpCheck_);
    shieldLayout->addWidget(antiTamperCheck_);
    mainLayout->addWidget(shieldGroup);

    // 2. Detection Sensitivity Group
    auto* sensitivityGroup = new QGroupBox("Detection & Threat Thresholds", this);
    auto* sensLayout = new QVBoxLayout(sensitivityGroup);

    auto* heurHeader = new QHBoxLayout();
    heurHeader->addWidget(new QLabel("Heuristic Detection Sensitivity:", sensitivityGroup));
    heurLabel_ = new QLabel("75%", sensitivityGroup);
    heurLabel_->setStyleSheet("font-weight: bold; color: #38bdf8;");
    heurHeader->addStretch();
    heurHeader->addWidget(heurLabel_);
    sensLayout->addLayout(heurHeader);

    heurSlider_ = new QSlider(Qt::Horizontal, sensitivityGroup);
    heurSlider_->setRange(50, 95);
    heurSlider_->setValue(75);
    connect(heurSlider_, &QSlider::valueChanged, this, [this](int val) {
        heurLabel_->setText(QString::number(val) + "%");
    });
    sensLayout->addWidget(heurSlider_);

    // Zip-Bomb Threshold
    auto* zipHeader = new QHBoxLayout();
    zipHeader->addWidget(new QLabel("Zip-Bomb Max Compression Ratio:", sensitivityGroup));
    zipRatioLabel_ = new QLabel("10.0x", sensitivityGroup);
    zipRatioLabel_->setStyleSheet("font-weight: bold; color: #d29922;");
    zipHeader->addStretch();
    zipHeader->addWidget(zipRatioLabel_);
    sensLayout->addLayout(zipHeader);

    zipRatioSlider_ = new QSlider(Qt::Horizontal, sensitivityGroup);
    zipRatioSlider_->setRange(5, 50);
    zipRatioSlider_->setValue(10);
    connect(zipRatioSlider_, &QSlider::valueChanged, this, [this](int val) {
        zipRatioLabel_->setText(QString::number(val) + ".0x");
    });
    sensLayout->addWidget(zipRatioSlider_);

    mainLayout->addWidget(sensitivityGroup);

    // 3. Exclusions Group
    auto* exclGroup = new QGroupBox("Scan Exclusions (Whitelisted Folders)", this);
    auto* exclLayout = new QVBoxLayout(exclGroup);

    exclusionsList_ = new QListWidget(exclGroup);
    exclLayout->addWidget(exclusionsList_);

    auto* exclBtns = new QHBoxLayout();
    auto* addExclBtn = new QPushButton("Add Folder...", exclGroup);
    connect(addExclBtn, &QPushButton::clicked, this, &SettingsDialog::OnAddExclusion);

    auto* remExclBtn = new QPushButton("Remove Selected", exclGroup);
    connect(remExclBtn, &QPushButton::clicked, this, &SettingsDialog::OnRemoveExclusion);

    exclBtns->addWidget(addExclBtn);
    exclBtns->addWidget(remExclBtn);
    exclBtns->addStretch();
    exclLayout->addLayout(exclBtns);

    mainLayout->addWidget(exclGroup);

    // 4. Update Server Group
    auto* updateGroup = new QGroupBox("Signature Distribution Channel", this);
    auto* updateLayout = new QVBoxLayout(updateGroup);

    auto* urlRow = new QHBoxLayout();
    urlRow->addWidget(new QLabel("Update Feed:", updateGroup));
    updateUrlEdit_ = new QLineEdit(updateGroup);
    urlRow->addWidget(updateUrlEdit_, 1);

    auto* checkBtn = new QPushButton("Check Now", updateGroup);
    connect(checkBtn, &QPushButton::clicked, this, &SettingsDialog::OnCheckUpdatesClicked);
    urlRow->addWidget(checkBtn);

    updateLayout->addLayout(urlRow);

    updateStatusLabel_ = new QLabel("Signatures up-to-date", updateGroup);
    updateStatusLabel_->setStyleSheet("color: #64748b; font-size: 11px;");
    updateLayout->addWidget(updateStatusLabel_);

    mainLayout->addWidget(updateGroup);

    // Bottom Action Buttons
    auto* bottomBar = new QHBoxLayout();
    bottomBar->addStretch();

    auto* saveBtn = new QPushButton("Apply Changes", this);
    saveBtn->setObjectName("btnPrimary");
    connect(saveBtn, &QPushButton::clicked, this, &SettingsDialog::OnSaveClicked);

    auto* cancelBtn = new QPushButton("Cancel", this);
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);

    bottomBar->addWidget(saveBtn);
    bottomBar->addWidget(cancelBtn);
    mainLayout->addLayout(bottomBar);
}

void SettingsDialog::LoadSettings() {
    currentConfig_ = GrpcClient::Instance().GetConfig();

    rtpCheck_->setChecked(currentConfig_.rtpEnabled);
    antiTamperCheck_->setChecked(currentConfig_.antiTamperEnabled);

    int heurVal = static_cast<int>(currentConfig_.heuristicThreshold * 100);
    heurSlider_->setValue(heurVal);
    heurLabel_->setText(QString::number(heurVal) + "%");

    int zipVal = static_cast<int>(currentConfig_.zipBombRatioLimit);
    zipRatioSlider_->setValue(zipVal);
    zipRatioLabel_->setText(QString::number(zipVal) + ".0x");

    exclusionsList_->clear();
    for (const auto& path : currentConfig_.excludedPaths) {
        exclusionsList_->addItem(QString::fromStdString(path));
    }

    updateUrlEdit_->setText(QString::fromStdString(currentConfig_.updateServerUrl));
}

void SettingsDialog::OnSaveClicked() {
    // Minor 39: URL validation with QUrl::isValid() and HTTPS/HTTP check
    QString urlStr = updateUrlEdit_->text().trimmed();
    QUrl url(urlStr);
    if (!urlStr.isEmpty() && (!url.isValid() || (url.scheme() != "https" && url.scheme() != "http"))) {
        QMessageBox::warning(this, "Invalid Configuration", "Update Server URL must be a valid HTTP or HTTPS address.");
        return;
    }

    currentConfig_.rtpEnabled = rtpCheck_->isChecked();
    currentConfig_.antiTamperEnabled = antiTamperCheck_->isChecked();
    currentConfig_.heuristicThreshold = static_cast<double>(heurSlider_->value()) / 100.0;
    currentConfig_.zipBombRatioLimit = static_cast<double>(zipRatioSlider_->value());
    currentConfig_.updateServerUrl = urlStr.toStdString();

    currentConfig_.excludedPaths.clear();
    for (int i = 0; i < exclusionsList_->count(); ++i) {
        currentConfig_.excludedPaths.push_back(exclusionsList_->item(i)->text().toStdString());
    }

    bool ok = GrpcClient::Instance().UpdateConfig(currentConfig_);
    if (ok) {
        accept();
    } else {
        QMessageBox::warning(this, "Save Warning", "Settings applied locally, but service is currently offline.");
        accept();
    }
}

void SettingsDialog::OnAddExclusion() {
    QString dir = QFileDialog::getExistingDirectory(this, "Select Directory to Exclude from Protection");
    if (!dir.isEmpty()) {
        exclusionsList_->addItem(dir);
    }
}

void SettingsDialog::OnRemoveExclusion() {
    int row = exclusionsList_->currentRow();
    if (row >= 0) {
        delete exclusionsList_->takeItem(row);
    }
}

void SettingsDialog::OnCheckUpdatesClicked() {
    QString urlStr = updateUrlEdit_->text().trimmed();
    QUrl url(urlStr);
    if (!url.isValid() || (url.scheme() != "https" && url.scheme() != "http")) {
        updateStatusLabel_->setText("Error: Enter a valid HTTP/HTTPS update URL.");
        updateStatusLabel_->setStyleSheet("color: #ef4444; font-size: 11px;");
        return;
    }

    updateStatusLabel_->setText("Checking remote distribution endpoint...");
    updateStatusLabel_->setStyleSheet("color: #38bdf8; font-size: 11px;");

    // Minor 33: Wire into SignatureUpdater actual pull
    auto res = backend::SignatureUpdater::Instance().CheckAndUpdate(urlStr.toStdString());
    if (res.success) {
        updateStatusLabel_->setText(QString("Update complete: +%1 new threat signatures incorporated. Total: %2")
                                        .arg(res.signaturesAdded).arg(res.totalSignatures));
        updateStatusLabel_->setStyleSheet("color: #10b981; font-size: 11px;");
    } else {
        updateStatusLabel_->setText(QString("Update notice: %1").arg(QString::fromStdString(res.errorMessage)));
        updateStatusLabel_->setStyleSheet("color: #f59e0b; font-size: 11px;");
    }
}

} // namespace ui
} // namespace vantor
