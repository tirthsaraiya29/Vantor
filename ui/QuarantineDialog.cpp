#include "QuarantineDialog.h"
#include "GrpcClient.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QFileDialog>

namespace vantor {
namespace ui {

QuarantineDialog::QuarantineDialog(QWidget* parent)
    : QDialog(parent) {
    setWindowTitle("Vantor - Quarantine Containment Vault");
    resize(850, 520);
    SetupUi();
    LoadQuarantineData();
}

void QuarantineDialog::SetupUi() {
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(15);

    // Top Bar: Search & Refresh
    auto* topBar = new QHBoxLayout();
    searchEdit_ = new QLineEdit(this);
    searchEdit_->setPlaceholderText("Search quarantined files or threats...");
    connect(searchEdit_, &QLineEdit::textChanged, this, &QuarantineDialog::OnFilterChanged);

    auto* refreshBtn = new QPushButton("Refresh", this);
    connect(refreshBtn, &QPushButton::clicked, this, &QuarantineDialog::LoadQuarantineData);

    topBar->addWidget(searchEdit_, 1);
    topBar->addWidget(refreshBtn);
    mainLayout->addLayout(topBar);

    // Table Widget
    table_ = new QTableWidget(this);
    table_->setColumnCount(5);
    table_->setHorizontalHeaderLabels({ "ID", "Threat", "Original Path", "Size", "Date Quarantined" });
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->verticalHeader()->setVisible(false);

    mainLayout->addWidget(table_, 1);

    // Status / Empty Label
    statusLabel_ = new QLabel("0 items in quarantine vault", this);
    statusLabel_->setStyleSheet("color: #64748b; font-size: 12px;");

    // Bottom Action Buttons
    auto* bottomBar = new QHBoxLayout();
    bottomBar->addWidget(statusLabel_);
    bottomBar->addStretch();

    restoreBtn_ = new QPushButton("Restore Selected...", this);
    restoreBtn_->setObjectName("btnPrimary");
    connect(restoreBtn_, &QPushButton::clicked, this, &QuarantineDialog::OnRestoreClicked);

    deleteBtn_ = new QPushButton("Delete Permanently", this);
    deleteBtn_->setObjectName("btnDanger");
    connect(deleteBtn_, &QPushButton::clicked, this, &QuarantineDialog::OnDeleteClicked);

    auto* closeBtn = new QPushButton("Close", this);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);

    bottomBar->addWidget(restoreBtn_);
    bottomBar->addWidget(deleteBtn_);
    bottomBar->addWidget(closeBtn);
    mainLayout->addLayout(bottomBar);
}

void QuarantineDialog::LoadQuarantineData() {
    currentEntries_ = GrpcClient::Instance().GetQuarantineList();
    PopulateTable(currentEntries_);
}

void QuarantineDialog::PopulateTable(const std::vector<QuarantineEntry>& entries) {
    table_->setRowCount(static_cast<int>(entries.size()));

    for (int row = 0; row < static_cast<int>(entries.size()); ++row) {
        const auto& e = entries[row];
        table_->setItem(row, 0, new QTableWidgetItem(QString::number(e.id)));
        table_->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(e.threatName)));
        table_->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(e.originalPath)));

        double kb = static_cast<double>(e.fileSizeBytes) / 1024.0;
        QString sizeStr = (kb > 1024.0) ? QString::number(kb / 1024.0, 'f', 2) + " MB" : QString::number(kb, 'f', 1) + " KB";
        table_->setItem(row, 3, new QTableWidgetItem(sizeStr));

        table_->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(e.timestamp)));
    }

    statusLabel_->setText(QString("%1 items in quarantine vault").arg(entries.size()));
}

void QuarantineDialog::OnFilterChanged(const QString& text) {
    if (text.trimmed().isEmpty()) {
        PopulateTable(currentEntries_);
        return;
    }

    std::vector<QuarantineEntry> filtered;
    QString lower = text.toLower();
    for (const auto& e : currentEntries_) {
        if (QString::fromStdString(e.originalPath).toLower().contains(lower) ||
            QString::fromStdString(e.threatName).toLower().contains(lower) ||
            QString::fromStdString(e.sha256).toLower().contains(lower)) {
            filtered.push_back(e);
        }
    }
    PopulateTable(filtered);
}

void QuarantineDialog::OnRestoreClicked() {
    int row = table_->currentRow();
    if (row < 0 || row >= static_cast<int>(currentEntries_.size())) {
        QMessageBox::information(this, "Select File", "Please select a quarantined item to restore.");
        return;
    }

    const auto& item = currentEntries_[row];
    auto ret = QMessageBox::question(
        this,
        "Confirm Restoration",
        QString("Are you sure you want to restore:\n%1\n\nRestoring malware to your filesystem could pose a security risk.")
            .arg(QString::fromStdString(item.originalPath)),
        QMessageBox::Yes | QMessageBox::No
    );

    if (ret == QMessageBox::Yes) {
        QString dest = QFileDialog::getSaveFileName(
            this,
            "Choose Restore Destination",
            QString::fromStdString(item.originalPath)
        );

        if (!dest.isEmpty()) {
            bool ok = GrpcClient::Instance().RestoreQuarantine(item.id, dest.toStdString());
            if (ok) {
                QMessageBox::information(this, "Success", "File restored successfully.");
                LoadQuarantineData();
            } else {
                QMessageBox::critical(this, "Error", "Failed to restore file.");
            }
        }
    }
}

void QuarantineDialog::OnDeleteClicked() {
    int row = table_->currentRow();
    if (row < 0 || row >= static_cast<int>(currentEntries_.size())) {
        QMessageBox::information(this, "Select File", "Please select a quarantined item to delete.");
        return;
    }

    const auto& item = currentEntries_[row];
    auto ret = QMessageBox::question(
        this,
        "Confirm Deletion",
        QString("Permanently delete quarantined threat:\n%1\n\nThis action cannot be undone.")
            .arg(QString::fromStdString(item.originalPath)),
        QMessageBox::Yes | QMessageBox::No
    );

    if (ret == QMessageBox::Yes) {
        bool ok = GrpcClient::Instance().DeleteQuarantine(item.id);
        if (ok) {
            LoadQuarantineData();
        } else {
            QMessageBox::critical(this, "Error", "Failed to delete item.");
        }
    }
}

} // namespace ui
} // namespace vantor
