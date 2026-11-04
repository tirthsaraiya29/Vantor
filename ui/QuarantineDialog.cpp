#include "QuarantineDialog.h"
#include "GrpcClient.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QFileDialog>
#include <QMenu>
#include <QClipboard>
#include <QGuiApplication>
#include <QDesktopServices>
#include <QUrl>
#include <QFile>
#include <QTextStream>

namespace vantor {
namespace ui {

QuarantineDialog::QuarantineDialog(QWidget* parent)
    : QDialog(parent) {
    setWindowTitle("Vantor - Quarantine Containment Vault");
    resize(920, 540);

    // Minor 32: Dark title bar & dialog styling
    setStyleSheet(
        "QDialog { background-color: #0b0f19; color: #f8fafc; font-family: 'Segoe UI', sans-serif; }"
        "QTableWidget { background-color: #0f172a; border: 1px solid #1e293b; gridline-color: #1e293b; color: #f8fafc; }"
        "QHeaderView::section { background-color: #1e293b; color: #94a3b8; font-weight: 700; padding: 6px; border: none; }"
        "QLineEdit { background-color: #1e293b; color: #f8fafc; border: 1px solid #334155; border-radius: 4px; padding: 6px 12px; }"
        "QPushButton { background-color: #1e293b; color: #f8fafc; border: 1px solid #334155; border-radius: 4px; padding: 6px 14px; font-weight: 600; }"
        "QPushButton:hover { background-color: #334155; }"
        "QPushButton#btnPrimary { background-color: #0284c7; border: none; }"
        "QPushButton#btnPrimary:hover { background-color: #0369a1; }"
        "QPushButton#btnDanger { background-color: #dc2626; border: none; }"
        "QPushButton#btnDanger:hover { background-color: #b91c1c; }"
    );

    SetupUi();
    LoadQuarantineData();
}

void QuarantineDialog::SetupUi() {
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(15);

    // Top Bar: Search & Actions
    auto* topBar = new QHBoxLayout();
    searchEdit_ = new QLineEdit(this);
    searchEdit_->setPlaceholderText("Search quarantined files, threat names, or SHA-256 digests...");
    connect(searchEdit_, &QLineEdit::textChanged, this, &QuarantineDialog::OnFilterChanged);

    exportCsvBtn_ = new QPushButton("Export CSV", this);
    connect(exportCsvBtn_, &QPushButton::clicked, this, &QuarantineDialog::OnExportCsvClicked);

    auto* refreshBtn = new QPushButton("Refresh", this);
    connect(refreshBtn, &QPushButton::clicked, this, &QuarantineDialog::LoadQuarantineData);

    topBar->addWidget(searchEdit_, 1);
    topBar->addWidget(exportCsvBtn_);
    topBar->addWidget(refreshBtn);
    mainLayout->addLayout(topBar);

    // Table Widget (Major 14: Multi-selection, hash column, context menu)
    table_ = new QTableWidget(this);
    table_->setColumnCount(6);
    table_->setHorizontalHeaderLabels({ "ID", "Threat", "Original Path", "SHA-256", "Size", "Date Quarantined" });
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::ExtendedSelection); // Multi-select support
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->verticalHeader()->setVisible(false);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(table_, &QWidget::customContextMenuRequested, this, &QuarantineDialog::OnCustomContextMenuRequested);

    mainLayout->addWidget(table_, 1);

    // Status Label
    statusLabel_ = new QLabel("0 items in quarantine vault", this);
    statusLabel_->setStyleSheet("color: #64748b; font-size: 12px;");

    // Bottom Action Buttons
    auto* bottomBar = new QHBoxLayout();
    bottomBar->addWidget(statusLabel_);
    bottomBar->addStretch();

    restoreBtn_ = new QPushButton("Restore Selected...", this);
    restoreBtn_->setObjectName("btnPrimary");
    connect(restoreBtn_, &QPushButton::clicked, this, &QuarantineDialog::OnRestoreClicked);

    deleteBtn_ = new QPushButton("Delete Selected", this);
    deleteBtn_->setObjectName("btnDanger");
    connect(deleteBtn_, &QPushButton::clicked, this, &QuarantineDialog::OnDeleteClicked);

    deleteAllBtn_ = new QPushButton("Delete All", this);
    deleteAllBtn_->setObjectName("btnDanger");
    connect(deleteAllBtn_, &QPushButton::clicked, this, &QuarantineDialog::OnDeleteAllClicked);

    auto* closeBtn = new QPushButton("Close", this);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);

    bottomBar->addWidget(restoreBtn_);
    bottomBar->addWidget(deleteBtn_);
    bottomBar->addWidget(deleteAllBtn_);
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

        QString hashStr = QString::fromStdString(e.sha256);
        QString shortHash = (hashStr.length() > 16) ? hashStr.left(8) + "..." + hashStr.right(8) : hashStr;
        auto* hashItem = new QTableWidgetItem(shortHash);
        hashItem->setToolTip(hashStr);
        table_->setItem(row, 3, hashItem);

        double kb = static_cast<double>(e.fileSizeBytes) / 1024.0;
        QString sizeStr = (kb > 1024.0) ? QString::number(kb / 1024.0, 'f', 2) + " MB" : QString::number(kb, 'f', 1) + " KB";
        table_->setItem(row, 4, new QTableWidgetItem(sizeStr));

        table_->setItem(row, 5, new QTableWidgetItem(QString::fromStdString(e.timestamp)));
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
    auto selectedRanges = table_->selectedRanges();
    if (selectedRanges.isEmpty()) {
        QMessageBox::information(this, "Select File", "Please select a quarantined item to restore.");
        return;
    }

    int row = table_->currentRow();
    if (row < 0 || row >= static_cast<int>(currentEntries_.size())) return;

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
    auto selectedItems = table_->selectionModel()->selectedRows();
    if (selectedItems.isEmpty()) {
        QMessageBox::information(this, "Select File", "Please select one or more quarantined items to delete.");
        return;
    }

    auto ret = QMessageBox::question(
        this,
        "Confirm Deletion",
        QString("Permanently delete %1 selected quarantined item(s)?\n\nThis action cannot be undone.")
            .arg(selectedItems.size()),
        QMessageBox::Yes | QMessageBox::No
    );

    if (ret == QMessageBox::Yes) {
        for (const auto& index : selectedItems) {
            int row = index.row();
            if (row >= 0 && row < static_cast<int>(currentEntries_.size())) {
                GrpcClient::Instance().DeleteQuarantine(currentEntries_[row].id);
            }
        }
        LoadQuarantineData();
    }
}

void QuarantineDialog::OnDeleteAllClicked() {
    if (currentEntries_.empty()) return;

    auto ret = QMessageBox::warning(
        this,
        "Confirm Delete All",
        QString("Permanently delete ALL %1 quarantined files?\n\nThis will permanently purge the entire quarantine database.")
            .arg(currentEntries_.size()),
        QMessageBox::Yes | QMessageBox::No
    );

    if (ret == QMessageBox::Yes) {
        for (const auto& item : currentEntries_) {
            GrpcClient::Instance().DeleteQuarantine(item.id);
        }
        LoadQuarantineData();
    }
}

void QuarantineDialog::OnExportCsvClicked() {
    if (currentEntries_.empty()) {
        QMessageBox::information(this, "Export CSV", "No quarantine entries to export.");
        return;
    }

    QString savePath = QFileDialog::getSaveFileName(this, "Export Quarantine Report", "quarantine_report.csv", "CSV Files (*.csv)");
    if (savePath.isEmpty()) return;

    QFile file(savePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Cannot open file for writing.");
        return;
    }

    QTextStream out(&file);
    out << "ID,ThreatName,OriginalPath,SHA256,FileSizeBytes,Timestamp\n";
    for (const auto& e : currentEntries_) {
        out << e.id << ",\""
            << QString::fromStdString(e.threatName) << "\",\""
            << QString::fromStdString(e.originalPath) << "\",\""
            << QString::fromStdString(e.sha256) << "\","
            << e.fileSizeBytes << ",\""
            << QString::fromStdString(e.timestamp) << "\"\n";
    }
    file.close();

    QMessageBox::information(this, "Export Complete", QString("Exported %1 records to CSV.").arg(currentEntries_.size()));
}

void QuarantineDialog::OnCustomContextMenuRequested(const QPoint& pos) {
    QModelIndex index = table_->indexAt(pos);
    if (!index.isValid()) return;

    int row = index.row();
    if (row < 0 || row >= static_cast<int>(currentEntries_.size())) return;

    const auto& entry = currentEntries_[row];
    QMenu menu(this);
    QAction* copyHashAction = menu.addAction("Copy SHA-256 Digest");
    QAction* vtAction = menu.addAction("Lookup Hash on VirusTotal");

    QAction* selected = menu.exec(table_->viewport()->mapToGlobal(pos));
    if (selected == copyHashAction) {
        QGuiApplication::clipboard()->setText(QString::fromStdString(entry.sha256));
    } else if (selected == vtAction) {
        QString url = "https://www.virustotal.com/gui/file/" + QString::fromStdString(entry.sha256);
        QDesktopServices::openUrl(QUrl(url));
    }
}

void QuarantineDialog::OnLookupVirusTotal() {
    int row = table_->currentRow();
    if (row >= 0 && row < static_cast<int>(currentEntries_.size())) {
        QString url = "https://www.virustotal.com/gui/file/" + QString::fromStdString(currentEntries_[row].sha256);
        QDesktopServices::openUrl(QUrl(url));
    }
}

} // namespace ui
} // namespace vantor
