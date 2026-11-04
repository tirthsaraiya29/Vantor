#pragma once

#include <QDialog>
#include <QTableWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <vector>
#include "../common/Common.h"

namespace vantor {
namespace ui {

class QuarantineDialog : public QDialog {
    Q_OBJECT

public:
    explicit QuarantineDialog(QWidget* parent = nullptr);
    ~QuarantineDialog() override = default;

public slots:
    void LoadQuarantineData();

private slots:
    void OnFilterChanged(const QString& text);
    void OnRestoreClicked();
    void OnDeleteClicked();
    void OnDeleteAllClicked();
    void OnExportCsvClicked();
    void OnLookupVirusTotal();
    void OnCustomContextMenuRequested(const QPoint& pos);

private:
    void SetupUi();
    void PopulateTable(const std::vector<QuarantineEntry>& entries);

    QTableWidget* table_ = nullptr;
    QLineEdit* searchEdit_ = nullptr;
    QPushButton* restoreBtn_ = nullptr;
    QPushButton* deleteBtn_ = nullptr;
    QPushButton* deleteAllBtn_ = nullptr;
    QPushButton* exportCsvBtn_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QLabel* emptyLabel_ = nullptr;

    std::vector<QuarantineEntry> currentEntries_;
};

} // namespace ui
} // namespace vantor
