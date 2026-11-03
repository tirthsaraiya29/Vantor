#pragma once

#include <QDialog>
#include <QCheckBox>
#include <QSlider>
#include <QListWidget>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include "../common/Common.h"

namespace vantor {
namespace ui {

class SettingsDialog : public QDialog {
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget* parent = nullptr);
    ~SettingsDialog() override = default;

private slots:
    void OnSaveClicked();
    void OnAddExclusion();
    void OnRemoveExclusion();
    void OnCheckUpdatesClicked();

private:
    void SetupUi();
    void LoadSettings();

    QCheckBox* rtpCheck_ = nullptr;
    QCheckBox* antiTamperCheck_ = nullptr;
    QSlider* heurSlider_ = nullptr;
    QLabel* heurLabel_ = nullptr;
    QSlider* zipRatioSlider_ = nullptr;
    QLabel* zipRatioLabel_ = nullptr;

    QListWidget* exclusionsList_ = nullptr;
    QLineEdit* updateUrlEdit_ = nullptr;
    QLabel* updateStatusLabel_ = nullptr;

    EngineConfig currentConfig_;
};

} // namespace ui
} // namespace vantor
