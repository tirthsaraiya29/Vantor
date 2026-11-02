#define _CRT_SECURE_NO_WARNINGS
#include "VantorBackend.h"
#include "quarantine.h"
#include "mlinference.h"
#include "VantorBackend.h"
#include "logging.h"
#include <Windows.h>
#include <filesystem>
#include <vector>
#include <string>

namespace fs = std::filesystem;

void scan_drive(const std::string& drive_letter, SafeDB& safe, MLInference& ml, ScanHistoryDB& history_db, const std::string& sid) {
    if (!fs::exists(drive_letter)) return;
    int files_scanned = 0;
    int threats_found = 0;

    int session_id = create_scan_session(history_db, "drive", sid);

    for (auto& entry : fs::recursive_directory_iterator(drive_letter, fs::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            // Pass the sid to scan_file
            ScanResult res = scan_file(entry.path().string(), safe, ml, history_db, session_id, sid);
            files_scanned++;
            if (res.is_malicious) threats_found++;
        }
    }
    log_scan_summary(history_db, session_id, files_scanned, threats_found);
}