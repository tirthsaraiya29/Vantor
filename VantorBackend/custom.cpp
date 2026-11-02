#include "mlinference.h"
#include "VantorBackend.h"
#include <filesystem>

namespace fs = std::filesystem;

void scan_custom(const std::string& path, SafeDB& safe_db, const MLInference& ml, ScanHistoryDB& history_db, const std::string& sid) {
    int files_scanned = 0;
    int threats_found = 0;
    if (!fs::exists(path)) return;

    // Use the 3-argument version of create_scan_session
    int session_id = create_scan_session(history_db, "custom", sid);

    // Provide all 8 required arguments to scan_recursive
    scan_recursive(path, safe_db, ml, history_db, session_id, sid, files_scanned, threats_found);

    log_scan_summary(history_db, session_id, files_scanned, threats_found);
}
