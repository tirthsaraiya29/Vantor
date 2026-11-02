#include "VantorBackend.h"
#include "recursive.h"
#include <windows.h>

// Ensure the signature includes 'const std::string& sid'
void scan_full(SafeDB& safe_db, const MLInference& ml, ScanHistoryDB& history_db, const std::string& sid) {
    prepare_logs_dir();
    int files = 0;   // Matches 'files' error
    int threats = 0; // Matches 'threats' error
    int session_id = create_scan_session(history_db, "full", sid);

    DWORD drive_mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (drive_mask & (1 << i)) {
            char drive_letter = 'A' + i;
            // Define root_path here to fix 'undefined' error
            std::string root_path = std::string(1, drive_letter) + ":\\";

            UINT drive_type = GetDriveTypeA(root_path.c_str());
            if (drive_type == DRIVE_REMOVABLE || drive_type == DRIVE_FIXED || drive_type == DRIVE_REMOTE) {
                // Now 'root_path', 'sid', 'files', and 'threats' are all defined
                scan_recursive(root_path, safe_db, ml, history_db, session_id, sid, files, threats);
            }
        }
    }
    log_scan_summary(history_db, session_id, files, threats);
    finalize_logs();
}