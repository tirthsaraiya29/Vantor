#include "VantorBackend.h"
#include "recursive.h"
#include <windows.h>

// Ensure the signature includes 'const std::string& sid'
void scan_quick(SafeDB& safe_db, const MLInference& ml, ScanHistoryDB& history_db, const std::string& sid) {
    prepare_logs_dir();
    int files = 0, threats = 0;
    int session_id = create_scan_session(history_db, "quick", sid);

    char* userprofile = nullptr;
    size_t len = 0;
    if (_dupenv_s(&userprofile, &len, "USERPROFILE") == 0 && userprofile) {
        // Define 'base' here to fix 'undefined' error
        std::string base(userprofile);

        // Pass 'sid' as the 6th argument
        scan_recursive(base + "\\Downloads", safe_db, ml, history_db, session_id, sid, files, threats);
        scan_recursive(base + "\\Desktop", safe_db, ml, history_db, session_id, sid, files, threats);
        scan_recursive(base + "\\Documents", safe_db, ml, history_db, session_id, sid, files, threats);

        free(userprofile);
    }
    log_scan_summary(history_db, session_id, files, threats);
    finalize_logs();
}