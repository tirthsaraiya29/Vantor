#include "VantorBackend.h"
#include "mlinference.h"
#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <windows.h> // Required for Sleep

// ================== AV SCAN PROTOTYPES ==================
void scan_full(SafeDB&, const MLInference&, ScanHistoryDB&, const std::string&);
void scan_quick(SafeDB&, const MLInference&, ScanHistoryDB&, const std::string&);
void scan_custom(const std::string&, SafeDB&, const MLInference&, ScanHistoryDB&, const std::string&);
void run_rtp_engine(SafeDB& safe, const MLInference& ml, ScanHistoryDB& history);

// ================== SOT MODULE ENTRY POINTS ==================
void run_disk_cleanup();           // from disk.cpp
void run_startup_optimization();   // from start_man.cpp

int main(int argc, char* argv[]) {
    // 1. Fast-path: Tools that DON'T require Databases or ML
    if (argc >= 2) {
        std::string cmd = argv[1];
        if (cmd == "clean") {
            std::cout << "[SOT] Disk cleanup invoked\n";
            run_disk_cleanup();
            return 0;
        }
        if (cmd == "mon") {
            std::cout << "[SOT] Startup manager invoked\n";
            run_startup_optimization();
            return 0;
        }
    }

    // 2. Initialize Core Engines (Required for Scans and RTP Service)
    SafeDB safe_db;
    ScanHistoryDB history_db;
    MLInference ml;

    srand((unsigned int)time(NULL));

    if (!safe_db_init(safe_db, "safe.db")) {
        std::cerr << "[FATAL] Failed to init SafeDB\n";
        return 1;
    }

    if (!init_scan_history(history_db, "scan_history.db")) {
        std::cerr << "[FATAL] Failed to init scan history DB\n";
        return 1;
    }

    std::vector<std::string> models = {
        "ember.json", "avast.json"
    };

    if (!ml.load_models(models)) {
        std::cerr << "[FATAL] Failed to load ML models\n";
        return 1;
    }

    // 3. Handle Service Mode (Must happen after ML/DB init)
    if (argc >= 2 && std::string(argv[1]) == "service") {
        log_event_json({ {"type", "rtp_start"}, {"status", "active"} });

        run_rtp_engine(safe_db, ml, history_db);

        // Keep the process alive
        while (true) {
            Sleep(1000);
        }
        return 0;
    }

    // 4. Handle Standard On-Demand Scans
    if (argc < 2) {
        std::cout << "Vantor Security Suite\n";
        std::cout << "Usage:\n";
        std::cout << "  vantor full           (Full System Scan)\n";
        std::cout << "  vantor quick          (Quick Scan)\n";
        std::cout << "  vantor custom <path>  (Scan specific folder)\n";
        std::cout << "  vantor service        (Run Real-Time Protection)\n";
        std::cout << "  vantor clean          (Disk Cleanup)\n";
        std::cout << "  vantor mon            (Startup Optimizer)\n";
        return 0;
    }

    log_event_json({
        {"type", "startup"},
        {"ml_models", (int)models.size()}
        });

    std::string mode = argv[1];
    std::string prefix = (mode == "full") ? "FS-" : (mode == "quick") ? "QS-" : "CS-";
    std::string sid = prefix + std::to_string(1000 + (rand() % 9000));

    if (mode == "full") {
        scan_full(safe_db, ml, history_db, sid);
    }
    else if (mode == "quick") {
        scan_quick(safe_db, ml, history_db, sid);
    }
    else if (mode == "custom" && argc >= 3) {
        scan_custom(argv[2], safe_db, ml, history_db, sid);
    }
    else {
        std::cerr << "[ERROR] Invalid arguments or missing path for custom scan\n";
    }

    log_event_json({ {"type", "shutdown"} });
    return 0;
}