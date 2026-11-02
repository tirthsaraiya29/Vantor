#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <sqlite3.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/* =========================
   Database Contexts
   ========================= */

struct SafeDB {
    sqlite3* db = nullptr;
};

struct ScanHistoryDB {
    sqlite3* db = nullptr;
};

/* =========================
   Core Scan Result Struct
   ========================= */

struct ScanResult {
    std::string file_path;
    std::string sha256;
    std::string sha512;

    bool is_malicious = false;
    bool signature_hit = false;

    double ml_score = 0.0;
    double heuristic_score = 0.0;  // Now reflects weighted points
    double final_score = 0.0;

    std::string verdict;           // "clean", "suspicious", "malicious"
};

// Forward declarations
class MLInference; 
void prepare_logs_dir(); 
void finalize_logs();

/* =========================
   Safe DB Interfaces
   ========================= */

bool safe_db_init(SafeDB& safe_db, const std::string& path);
bool safe_db_contains(SafeDB& safe_db, const std::string& sha512);
void safe_db_mark(SafeDB& safe_db, const std::string& sha512);

/* =========================
   Scan History Interfaces
   ========================= */

bool init_scan_history(ScanHistoryDB& db, const std::string& path);

// FIX: Added sid_string to match implementation
int create_scan_session(ScanHistoryDB& db, const std::string& scan_type, const std::string& sid_string);

void log_file_scan(ScanHistoryDB& db, int session_id, const ScanResult& result);
void log_scan_summary(ScanHistoryDB& db, int session_id, int total_files, int threats);

/* =========================
   Scanning Functions
   ========================= */

   // FIX: Added sid_string to solve C2660/C3861 errors
ScanResult scan_file(
    const std::string& path,
    SafeDB& safe_db,
    const MLInference& ml,
    ScanHistoryDB& history_db,
    int session_id,
    const std::string& sid_string = "UNK-0000"
);

void scan_recursive(
    const std::string& root,
    SafeDB& safe_db,
    const MLInference& ml,
    ScanHistoryDB& history_db,
    int session_id,
    const std::string& sid_string, // <--- MUST BE HERE
    int& files_scanned,
    int& threats_found
);

/* =========================
   Central JSONL Logging
   ========================= */

void log_event_json(const std::string& sid, const std::string& timestamp, const std::string& path, const std::string& verdict);
void log_event_json(const nlohmann::json& obj);

/* =========================
   Compatibility Overloads
   ========================= */
   // These allow older code to still call functions without the SID string
int create_scan_session(ScanHistoryDB& db, const std::string& scan_type);
void scan_custom(const std::string& path, SafeDB& safe_db, const MLInference& ml, ScanHistoryDB& history_db, const std::string& sid);
void scan_recursive(const std::string& root, SafeDB& safe_db, const MLInference& ml, ScanHistoryDB& history_db, int session_id, int& files, int& threats);