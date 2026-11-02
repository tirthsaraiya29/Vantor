#include "feature_extractor.h"
#include "heuristic.h"
#include "quarantine.h"
#include "signatures.h"
#include "VantorBackend.h"
#include "mlinference.h"
#include "recursive.h"
#include <fstream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <mutex>
#include <Windows.h>
#include <thread>

using ordered_json = nlohmann::ordered_json;
namespace fs = std::filesystem;

/* =========================    Global JSONL Logger    ========================= */
static std::mutex g_log_mutex;

// Helper to handle zip extraction and folder setup at the start of a scan
void prepare_logs_dir() {
    std::string zip_path = "logs.zip";
    if (fs::exists(zip_path)) {
        // System command to extract (Windows built-in powershell)
        system("powershell -Command \"Expand-Archive -Path 'logs.zip' -DestinationPath '.' -Force\"");
        fs::remove(zip_path);
    }
    fs::create_directories("logs/fs");
    fs::create_directories("logs/qs");
    fs::create_directories("logs/cs");
}

// Helper to compress and clean up after scan
void finalize_logs() {
    if (fs::exists("logs")) {
        // System command to max compress (Optimal level)
        system("powershell -Command \"Compress-Archive -Path 'logs' -DestinationPath 'logs.zip' -CompressionLevel 'Optimal'\"");
        fs::remove_all("logs");
    }
}

// Main implementation (JSON Overload): Handles all folder logic and file writing
void log_event_json(const nlohmann::json& obj) {
    std::lock_guard<std::mutex> lock(g_log_mutex);

    // 1. Resolve SID and determine subfolder (fs, qs, or cs)
    std::string sid = obj.value("SID", "SYS-0000");
    std::string subfolder = "cs"; // default
    if (sid.find("FS-") == 0) subfolder = "fs";
    else if (sid.find("QS-") == 0) subfolder = "qs";

    // 2. Ensure physical directory structure exists
    std::string dir_path = "logs/" + subfolder;
    std::error_code ec;
    fs::create_directories(dir_path, ec);

    // 3. Construct unique file path: logs/{subfolder}/logs_{SID}.jsonl
    std::string file_path = dir_path + "/logs_" + sid + ".jsonl";

    std::ofstream ofs(file_path, std::ios::app);
    if (!ofs) return;

    // 4. Handle auto-timestamping if not provided
    nlohmann::ordered_json final_log = obj;
    if (!final_log.contains("timestamp")) {
        auto tp = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(tp);
        std::tm tm{};
        gmtime_s(&tm, &t);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
        final_log["timestamp"] = oss.str();
    }

    // 5. Final Write to disk
    ofs << final_log.dump() << '\n';
}

// Compatibility Wrapper (String Overload): Delegates to the JSON version
void log_event_json(const std::string& sid, const std::string& timestamp, const std::string& path, const std::string& verdict) {
    nlohmann::json log_obj;
    log_obj["SID"] = sid;
    log_obj["timestamp"] = timestamp;
    log_obj["file path"] = path;
    log_obj["verdict"] = verdict;

    // Send to the central logic
    log_event_json(log_obj);
}

/* =========================    Helpers    ========================= */
static std::string now_utc() {
    auto tp = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    gmtime_s(&tm, &t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

bool compute_hashes(const std::string& path, std::string& sha256_out, std::string& sha512_out) {
    auto digest = [](const std::string& p, const EVP_MD* md) -> std::string {
        std::ifstream f(p, std::ios::binary);
        if (!f) return "";
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, md, nullptr);
        auto buf = std::make_unique<char[]>(16384);
        while (f.read(buf.get(), 16384) || f.gcount() > 0) {
            EVP_DigestUpdate(ctx, buf.get(), static_cast<size_t>(f.gcount()));
        }
        unsigned char res[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        EVP_DigestFinal_ex(ctx, res, &len);
        EVP_MD_CTX_free(ctx);
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < len; i++) ss << std::setw(2) << (int)res[i];
        return ss.str();
        };
    sha256_out = digest(path, EVP_sha256());
    sha512_out = digest(path, EVP_sha512());
    return !sha256_out.empty();
}

/* =========================    Safe DB    ========================= */
bool safe_db_init(SafeDB& safe_db, const std::string& path) {
    if (sqlite3_open(path.c_str(), &safe_db.db) != SQLITE_OK) return false;
    const char* sql = "CREATE TABLE IF NOT EXISTS safe_files (sha512 TEXT PRIMARY KEY);";
    return sqlite3_exec(safe_db.db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool safe_db_contains(SafeDB& safe_db, const std::string& sha512) {
    sqlite3_stmt* stmt;
    const char* sql = "SELECT 1 FROM safe_files WHERE sha512=? LIMIT 1;";
    if (sqlite3_prepare_v2(safe_db.db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, sha512.c_str(), -1, SQLITE_STATIC);
    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

void safe_db_mark(SafeDB& safe_db, const std::string& sha512) {
    sqlite3_stmt* stmt;
    const char* sql = "INSERT OR IGNORE INTO safe_files VALUES (?);";
    sqlite3_prepare_v2(safe_db.db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, sha512.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

/* =========================    Scan History    ========================= */
bool init_scan_history(ScanHistoryDB& db, const std::string& path) {
    if (sqlite3_open(path.c_str(), &db.db) != SQLITE_OK) return false;
    const char* sql =
        "CREATE TABLE IF NOT EXISTS scan_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, sid_string TEXT, type TEXT, timestamp TEXT);"
        "CREATE TABLE IF NOT EXISTS scan_files (session_id INTEGER, path TEXT, verdict TEXT, ml REAL, heur REAL);";
    return sqlite3_exec(db.db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

int create_scan_session(ScanHistoryDB& db, const std::string& scan_type, const std::string& sid_string) {
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO scan_sessions(sid_string, type, timestamp) VALUES(?,?,?);";
    sqlite3_prepare_v2(db.db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, sid_string.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, scan_type.c_str(), -1, SQLITE_STATIC);
    std::string ts = now_utc();
    sqlite3_bind_text(stmt, 3, ts.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (int)sqlite3_last_insert_rowid(db.db);
}

void log_file_scan(ScanHistoryDB& db, int session_id, const ScanResult& r) {
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO scan_files VALUES (?,?,?,?,?);";
    sqlite3_prepare_v2(db.db, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, session_id);
    sqlite3_bind_text(stmt, 2, r.file_path.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, r.verdict.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_double(stmt, 4, r.ml_score);
    sqlite3_bind_double(stmt, 5, r.heuristic_score);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void log_scan_summary(ScanHistoryDB& db, int session_id, int total_files, int threats) {
    sqlite3_stmt* stmt;
    const char* sql = "UPDATE scan_sessions SET timestamp = timestamp || ' | Scanned: ' || ? || ' | Threats: ' || ? WHERE id = ?;";
    if (sqlite3_prepare_v2(db.db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, total_files);
        sqlite3_bind_int(stmt, 2, threats);
        sqlite3_bind_int(stmt, 3, session_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

/* =========================    Scan Engine    ========================= */
ScanResult scan_file(const std::string& path, SafeDB& safe_db, const MLInference& ml, ScanHistoryDB& history_db, int session_id, const std::string& sid_string) {
    ScanResult r;
    r.file_path = path;
    std::string ts = now_utc();

    if (!compute_hashes(path, r.sha256, r.sha512)) {
        r.verdict = "error";
        log_event_json(sid_string, ts, path, r.verdict);
        return r;
    }

    if (safe_db_contains(safe_db, r.sha512)) {
        r.verdict = "safe";
        log_event_json(sid_string, ts, path, r.verdict);
        return r;
    }

    r.signature_hit = signature_hit(r.sha256);
    r.ml_score = ml.predict(extract_features(path));
    r.heuristic_score = run_heuristic_scan(path);

    r.final_score = (std::max)(r.ml_score, r.heuristic_score);

    if (r.signature_hit || r.final_score >= 0.8) {
        r.is_malicious = true;
        r.verdict = "malicious";
        handle_malicious_file(path, sid_string, r.sha256, r.sha512);
    }
    else if (r.final_score >= 0.65) {
        r.is_malicious = false;
        r.verdict = "suspicious";
    }
    else {
        r.is_malicious = false;
        r.verdict = "clean";
        safe_db_mark(safe_db, r.sha512);
    }

    log_file_scan(history_db, session_id, r);
    log_event_json(sid_string, ts, path, r.verdict);
    return r;
}

/* =========================    Compatibility Overloads    ========================= */
int create_scan_session(ScanHistoryDB& db, const std::string& scan_type) {
    std::string prefix = (scan_type == "full") ? "FS-" : (scan_type == "quick") ? "QS-" : "CS-";
    return create_scan_session(db, scan_type, prefix + std::to_string(1000 + (rand() % 9000)));
}

ScanResult scan_file(const std::string& path, SafeDB& safe_db, const MLInference& ml, ScanHistoryDB& history_db, int session_id) {
    return scan_file(path, safe_db, ml, history_db, session_id, "UNK-0000");
}