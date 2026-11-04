#include "ScanHistoryStore.h"
#include "../common/Logger.h"
#include "../common/sqlite3.h"
#include "../common/nlohmann/json.hpp"
#include <filesystem>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace vantor {
namespace scan {

ScanHistoryStore::ScanHistoryStore() = default;

ScanHistoryStore::~ScanHistoryStore() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool ScanHistoryStore::Initialize(const std::string& baseDir) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_ && db_) return true;

    std::string dir = baseDir.empty() ? Utf16ToUtf8(GetExecutableDirectory()) : baseDir;
    dbPath_ = dir + "/scan_history.db";

    std::error_code ec;
    fs::create_directories(fs::path(dbPath_).parent_path(), ec);

    if (sqlite3_open(dbPath_.c_str(), &db_) != SQLITE_OK) {
        LOG_ERROR("ScanHistoryStore", "Failed to open scan history SQLite database: " + dbPath_);
        return false;
    }

    // Set WAL mode for concurrency
    sqlite3_exec(db_, "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;", nullptr, nullptr, nullptr);

    const char* schema =
        "CREATE TABLE IF NOT EXISTS scan_sessions ("
        "session_id TEXT PRIMARY KEY, "
        "scan_type TEXT, "
        "start_time TEXT, "
        "end_time TEXT, "
        "files_scanned INTEGER, "
        "threats_found INTEGER, "
        "quarantined_count INTEGER, "
        "status TEXT);"
        "CREATE TABLE IF NOT EXISTS scan_threats ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "session_id TEXT, "
        "file_path TEXT, "
        "threat_name TEXT, "
        "verdict TEXT, "
        "action_taken TEXT, "
        "sha256 TEXT, "
        "timestamp TEXT);";

    char* errMsg = nullptr;
    if (sqlite3_exec(db_, schema, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        LOG_ERROR("ScanHistoryStore", "Schema creation error: " + std::string(errMsg ? errMsg : ""));
        if (errMsg) sqlite3_free(errMsg);
        return false;
    }

    initialized_ = true;
    LOG_INFO("ScanHistoryStore", "Scan history database active: " + dbPath_);
    return true;
}

void ScanHistoryStore::RecordSessionStart(const std::string& sessionId, const std::string& scanType) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return;

    const char* sql = "INSERT OR REPLACE INTO scan_sessions "
                      "(session_id, scan_type, start_time, end_time, files_scanned, threats_found, quarantined_count, status) "
                      "VALUES (?, ?, ?, '', 0, 0, 0, 'RUNNING');";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        std::string ts = NowUtcIso8601();
        sqlite3_bind_text(stmt, 1, sessionId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, scanType.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, ts.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

void ScanHistoryStore::RecordThreat(const std::string& sessionId, const std::string& filePath,
                                   const std::string& threatName, const std::string& verdict,
                                   const std::string& actionTaken, const std::string& sha256) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return;

    const char* sql = "INSERT INTO scan_threats "
                      "(session_id, file_path, threat_name, verdict, action_taken, sha256, timestamp) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        std::string ts = NowUtcIso8601();
        sqlite3_bind_text(stmt, 1, sessionId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, filePath.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, threatName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, verdict.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, actionTaken.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, sha256.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, ts.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

void ScanHistoryStore::RecordSessionEnd(const std::string& sessionId, int filesScanned,
                                       int threatsFound, int quarantinedCount, const std::string& status) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return;

    const char* sql = "UPDATE scan_sessions SET end_time = ?, files_scanned = ?, threats_found = ?, "
                      "quarantined_count = ?, status = ? WHERE session_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        std::string ts = NowUtcIso8601();
        sqlite3_bind_text(stmt, 1, ts.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, filesScanned);
        sqlite3_bind_int(stmt, 3, threatsFound);
        sqlite3_bind_int(stmt, 4, quarantinedCount);
        sqlite3_bind_text(stmt, 5, status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, sessionId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

std::string ScanHistoryStore::GetRecentSessionsJson(int limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    json result = json::array();
    if (!db_) return result.dump();

    const char* sql = "SELECT session_id, scan_type, start_time, end_time, files_scanned, threats_found, "
                      "quarantined_count, status FROM scan_sessions ORDER BY rowid DESC LIMIT ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, limit);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json item;
            item["session_id"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            item["scan_type"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            item["start_time"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            item["end_time"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            item["files_scanned"] = sqlite3_column_int(stmt, 4);
            item["threats_found"] = sqlite3_column_int(stmt, 5);
            item["quarantined_count"] = sqlite3_column_int(stmt, 6);
            item["status"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            result.push_back(item);
        }
        sqlite3_finalize(stmt);
    }
    return result.dump();
}

std::string ScanHistoryStore::GetSessionThreatsJson(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    json result = json::array();
    if (!db_) return result.dump();

    const char* sql = "SELECT id, file_path, threat_name, verdict, action_taken, sha256, timestamp "
                      "FROM scan_threats WHERE session_id = ? ORDER BY id ASC;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, sessionId.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json item;
            item["id"] = sqlite3_column_int64(stmt, 0);
            item["file_path"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            item["threat_name"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            item["verdict"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            item["action_taken"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            item["sha256"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            item["timestamp"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            result.push_back(item);
        }
        sqlite3_finalize(stmt);
    }
    return result.dump();
}

} // namespace scan
} // namespace vantor
