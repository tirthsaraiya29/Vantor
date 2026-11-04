#pragma once

#include "../common/Common.h"
#include <string>
#include <vector>
#include <mutex>

struct sqlite3;

namespace vantor {
namespace scan {

struct ScanSessionRecord {
    std::string sessionId;
    std::string scanType;
    std::string startTime;
    std::string endTime;
    int filesScanned = 0;
    int threatsFound = 0;
    int quarantinedCount = 0;
    std::string status;
};

struct ScanThreatRecord {
    int64_t id = 0;
    std::string sessionId;
    std::string filePath;
    std::string threatName;
    std::string verdict;
    std::string actionTaken;
    std::string sha256;
    std::string timestamp;
};

class ScanHistoryStore {
public:
    static ScanHistoryStore& Instance() {
        static ScanHistoryStore instance;
        return instance;
    }

    bool Initialize(const std::string& baseDir = "");

    void RecordSessionStart(const std::string& sessionId, const std::string& scanType);
    void RecordThreat(const std::string& sessionId, const std::string& filePath,
                      const std::string& threatName, const std::string& verdict,
                      const std::string& actionTaken, const std::string& sha256);
    void RecordSessionEnd(const std::string& sessionId, int filesScanned,
                          int threatsFound, int quarantinedCount, const std::string& status = "COMPLETED");

    std::string GetRecentSessionsJson(int limit = 50);
    std::string GetSessionThreatsJson(const std::string& sessionId);

private:
    ScanHistoryStore();
    ~ScanHistoryStore();

    mutable std::mutex mutex_;
    sqlite3* db_{nullptr};
    std::string dbPath_;
    bool initialized_{false};
};

} // namespace scan
} // namespace vantor
