#pragma once

#include <string>
#include <vector>

namespace vantor {
namespace backend {

struct ScheduledScanConfig {
    std::string taskName = "VantorScheduledScan";
    std::string scanType = "quick"; // quick or full
    int hour = 2;                    // 0-23
    int minute = 0;                  // 0-59
    std::vector<int> daysOfWeek;     // 1=Mon, 2=Tue, ..., 7=Sun (empty for daily)
    bool enabled = true;
};

class ScheduledScanService {
public:
    static ScheduledScanService& Instance() {
        static ScheduledScanService instance;
        return instance;
    }

    ScheduledScanService() = default;
    ~ScheduledScanService() = default;

    bool RegisterTask(const ScheduledScanConfig& config, std::string& outError);
    bool DeleteTask(const std::string& taskName, std::string& outError);
    bool GetNextRunTime(const std::string& taskName, std::string& outNextRunIso, std::string& outError);
    bool IsTaskRegistered(const std::string& taskName);
};

} // namespace backend
} // namespace vantor
