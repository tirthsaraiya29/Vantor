#pragma once

#include "../common/Common.h"
#include <string>
#include <vector>

namespace vantor {
namespace audit {

struct MemoryAnomaly {
    DWORD pid{0};
    std::string processName;
    std::string processPath;
    std::string baseAddress;
    uint64_t regionSize{0};
    std::string protection;
    std::string anomalyType;
    std::string description;
    std::string severity;
};

struct MemoryAuditReport {
    bool success{false};
    std::string timestamp;
    uint32_t processesScanned{0};
    uint32_t processesSuspect{0};
    uint64_t totalRegionsAudited{0};
    uint32_t suspectAllocationsCount{0};
    std::vector<MemoryAnomaly> anomalies;
    std::string summary;
};

class ProcessMemoryAuditor {
public:
    static ProcessMemoryAuditor& Instance() {
        static ProcessMemoryAuditor instance;
        return instance;
    }

    MemoryAuditReport AuditRunningProcesses();
    std::string AuditRunningProcessesJson();

    static bool AuditProcessHandle(HANDLE hProc, DWORD pid, const std::string& name, const std::string& path,
                                   std::vector<MemoryAnomaly>& anomalies, uint64_t& regionsAudited);

private:
    ProcessMemoryAuditor() = default;
    ~ProcessMemoryAuditor() = default;
};

} // namespace audit
} // namespace vantor
