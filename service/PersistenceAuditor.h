#pragma once

#include "../common/Common.h"
#include <string>
#include <vector>

namespace vantor {
namespace audit {

struct PersistenceEntry {
    std::string location;      // e.g. "HKCU\\Run", "HKLM\\Run", "Startup"
    std::string name;          // Registry value name or shortcut name
    std::string rawCommand;    // Raw command line
    std::string targetPath;    // Resolved binary path
    bool fileExists{false};
    bool isSigned{false};
    double entropy{0.0};
    bool signatureHit{false};
    std::string verdict;       // "SAFE", "SUSPICIOUS", "MALICIOUS"
    std::string threatDescription;
};

struct PersistenceReport {
    bool success{false};
    std::string timestamp;
    uint32_t totalAudited{0};
    uint32_t unsignedCount{0};
    uint32_t suspiciousCount{0};
    uint32_t maliciousCount{0};
    std::vector<PersistenceEntry> entries;
    std::string summary;
};

class PersistenceAuditor {
public:
    static PersistenceAuditor& Instance() {
        static PersistenceAuditor instance;
        return instance;
    }

    PersistenceReport AuditPersistence();
    std::string AuditPersistenceJson();

    static std::string ExtractExecutablePath(const std::string& commandLine);

private:
    PersistenceAuditor() = default;
    ~PersistenceAuditor() = default;

    void AuditRegistryKey(HKEY rootKey, const std::wstring& subKey, const std::string& locationName,
                          std::vector<PersistenceEntry>& entries);
    void AuditStartupDirectory(int csidl, const std::string& locationName,
                               std::vector<PersistenceEntry>& entries);
    void InspectTargetFile(PersistenceEntry& entry);
};

} // namespace audit
} // namespace vantor
