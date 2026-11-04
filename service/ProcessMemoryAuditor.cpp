#include "ProcessMemoryAuditor.h"
#include "../common/Logger.h"
#include "../common/nlohmann/json.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <sstream>
#include <iomanip>
#include <unordered_set>

#pragma comment(lib, "psapi.lib")

using json = nlohmann::json;

namespace vantor {
namespace audit {

bool ProcessMemoryAuditor::AuditProcessHandle(HANDLE hProc, DWORD pid, const std::string& name, const std::string& path,
                                              std::vector<MemoryAnomaly>& anomalies, uint64_t& regionsAudited) {
    if (!hProc) return false;

    unsigned char* addr = nullptr;
    MEMORY_BASIC_INFORMATION mbi;
    bool foundAnomaly = false;

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        regionsAudited++;

        // Stop at user-mode virtual memory boundary
        if (reinterpret_cast<uintptr_t>(mbi.BaseAddress) >= 0x7FFFFFFEFFFFULL) {
            break;
        }

        if (mbi.State == MEM_COMMIT) {
            wchar_t mappedPath[MAX_PATH] = { 0 };
            DWORD len = GetMappedFileNameW(hProc, mbi.BaseAddress, mappedPath, MAX_PATH);
            bool isUnbacked = (len == 0 || mbi.Type == MEM_PRIVATE);

            if (mbi.Protect == PAGE_EXECUTE_READWRITE && isUnbacked) {
                MemoryAnomaly anomaly;
                anomaly.pid = pid;
                anomaly.processName = name;
                anomaly.processPath = path;

                std::stringstream ss;
                ss << "0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                anomaly.baseAddress = ss.str();

                anomaly.regionSize = static_cast<uint64_t>(mbi.RegionSize);
                anomaly.protection = "PAGE_EXECUTE_READWRITE (RWX)";
                anomaly.anomalyType = "UNBACKED_RWX_PAGE";
                anomaly.description = "Unbacked executable and writable memory region (Reflective Injection / Shellcode risk)";
                anomaly.severity = "HIGH";
                anomalies.push_back(anomaly);
                foundAnomaly = true;
            }
            else if (mbi.Protect == PAGE_EXECUTE_WRITECOPY && isUnbacked) {
                MemoryAnomaly anomaly;
                anomaly.pid = pid;
                anomaly.processName = name;
                anomaly.processPath = path;

                std::stringstream ss;
                ss << "0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                anomaly.baseAddress = ss.str();

                anomaly.regionSize = static_cast<uint64_t>(mbi.RegionSize);
                anomaly.protection = "PAGE_EXECUTE_WRITECOPY (WCX)";
                anomaly.anomalyType = "UNBACKED_EXECUTE_WRITECOPY";
                anomaly.description = "Unbacked execute-write-copy memory region (Process hollowing / hooking risk)";
                anomaly.severity = "MEDIUM";
                anomalies.push_back(anomaly);
                foundAnomaly = true;
            }
            else if (mbi.Protect == PAGE_EXECUTE_READ && mbi.Type == MEM_PRIVATE && len == 0) {
                MemoryAnomaly anomaly;
                anomaly.pid = pid;
                anomaly.processName = name;
                anomaly.processPath = path;

                std::stringstream ss;
                ss << "0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                anomaly.baseAddress = ss.str();

                anomaly.regionSize = static_cast<uint64_t>(mbi.RegionSize);
                anomaly.protection = "PAGE_EXECUTE_READ (RX MEM_PRIVATE)";
                anomaly.anomalyType = "UNBACKED_RX_PRIVATE";
                anomaly.description = "Unbacked private executable memory region (Reflective DLL / stealth loader risk)";
                anomaly.severity = "MEDIUM";
                anomalies.push_back(anomaly);
                foundAnomaly = true;
            }
        }

        addr = static_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize;
        if (addr <= mbi.BaseAddress) {
            break; // Address wrap-around check
        }
    }

    return foundAnomaly;
}

MemoryAuditReport ProcessMemoryAuditor::AuditRunningProcesses() {
    MemoryAuditReport report;
    report.timestamp = NowUtcIso8601();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        report.success = false;
        report.summary = "Failed to snapshot running processes.";
        return report;
    }

    // Whitelist known sensitive system / host processes to eliminate false alerts & privilege denials
    static const std::unordered_set<std::string> systemWhitelist = {
        "smss.exe", "csrss.exe", "services.exe", "lsass.exe", "wininit.exe",
        "svchost.exe", "fontdrvhost.exe", "dwm.exe", "memory compression",
        "vantorservice.exe", "vantor.exe", "vantorbackend.exe"
    };

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    std::unordered_set<DWORD> suspectPids;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4 || pe.th32ProcessID == GetCurrentProcessId()) {
                continue;
            }

            std::string procName = ToLower(Utf16ToUtf8(pe.szExeFile));
            if (systemWhitelist.count(procName) > 0) {
                continue;
            }

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (!hProc) {
                hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            }

            if (hProc) {
                wchar_t procPath[MAX_PATH] = { 0 };
                DWORD size = MAX_PATH;
                std::string fullPath;
                if (QueryFullProcessImageNameW(hProc, 0, procPath, &size)) {
                    fullPath = Utf16ToUtf8(procPath);
                }

                report.processesScanned++;
                bool hasAnomaly = AuditProcessHandle(hProc, pe.th32ProcessID, Utf16ToUtf8(pe.szExeFile),
                                                     fullPath, report.anomalies, report.totalRegionsAudited);
                if (hasAnomaly) {
                    suspectPids.insert(pe.th32ProcessID);
                }
                CloseHandle(hProc);
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);

    report.processesSuspect = static_cast<uint32_t>(suspectPids.size());
    report.suspectAllocationsCount = static_cast<uint32_t>(report.anomalies.size());
    report.success = true;

    if (report.suspectAllocationsCount == 0) {
        report.summary = "Clean: Audited " + std::to_string(report.processesScanned) +
                         " user-mode processes (" + std::to_string(report.totalRegionsAudited) +
                         " memory regions). Zero unbacked RWX injection allocations found.";
    } else {
        report.summary = "ALERT: Detected " + std::to_string(report.suspectAllocationsCount) +
                         " unbacked RWX execution pages across " + std::to_string(report.processesSuspect) +
                         " running processes.";
    }

    return report;
}

std::string ProcessMemoryAuditor::AuditRunningProcessesJson() {
    auto report = AuditRunningProcesses();

    json root;
    root["cmd"] = "audit_memory";
    root["status"] = report.success ? "ok" : "error";
    root["timestamp"] = report.timestamp;
    root["processes_scanned"] = report.processesScanned;
    root["processes_suspect"] = report.processesSuspect;
    root["total_regions_audited"] = report.totalRegionsAudited;
    root["suspect_allocations_count"] = report.suspectAllocationsCount;
    root["summary"] = report.summary;

    json anomalies = json::array();
    for (const auto& a : report.anomalies) {
        json item;
        item["pid"] = a.pid;
        item["process_name"] = a.processName;
        item["process_path"] = a.processPath;
        item["base_address"] = a.baseAddress;
        item["region_size"] = a.regionSize;
        item["protection"] = a.protection;
        item["anomaly_type"] = a.anomalyType;
        item["description"] = a.description;
        item["severity"] = a.severity;
        anomalies.push_back(item);
    }
    root["anomalies"] = anomalies;

    return root.dump();
}

} // namespace audit
} // namespace vantor
