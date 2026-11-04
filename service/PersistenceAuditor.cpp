#include "PersistenceAuditor.h"
#include "Scanner.h"
#include "SignatureStore.h"
#include "../common/Crypto.h"
#include "../common/Logger.h"
#include "../common/AuthenticodeVerifier.h"
#include "../common/nlohmann/json.hpp"

#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <cmath>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace vantor {
namespace audit {

std::string PersistenceAuditor::ExtractExecutablePath(const std::string& commandLine) {
    if (commandLine.empty()) return "";

    std::string trimmed = commandLine;
    // Strip leading whitespace
    while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t')) {
        trimmed.erase(0, 1);
    }

    if (trimmed.empty()) return "";

    // 1. Quoted path: "C:\Program Files\App\app.exe" --param
    if (trimmed.front() == '"') {
        size_t endQuote = trimmed.find('"', 1);
        if (endQuote != std::string::npos) {
            return trimmed.substr(1, endQuote - 1);
        }
    }

    // 2. Unquoted path: find first space that might separate executable from arguments
    // Test whole string first
    std::error_code ec;
    if (fs::exists(trimmed, ec) && fs::is_regular_file(trimmed, ec)) {
        return trimmed;
    }

    // Attempt splitting at spaces from left to right until an existing file is found
    size_t spacePos = trimmed.find(' ');
    while (spacePos != std::string::npos) {
        std::string candidate = trimmed.substr(0, spacePos);
        if (fs::exists(candidate, ec) && fs::is_regular_file(candidate, ec)) {
            return candidate;
        }
        spacePos = trimmed.find(' ', spacePos + 1);
    }

    // Fallback: take first token
    size_t firstSpace = trimmed.find(' ');
    if (firstSpace != std::string::npos) {
        return trimmed.substr(0, firstSpace);
    }

    return trimmed;
}

void PersistenceAuditor::AuditRegistryKey(HKEY rootKey, const std::wstring& subKey, const std::string& locationName,
                                          std::vector<PersistenceEntry>& entries) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(rootKey, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return;
    }

    DWORD index = 0;
    wchar_t valueName[16384];
    BYTE data[16384];

    while (true) {
        DWORD nameSize = sizeof(valueName) / sizeof(wchar_t);
        DWORD dataSize = sizeof(data);
        DWORD type = 0;

        LONG res = RegEnumValueW(hKey, index, valueName, &nameSize, nullptr, &type, data, &dataSize);
        if (res != ERROR_SUCCESS) break;

        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            std::wstring rawStr(reinterpret_cast<wchar_t*>(data), dataSize / sizeof(wchar_t));
            // Strip any null terminators
            while (!rawStr.empty() && rawStr.back() == L'\0') {
                rawStr.pop_back();
            }

            PersistenceEntry entry;
            entry.location = locationName;
            entry.name = Utf16ToUtf8(valueName);
            entry.rawCommand = Utf16ToUtf8(rawStr);
            entry.targetPath = ExtractExecutablePath(entry.rawCommand);

            InspectTargetFile(entry);
            entries.push_back(entry);
        }

        index++;
    }

    RegCloseKey(hKey);
}

void PersistenceAuditor::AuditStartupDirectory(int csidl, const std::string& locationName,
                                               std::vector<PersistenceEntry>& entries) {
    wchar_t startupPath[MAX_PATH];
    if (FAILED(SHGetFolderPathW(nullptr, csidl, nullptr, 0, startupPath))) {
        return;
    }

    std::error_code ec;
    if (!fs::exists(startupPath, ec) || !fs::is_directory(startupPath, ec)) {
        return;
    }

    for (const auto& dirEntry : fs::directory_iterator(startupPath, ec)) {
        if (ec) break;
        if (dirEntry.is_regular_file()) {
            PersistenceEntry entry;
            entry.location = locationName;
            entry.name = dirEntry.path().filename().string();
            entry.rawCommand = dirEntry.path().string();
            entry.targetPath = dirEntry.path().string();

            InspectTargetFile(entry);
            entries.push_back(entry);
        }
    }
}

void PersistenceAuditor::InspectTargetFile(PersistenceEntry& entry) {
    std::error_code ec;
    if (entry.targetPath.empty() || !fs::exists(entry.targetPath, ec) || !fs::is_regular_file(entry.targetPath, ec)) {
        entry.fileExists = false;
        entry.verdict = "SUSPICIOUS";
        entry.threatDescription = "Orphaned persistence pointer (Binary not found on disk)";
        return;
    }

    entry.fileExists = true;

    // 1. Digital Signature Check (using shared Authenticode verifier)
    entry.isSigned = authenticode::VerifyAuthenticodeSignature(Utf8ToUtf16(entry.targetPath));

    // 2. Hash & Signature Lookup
    std::string sha256, sha512;
    if (crypto::ComputeFileHashes(entry.targetPath, sha256, sha512)) {
        if (backend::SignatureStore::Instance().Contains(sha256)) {
            entry.signatureHit = true;
            entry.verdict = "MALICIOUS";
            entry.threatDescription = "Known Malicious Signature in Persistence Vector";
            return;
        }
    }

    // 3. Shannon Entropy Analysis
    std::ifstream f(entry.targetPath, std::ios::binary);
    if (f) {
        std::vector<uint8_t> buffer(64 * 1024);
        f.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        size_t readCount = static_cast<size_t>(f.gcount());
        buffer.resize(readCount);

        if (!buffer.empty()) {
            // Compute Shannon entropy
            size_t freq[256] = { 0 };
            for (uint8_t b : buffer) freq[b]++;

            double entropy = 0.0;
            double len = static_cast<double>(buffer.size());
            for (int i = 0; i < 256; ++i) {
                if (freq[i] > 0) {
                    double p = static_cast<double>(freq[i]) / len;
                    entropy -= p * (std::log(p) / std::log(2.0));
                }
            }
            entry.entropy = entropy;
        }
    }

    // 4. Verdict Assignment
    if (entry.isSigned) {
        entry.verdict = "SAFE";
        entry.threatDescription = "Valid Authenticode Digital Signature";
    } else {
        if (entry.entropy > 7.2) {
            entry.verdict = "SUSPICIOUS";
            entry.threatDescription = "Unsigned binary with high Shannon entropy (" +
                                      std::to_string(entry.entropy).substr(0, 4) + ") in autoruns";
        } else {
            entry.verdict = "SUSPICIOUS";
            entry.threatDescription = "Unsigned startup executable";
        }
    }
}

PersistenceReport PersistenceAuditor::AuditPersistence() {
    PersistenceReport report;
    report.timestamp = NowUtcIso8601();

    // Check Run and RunOnce in HKCU and HKLM
    AuditRegistryKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Run", report.entries);
    AuditRegistryKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU\\RunOnce", report.entries);
    AuditRegistryKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Run", report.entries);
    AuditRegistryKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM\\RunOnce", report.entries);

    // Check CSIDL_STARTUP and CSIDL_COMMON_STARTUP
    AuditStartupDirectory(CSIDL_STARTUP, "Startup (User)", report.entries);
    AuditStartupDirectory(CSIDL_COMMON_STARTUP, "Startup (Common)", report.entries);

    report.totalAudited = static_cast<uint32_t>(report.entries.size());

    for (const auto& e : report.entries) {
        if (!e.isSigned) report.unsignedCount++;
        if (e.verdict == "MALICIOUS") report.maliciousCount++;
        else if (e.verdict == "SUSPICIOUS") report.suspiciousCount++;
    }

    report.success = true;

    if (report.maliciousCount > 0) {
        report.summary = "CRITICAL ALERT: Detected " + std::to_string(report.maliciousCount) +
                         " malicious persistence binaries in startup.";
    } else if (report.suspiciousCount > 0) {
        report.summary = "Audited " + std::to_string(report.totalAudited) +
                         " autorun locations. Found " + std::to_string(report.suspiciousCount) +
                         " unsigned or high-entropy startup entries.";
    } else {
        report.summary = "Audited " + std::to_string(report.totalAudited) +
                         " persistence locations. All registered binaries are Authenticode verified and clean.";
    }

    return report;
}

std::string PersistenceAuditor::AuditPersistenceJson() {
    auto report = AuditPersistence();

    json root;
    root["cmd"] = "audit_autoruns";
    root["status"] = report.success ? "ok" : "error";
    root["timestamp"] = report.timestamp;
    root["total_audited"] = report.totalAudited;
    root["unsigned_count"] = report.unsignedCount;
    root["suspicious_count"] = report.suspiciousCount;
    root["malicious_count"] = report.maliciousCount;
    root["summary"] = report.summary;

    json entries = json::array();
    for (const auto& e : report.entries) {
        json item;
        item["location"] = e.location;
        item["name"] = e.name;
        item["raw_command"] = e.rawCommand;
        item["target_path"] = e.targetPath;
        item["file_exists"] = e.fileExists;
        item["is_signed"] = e.isSigned;
        item["entropy"] = e.entropy;
        item["signature_hit"] = e.signatureHit;
        item["verdict"] = e.verdict;
        item["threat_description"] = e.threatDescription;
        entries.push_back(item);
    }
    root["entries"] = entries;

    return root.dump();
}

} // namespace audit
} // namespace vantor
