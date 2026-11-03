#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>

namespace vantor {

// Constants
constexpr const wchar_t* SERVICE_NAME = L"VantorAntivirusService";
constexpr const wchar_t* SERVICE_DISPLAY_NAME = L"Vantor Antivirus Endpoint Service";
constexpr const wchar_t* SERVICE_DESCRIPTION = L"Provides real-time filesystem monitoring, malware scanning, and anti-tamper protection.";
constexpr const wchar_t* IPC_PIPE_NAME = L"\\\\.\\pipe\\VantorSecurityIPC";
constexpr const char* DEFAULT_GRPC_ADDRESS = "127.0.0.1:50051";

// SDDL: Allow LocalSystem (SY) and Builtin Administrators (BA) full access;
// Interactive Users (IU) Read/Write access; explicitly deny network logon.
constexpr const wchar_t* IPC_PIPE_SDDL = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

enum class ScanVerdict {
    Clean = 0,
    Safe = 1,
    Suspicious = 2,
    Malicious = 3,
    Error = 4
};

inline const char* VerdictToString(ScanVerdict v) {
    switch (v) {
        case ScanVerdict::Clean: return "clean";
        case ScanVerdict::Safe: return "safe";
        case ScanVerdict::Suspicious: return "suspicious";
        case ScanVerdict::Malicious: return "malicious";
        default: return "error";
    }
}

inline ScanVerdict StringToVerdict(const std::string& s) {
    if (s == "clean") return ScanVerdict::Clean;
    if (s == "safe") return ScanVerdict::Safe;
    if (s == "suspicious") return ScanVerdict::Suspicious;
    if (s == "malicious") return ScanVerdict::Malicious;
    return ScanVerdict::Error;
}

struct ScanResult {
    std::string filePath;
    std::string sha256;
    std::string sha512;
    ScanVerdict verdict = ScanVerdict::Clean;
    bool signatureHit = false;
    double heuristicScore = 0.0;
    double mlScore = 0.0;
    double finalScore = 0.0;
    std::string threatDescription;
    uint64_t fileSizeBytes = 0;
};

struct EngineConfig {
    bool rtpEnabled = true;
    double heuristicThreshold = 0.75;
    double zipBombRatioLimit = 10.0;
    uint64_t maxArchiveUncompressedBytes = 1024ULL * 1024ULL * 1024ULL; // 1GB
    bool antiTamperEnabled = true;
    std::string updateServerUrl = "https://signatures.vantor.local/v1/updates";
    int updateIntervalMinutes = 60;
    std::vector<std::string> excludedPaths;
};

struct QuarantineEntry {
    int64_t id = 0;
    std::string timestamp;
    std::string scanId;
    std::string originalPath;
    std::string encryptedFilename;
    std::string sha256;
    std::string sha512;
    std::string threatName;
    uint64_t fileSizeBytes = 0;
};

// Utilities
inline std::string Utf16ToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return {};
    std::string out(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &out[0], len, nullptr, nullptr);
    return out;
}

inline std::wstring Utf8ToUtf16(const std::string& str) {
    if (str.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (len <= 1) return {};
    std::wstring out(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &out[0], len);
    return out;
}

inline std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

inline std::string NowUtcIso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_s(&tm, &t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

inline std::string GenerateSessionId(const std::string& prefix) {
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    uint32_t rnd = (uint32_t)(now ^ (now >> 32)) % 9000 + 1000;
    return prefix + "-" + std::to_string(rnd);
}

} // namespace vantor
