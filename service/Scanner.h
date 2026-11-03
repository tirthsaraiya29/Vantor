#pragma once

#include "../common/Common.h"
#include <functional>
#include <atomic>
#include <memory>
#include <unordered_set>
#include <mutex>
#include <vector>

namespace vantor {
namespace scan {

struct ScanProgressInfo {
    std::string sessionId;
    int filesScanned = 0;
    int threatsDetected = 0;
    int filesQuarantined = 0;
    std::string currentFile;
    float percentComplete = 0.0f;
    bool isComplete = false;
    std::string errorMessage;
};

using ProgressCallback = std::function<void(const ScanProgressInfo&)>;

class Scanner {
public:
    static Scanner& Instance() {
        static Scanner instance;
        return instance;
    }

    bool Initialize(const std::string& baseDir = "");

    // Scanning execution
    bool StartScan(const std::string& scanType, const std::string& customPath = "", ProgressCallback progressCb = nullptr);
    void CancelScan();
    bool IsScanning() const { return isScanning_; }

    // Single file scan
    ScanResult ScanSingleFile(const std::string& filePath, const std::string& sessionId = "MANUAL-001");

    // Quarantine management
    bool QuarantineFile(const std::string& filePath, const std::string& sessionId, const std::string& sha256, const std::string& sha512);
    bool RestoreQuarantinedFile(int64_t recordId, const std::string& destinationPath = "");
    bool DeleteQuarantinedFile(int64_t recordId);
    std::vector<QuarantineEntry> GetQuarantineRecords();

    // PE Analysis & Heuristics
    static double CalculateHeuristicScore(const std::string& filePath, const std::vector<uint8_t>& peHeaderBuf);
    static bool VerifyAuthenticode(const std::wstring& filePath);

private:
    Scanner();
    ~Scanner();

    void ScanWorker(std::string scanType, std::string customPath, ProgressCallback progressCb);
    void TraverseDirectory(const std::wstring& root, int& scanned, int& threats, int totalEst, ProgressCallback progressCb);
    int EstimateFileCount(const std::string& scanType, const std::string& customPath);

    std::string baseDir_;
    std::string quarantineDir_;
    std::atomic<bool> isScanning_{false};
    std::atomic<bool> cancelRequested_{false};
    std::string activeSessionId_;

    std::mutex safeDbMutex_;
    std::mutex quarantineMutex_;
    std::unordered_set<std::string> inMemorySafeCache_;
};

} // namespace scan
} // namespace vantor
