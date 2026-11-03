#pragma once

#include "../common/Common.h"
#include <wintrust.h>
#include <softpub.h>
#include <winternl.h>
#include <intrin.h>
#include <unordered_map>
#include <atomic>
#include <thread>
#include <mutex>

#pragma comment(lib, "wintrust.lib")

namespace vantor {
namespace antitamper {

struct TamperAlert {
    bool tampered = false;
    std::string reason;
    std::string affectedTarget;
    std::string detectionMechanism;
};

class AntiTamper {
public:
    static AntiTamper& Instance() {
        static AntiTamper instance;
        return instance;
    }

    // Initialize baseline, backup, and self-checks
    bool Initialize(const std::wstring& appDirectory = L"");

    // Lifecycle
    void Start();
    void Stop();

    // Inspection APIs
    bool VerifyAuthenticodeSignature(const std::wstring& filePath);
    bool VerifyBinaryHash(const std::wstring& filePath, const std::string& expectedSha256);
    bool VerifyRuntimeCodeIntegrity();
    bool DetectApiHooks();
    bool CheckAntiDebug();
    bool CheckAntiVM(std::string& vmVendorOut);

    // Full system integrity scan
    TamperAlert RunComprehensiveIntegrityCheck();

    // Directory Watchdog & Self-Healing
    void EnableDirectoryWatchdog(const std::wstring& targetDirectory);

    // Hardens current thread against debuggers
    static void HideThreadFromDebugger(HANDLE hThread = GetCurrentThread());

private:
    AntiTamper();
    ~AntiTamper();

    void WatchdogWorker();
    void BackupProtectedFiles();
    bool RestoreFile(const std::wstring& filename);

    std::wstring appDir_;
    std::wstring backupDir_;
    std::atomic<bool> running_{false};
    std::atomic<HANDLE> hWatchdogDir_{INVALID_HANDLE_VALUE};
    std::thread watchdogThread_;

    // Baselines
    mutable std::mutex baselineMutex_;
    std::unordered_map<std::wstring, std::string> baselineHashes_;
    std::string textSectionBaselineHash_;
    void* textSectionStart_ = nullptr;
    size_t textSectionSize_ = 0;

    std::vector<std::wstring> protectedFiles_ = {
        L"VantorService.exe",
        L"VantorBackend.exe",
        L"VantorUI.exe",
        L"signatures.db",
        L"signatures.idx",
        L"config.json"
    };
};

} // namespace antitamper
} // namespace vantor
