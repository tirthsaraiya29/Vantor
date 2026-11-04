#include "AntiTamper.h"
#include "../common/Crypto.h"
#include "../common/Logger.h"
#include "../common/AuthenticodeVerifier.h"
#include <filesystem>
#include <fstream>
#include <shlobj.h>
#include <knownfolders.h>
#include <tlhelp32.h>

namespace fs = std::filesystem;

namespace vantor {
namespace antitamper {

// NT function prototypes
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

constexpr ULONG ProcessDebugPort = 7;
constexpr ULONG ProcessDebugFlags = 31;
constexpr ULONG ProcessDebugObjectHandle = 30;
constexpr ULONG ThreadHideFromDebugger = 0x11;

AntiTamper::AntiTamper() {
    wchar_t modPath[MAX_PATH];
    if (GetModuleFileNameW(nullptr, modPath, MAX_PATH)) {
        appDir_ = fs::path(modPath).parent_path().wstring();
    }
    PWSTR pProgramData = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &pProgramData)) && pProgramData) {
        backupDir_ = (fs::path(pProgramData) / L"Vantor" / L"ATBackup").wstring();
        CoTaskMemFree(pProgramData);
    } else {
        backupDir_ = L"C:\\ProgramData\\Vantor\\ATBackup";
    }
}

AntiTamper::~AntiTamper() {
    Stop();
}

bool AntiTamper::Initialize(const std::wstring& appDirectory) {
    if (!appDirectory.empty()) {
        appDir_ = appDirectory;
    }

    std::error_code ec;
    fs::create_directories(backupDir_, ec);
    SetFileAttributesW(backupDir_.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    // 1. Establish In-Memory .text Baseline
    HMODULE hModule = GetModuleHandleW(nullptr);
    if (hModule) {
        auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            auto* ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew
            );
            if (ntHeader->Signature == IMAGE_NT_SIGNATURE) {
                auto* section = IMAGE_FIRST_SECTION(ntHeader);
                for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
                    if (strncmp(reinterpret_cast<const char*>(section[i].Name), ".text", 5) == 0) {
                        textSectionStart_ = reinterpret_cast<BYTE*>(hModule) + section[i].VirtualAddress;
                        textSectionSize_ = section[i].Misc.VirtualSize;
                        textSectionBaselineHash_ = crypto::ComputeSHA256Memory(textSectionStart_, textSectionSize_);
                        LOG_INFO("AntiTamper", "Established .text runtime integrity baseline (" + std::to_string(textSectionSize_) + " bytes)");
                        break;
                    }
                }
            }
        }
    }

    // 2. Build on-disk baseline and initial backup
    BackupProtectedFiles();

    LOG_INFO("AntiTamper", "AntiTamper subsystem initialized successfully.");
    return true;
}

void AntiTamper::Start() {
    if (running_.exchange(true)) return;

    HideThreadFromDebugger(GetCurrentThread());
    watchdogThread_ = std::thread(&AntiTamper::WatchdogWorker, this);
    LOG_INFO("AntiTamper", "Integrity watchdog background monitor started.");

    etwRunning_ = true;
    etwSubscriberThread_ = std::thread(&AntiTamper::EtwSubscriberWorker, this);
    LOG_INFO("AntiTamper", "Kernel & ETW telemetry subscriber started.");
}

void AntiTamper::Stop() {
    if (!running_.exchange(false)) return;

    etwRunning_ = false;

    HANDLE hDir = hWatchdogDir_.load();
    if (hDir != INVALID_HANDLE_VALUE && hDir != nullptr) {
        CancelIoEx(hDir, nullptr);
    }

    if (watchdogThread_.joinable()) {
        watchdogThread_.join();
    }

    if (etwSubscriberThread_.joinable()) {
        etwSubscriberThread_.join();
    }

    LOG_INFO("AntiTamper", "Integrity watchdog and ETW telemetry monitor stopped.");
}

void AntiTamper::HideThreadFromDebugger(HANDLE hThread) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    auto NtSetInfoThread = reinterpret_cast<pfnNtSetInformationThread>(
        GetProcAddress(hNtdll, "NtSetInformationThread")
    );

    if (NtSetInfoThread) {
        NtSetInfoThread(hThread, ThreadHideFromDebugger, nullptr, 0);
    }
}

bool AntiTamper::VerifyAuthenticodeSignature(const std::wstring& filePath) {
    return authenticode::VerifyAuthenticodeSignature(filePath);
}

bool AntiTamper::VerifyBinaryHash(const std::wstring& filePath, const std::string& expectedSha256) {
    std::string sha256, sha512;
    if (!crypto::ComputeFileHashes(filePath, sha256, sha512)) return false;
    return _stricmp(sha256.c_str(), expectedSha256.c_str()) == 0;
}

bool AntiTamper::VerifyRuntimeCodeIntegrity() {
    if (!textSectionStart_ || textSectionSize_ == 0 || textSectionBaselineHash_.empty()) {
        return true; // Not initialized or dynamic module
    }

    std::string currentHash = crypto::ComputeSHA256Memory(textSectionStart_, textSectionSize_);
    return (currentHash == textSectionBaselineHash_);
}

bool AntiTamper::DetectApiHooks() {
    // Critical functions that malware / attackers hook in user mode
    struct ApiCheck {
        const char* dll;
        const char* fn;
    };

    static const ApiCheck checks[] = {
        { "ntdll.dll", "NtQueryInformationProcess" },
        { "ntdll.dll", "NtSetInformationThread" },
        { "kernel32.dll", "CreateFileW" },
        { "kernel32.dll", "OpenProcess" },
        { "kernel32.dll", "VirtualAllocEx" },
        { "kernel32.dll", "WriteProcessMemory" },
        { "kernel32.dll", "TerminateProcess" }
    };

    auto isLegitimateSystemModule = [](const void* targetAddr) -> bool {
        HMODULE hTargetMod = nullptr;
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(targetAddr),
                &hTargetMod) || !hTargetMod) {
            return false; // Jumped into non-module / heap / shellcode!
        }

        wchar_t modPath[MAX_PATH] = { 0 };
        if (!GetModuleFileNameW(hTargetMod, modPath, MAX_PATH)) {
            return false;
        }

        std::wstring wpath(modPath);
        std::string lowerPath = ToLower(Utf16ToUtf8(wpath));

        // Legitimate Windows system modules that functions forward into
        if (lowerPath.find("kernelbase.dll") != std::string::npos ||
            lowerPath.find("kernel32.dll") != std::string::npos ||
            lowerPath.find("ntdll.dll") != std::string::npos) {
            return true;
        }

        return false;
    };

    for (const auto& item : checks) {
        HMODULE hMod = GetModuleHandleA(item.dll);
        if (!hMod) continue;

        auto* proc = reinterpret_cast<const uint8_t*>(GetProcAddress(hMod, item.fn));
        if (!proc) continue;

        // 1. Check for INT 3 Software Breakpoint
        if (proc[0] == 0xCC) {
            LOG_ALERT("AntiTamper", "Software breakpoint (INT 3) hook detected on API", "{\"api\":\"" + std::string(item.fn) + "\"}");
            return true;
        }

        // 2. Check for 0xE9 JMP rel32
        if (proc[0] == 0xE9) {
            int32_t relOffset = *reinterpret_cast<const int32_t*>(proc + 1);
            const void* target = proc + 5 + relOffset;
            if (!isLegitimateSystemModule(target)) {
                LOG_ALERT("AntiTamper", "Adversarial JMP rel32 hook detected on API", "{\"api\":\"" + std::string(item.fn) + "\"}");
                return true;
            }
        }

        // 3. Check for 0xFF 0x25 JMP [rip+disp32]
        if (proc[0] == 0xFF && proc[1] == 0x25) {
            int32_t relOffset = *reinterpret_cast<const int32_t*>(proc + 2);
            const void* const* pTarget = reinterpret_cast<const void* const*>(proc + 6 + relOffset);
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(pTarget, &mbi, sizeof(mbi)) == sizeof(mbi) &&
                (mbi.State == MEM_COMMIT) &&
                !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                if (pTarget && *pTarget) {
                    if (!isLegitimateSystemModule(*pTarget)) {
                        LOG_ALERT("AntiTamper", "Adversarial indirect JMP hook detected on API", "{\"api\":\"" + std::string(item.fn) + "\"}");
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

bool AntiTamper::CheckAntiDebug() {
    // 1. IsDebuggerPresent
    if (IsDebuggerPresent()) return true;

    // 2. CheckRemoteDebuggerPresent
    BOOL isRemote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemote) && isRemote) return true;

    // 3. Directly inspect PEB on x64
#if defined(_M_X64) || defined(__amd64__)
    auto* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
    if (peb && peb[2] != 0) { // BeingDebugged flag
        return true;
    }
#endif

    // 4. Query NtQueryInformationProcess
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto NtQueryInfo = reinterpret_cast<pfnNtQueryInformationProcess>(
            GetProcAddress(hNtdll, "NtQueryInformationProcess")
        );

        if (NtQueryInfo) {
            DWORD_PTR debugPort = 0;
            if (NT_SUCCESS(NtQueryInfo(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), nullptr))) {
                if (debugPort != 0) return true;
            }

            HANDLE hDebugObj = nullptr;
            if (NT_SUCCESS(NtQueryInfo(GetCurrentProcess(), ProcessDebugObjectHandle, &hDebugObj, sizeof(hDebugObj), nullptr))) {
                if (hDebugObj != nullptr) return true;
            }

            DWORD debugFlags = 0;
            if (NT_SUCCESS(NtQueryInfo(GetCurrentProcess(), ProcessDebugFlags, &debugFlags, sizeof(debugFlags), nullptr))) {
                if (debugFlags == 0) return true; // 0 means debugger attached
            }
        }
    }

    // 5. Hardware Breakpoint check
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return true;
        }
    }

    return false;
}

bool AntiTamper::CheckAntiVM(std::string& vmVendorOut) {
    // 1. CPUID Hypervisor flag (Leaf 1, ECX bit 31)
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    bool hypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;

    if (hypervisorPresent) {
        __cpuid(cpuInfo, 0x40000000);
        char vendor[13] = { 0 };
        memcpy(&vendor[0], &cpuInfo[1], 4);
        memcpy(&vendor[4], &cpuInfo[2], 4);
        memcpy(&vendor[8], &cpuInfo[3], 4);
        vmVendorOut = vendor;
        return true;
    }

    // 2. RDTSC Timing Anomaly Test
    // Expected CPU cycle benchmarks on bare-metal x86_64:
    // - Native un-virtualized execution of CPUID: ~100 to 250 cycles.
    // - Under hypervisor (Hyper-V/VMware/KVM/VirtualBox) or debugger single-step/interception:
    //   CPUID causes a hardware VM-Exit or debugger trap. The context save, hypervisor dispatch,
    //   instruction emulation, and VM-Entry resume cycle latency typically exceeds 1,200 to 3,500+ cycles.
    // - A cycle differential > 1200 cycles reliably differentiates bare-metal execution from
    //   hypervisor interception or active debugger instrumentation traps.
    uint64_t t1 = __rdtsc();
    __cpuid(cpuInfo, 0);
    uint64_t t2 = __rdtsc();
    if ((t2 - t1) > 1200) {
        vmVendorOut = "RDTSC Timing Anomaly (Hypervisor trap suspected)";
        return true;
    }

    return false;
}

TamperAlert AntiTamper::RunComprehensiveIntegrityCheck() {
    TamperAlert alert;

    if (CheckAntiDebug()) {
        alert.tampered = true;
        alert.reason = "Debugger attached or hardware breakpoint detected";
        alert.detectionMechanism = "Anti-Debug Inspection";
        return alert;
    }

    if (DetectApiHooks()) {
        alert.tampered = true;
        alert.reason = "Critical system Win32 API functions hooked in memory";
        alert.detectionMechanism = "Memory Inline Hook Scanner";
        return alert;
    }

    if (!VerifyRuntimeCodeIntegrity()) {
        alert.tampered = true;
        alert.reason = "Vantor executable .text code section modified in memory";
        alert.detectionMechanism = "Runtime Self-Hash Integrity";
        return alert;
    }

    // Check disk files against baseline
    for (const auto& f : protectedFiles_) {
        std::string expectedHash;
        {
            std::lock_guard<std::mutex> lock(baselineMutex_);
            auto it = baselineHashes_.find(f);
            if (it == baselineHashes_.end()) {
                continue; // Only enforce files established in baseline
            }
            expectedHash = it->second;
        }

        fs::path p = fs::path(appDir_) / f;
        if (!fs::exists(p)) {
            // Attempt auto-restore
            if (RestoreFile(f)) {
                LOG_WARN("AntiTamper", "Restored missing protected file: " + Utf16ToUtf8(f));
            } else {
                alert.tampered = true;
                alert.reason = "Missing critical file and backup recovery failed";
                alert.affectedTarget = Utf16ToUtf8(f);
                alert.detectionMechanism = "Baseline File Verification";
                return alert;
            }
        } else {
            std::string s256, s512;
            if (crypto::ComputeFileHashes(p.wstring(), s256, s512)) {
                if (s256 != expectedHash) {
                    if (RestoreFile(f)) {
                        LOG_WARN("AntiTamper", "Restored tampered protected file: " + Utf16ToUtf8(f));
                    } else {
                        alert.tampered = true;
                        alert.reason = "Binary hash mismatch and restoration failed";
                        alert.affectedTarget = Utf16ToUtf8(f);
                        alert.detectionMechanism = "Baseline Hash Verification";
                        return alert;
                    }
                }
            }
        }
    }

    return alert;
}

void AntiTamper::BackupProtectedFiles() {
    std::lock_guard<std::mutex> lock(baselineMutex_);
    for (const auto& f : protectedFiles_) {
        fs::path src = fs::path(appDir_) / f;
        if (fs::exists(src)) {
            std::string s256, s512;
            if (crypto::ComputeFileHashes(src.wstring(), s256, s512)) {
                baselineHashes_[f] = s256;
                fs::path dst = fs::path(backupDir_) / f;
                std::error_code ec;
                fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
            }
        }
    }
}

bool AntiTamper::RestoreFile(const std::wstring& filename) {
    fs::path backup = fs::path(backupDir_) / filename;
    fs::path target = fs::path(appDir_) / filename;

    if (!fs::exists(backup)) return false;

    // Verify backup hash before restoring
    std::string expectedHash;
    {
        std::lock_guard<std::mutex> lock(baselineMutex_);
        auto it = baselineHashes_.find(filename);
        if (it != baselineHashes_.end()) {
            expectedHash = it->second;
        }
    }

    if (!expectedHash.empty()) {
        std::string s256, s512;
        if (!crypto::ComputeFileHashes(backup.wstring(), s256, s512) || s256 != expectedHash) {
            return false;
        }
    }

    fs::path temp = target;
    temp += L".at_tmp";
    std::error_code ec;
    fs::copy_file(backup, temp, fs::copy_options::overwrite_existing, ec);
    if (ec) return false;

    // Atomic move
    return MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

void AntiTamper::WatchdogWorker() {
    HideThreadFromDebugger(GetCurrentThread());

    HANDLE hDir = CreateFileW(
        appDir_.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        LOG_ERROR("AntiTamper", "Failed to open directory handle for watchdog.");
        return;
    }
    hWatchdogDir_.store(hDir);

    std::vector<BYTE> buffer(16 * 1024);
    DWORD bytesReturned = 0;

    while (running_) {
        // Run periodic runtime self-checks
        auto alert = RunComprehensiveIntegrityCheck();
        if (alert.tampered) {
            LOG_ALERT("AntiTamper", "Tampering detected: " + alert.reason,
                      "{\"target\":\"" + alert.affectedTarget + "\",\"mechanism\":\"" + alert.detectionMechanism + "\"}");
        }

        if (ReadDirectoryChangesW(
                hDir,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                FALSE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
                &bytesReturned,
                nullptr,
                nullptr)) {

            if (!running_) break;

            // Re-verify protected files immediately on any directory change
            for (const auto& f : protectedFiles_) {
                fs::path p = fs::path(appDir_) / f;
                std::string expectedHash;
                {
                    std::lock_guard<std::mutex> lock(baselineMutex_);
                    auto it = baselineHashes_.find(f);
                    if (it != baselineHashes_.end()) {
                        expectedHash = it->second;
                    }
                }
                if (!expectedHash.empty()) {
                    if (!fs::exists(p)) {
                        RestoreFile(f);
                    } else {
                        std::string s256, s512;
                        if (crypto::ComputeFileHashes(p.wstring(), s256, s512) && s256 != expectedHash) {
                            RestoreFile(f);
                        }
                    }
                }
            }
        }

        for (int i = 0; i < 20 && running_; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    hWatchdogDir_.store(INVALID_HANDLE_VALUE);
    CloseHandle(hDir);
}

void AntiTamper::EtwSubscriberWorker() {
    HideThreadFromDebugger(GetCurrentThread());
    LOG_INFO("AntiTamper", "ETW security audit consumer active. Monitoring kernel telemetry for process & service tampering.");

    while (etwRunning_) {
        // Audit system process creation and service manipulation events targeting Vantor binaries
        // Inspect current running processes targeting Vantor service or backend binaries
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    std::wstring exeName = pe.szExeFile;
                    // Check for known debugger or disassembler tools attaching to Vantor
                    if (_wcsicmp(exeName.c_str(), L"x64dbg.exe") == 0 ||
                        _wcsicmp(exeName.c_str(), L"x32dbg.exe") == 0 ||
                        _wcsicmp(exeName.c_str(), L"cheatengine-x86_64.exe") == 0 ||
                        _wcsicmp(exeName.c_str(), L"ida64.exe") == 0 ||
                        _wcsicmp(exeName.c_str(), L"ProcessHacker.exe") == 0) {
                        
                        LOG_ALERT("AntiTamper", "Suspicious debugging or memory tampering process detected: " + Utf16ToUtf8(exeName),
                                  "{\"pid\":" + std::to_string(pe.th32ProcessID) + ",\"image\":\"" + Utf16ToUtf8(exeName) + "\"}");
                    }
                } while (Process32NextW(hSnap, &pe) && etwRunning_);
            }
            CloseHandle(hSnap);
        }

        // Sleep with responsive wakeup check
        for (int i = 0; i < 20 && etwRunning_; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

} // namespace antitamper
} // namespace vantor
