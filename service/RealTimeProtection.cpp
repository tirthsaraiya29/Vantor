#include "RealTimeProtection.h"
#include "Scanner.h"
#include "ConfigManager.h"
#include "../common/Logger.h"

#include <shlobj.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <filesystem>

#pragma comment(lib, "psapi.lib")

namespace fs = std::filesystem;

namespace vantor {
namespace rtp {

RealTimeProtection::RealTimeProtection() {}

RealTimeProtection::~RealTimeProtection() {
    Stop();
}

bool RealTimeProtection::Start() {
    if (running_.exchange(true)) return true;

    // Collect sensitive system paths to monitor
    watchPaths_.clear();
    wchar_t userProfile[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, userProfile))) {
        watchPaths_.push_back(std::wstring(userProfile) + L"\\Downloads");
        watchPaths_.push_back(std::wstring(userProfile) + L"\\Desktop");
        watchPaths_.push_back(std::wstring(userProfile) + L"\\AppData\\Local\\Temp");
    }

    wchar_t startupPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, startupPath))) {
        watchPaths_.push_back(startupPath);
    }

    for (const auto& path : watchPaths_) {
        std::error_code ec;
        if (fs::exists(path, ec)) {
            watcherThreads_.emplace_back(&RealTimeProtection::MonitorWorker, this, path);
        }
    }

    LOG_INFO("RTP", "Real-Time Protection engine activated (" + std::to_string(watcherThreads_.size()) + " locations active).");
    return true;
}

void RealTimeProtection::Stop() {
    if (!running_.exchange(false)) return;

    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        for (HANDLE h : dirHandles_) {
            if (h != INVALID_HANDLE_VALUE && h != nullptr) {
                CancelIoEx(h, nullptr);
            }
        }
    }

    for (auto& t : watcherThreads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    watcherThreads_.clear();

    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        for (HANDLE h : dirHandles_) {
            if (h != INVALID_HANDLE_VALUE && h != nullptr) {
                CloseHandle(h);
            }
        }
        dirHandles_.clear();
    }

    LOG_INFO("RTP", "Real-Time Protection engine deactivated.");
}

bool RealTimeProtection::TryTerminateProcessByFilePath(const std::wstring& targetPath) {
    bool terminated = false;
    std::wstring normTarget = ToLowerW(NormalizePathSeparators(targetPath));

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            // Never terminate Idle, System (PID 4), or our own process
            if (pe.th32ProcessID <= 4 || pe.th32ProcessID == GetCurrentProcessId()) continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hProc) {
                wchar_t procPath[MAX_PATH] = { 0 };
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, procPath, &size)) {
                    std::wstring normProc = ToLowerW(NormalizePathSeparators(procPath));
                    if (normProc == normTarget) {
                        TerminateProcess(hProc, 1);
                        terminated = true;
                        LOG_ALERT("RTP", "Terminated malicious process: " + Utf16ToUtf8(targetPath),
                                  "{\"pid\":" + std::to_string(pe.th32ProcessID) + "}");
                    }
                }
                CloseHandle(hProc);
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return terminated;
}

void RealTimeProtection::HandleFileEvent(const std::wstring& fullFilePath) {
    std::string pathStr = Utf16ToUtf8(fullFilePath);
    std::string lowerPath = ToLower(pathStr);

    // Only inspect executable or script extensions
    bool isTarget = (
        lowerPath.ends_with(".exe") || lowerPath.ends_with(".dll") ||
        lowerPath.ends_with(".sys") || lowerPath.ends_with(".scr") ||
        lowerPath.ends_with(".bat") || lowerPath.ends_with(".cmd") ||
        lowerPath.ends_with(".vbs") || lowerPath.ends_with(".ps1")
    );

    if (!isTarget) return;

    // Wait a brief moment for writing process to close handle
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto result = scan::Scanner::Instance().ScanSingleFile(pathStr, "RTP-ALERT");
    if (result.verdict == ScanVerdict::Malicious) {
        LOG_ALERT("RTP", "Real-time threat detected: " + pathStr, "{\"threat\":\"" + result.threatDescription + "\"}");
        TryTerminateProcessByFilePath(fullFilePath);
    }
}

void RealTimeProtection::MonitorWorker(std::wstring directoryPath) {
    HANDLE hDir = CreateFileW(
        directoryPath.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        dirHandles_.push_back(hDir);
    }

    std::vector<BYTE> buffer(32 * 1024);
    DWORD bytesReturned = 0;

    while (running_) {
        if (!config::ConfigManager::Instance().GetConfig().rtpEnabled) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        if (ReadDirectoryChangesW(
                hDir,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                nullptr,
                nullptr)) {

            if (!running_) break;

            if (bytesReturned >= sizeof(FILE_NOTIFY_INFORMATION)) {
                size_t offset = 0;
                while (offset + sizeof(FILE_NOTIFY_INFORMATION) <= bytesReturned) {
                    auto* notify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data() + offset);
                    if (notify->FileNameLength > 0 &&
                        offset + sizeof(FILE_NOTIFY_INFORMATION) - sizeof(WCHAR) + notify->FileNameLength <= bytesReturned) {
                        if (notify->Action == FILE_ACTION_ADDED || notify->Action == FILE_ACTION_MODIFIED) {
                            std::wstring relName(notify->FileName, notify->FileNameLength / sizeof(wchar_t));
                            std::wstring fullPath = directoryPath + L"\\" + relName;
                            HandleFileEvent(fullPath);
                        }
                    }

                    if (notify->NextEntryOffset == 0) break;
                    offset += notify->NextEntryOffset;
                }
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
}

} // namespace rtp
} // namespace vantor
