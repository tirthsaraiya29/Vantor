#include "RealTimeProtection.h"
#include "Scanner.h"
#include "ConfigManager.h"
#include "../common/Logger.h"
#include "../common/nlohmann/json.hpp"

#include <shlobj.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <dbt.h>
#include <filesystem>
#include <chrono>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace vantor {
namespace rtp {

// Window procedure for hidden USB/removable device notification window
static LRESULT CALLBACK DeviceWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_DEVICECHANGE && wParam == DBT_DEVICEARRIVAL) {
        auto* hdr = reinterpret_cast<DEV_BROADCAST_HDR*>(lParam);
        if (hdr && hdr->dbch_devicetype == DBT_DEVTYP_VOLUME) {
            auto* vol = reinterpret_cast<DEV_BROADCAST_VOLUME*>(lParam);
            DWORD unitmask = vol->dbcv_unitmask;
            for (char i = 0; i < 26; ++i) {
                if (unitmask & (1 << i)) {
                    wchar_t driveRoot[] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', L'\0' };
                    if (GetDriveTypeW(driveRoot) == DRIVE_REMOVABLE) {
                        LOG_INFO("RTP", "New USB/Removable volume arrival detected: " + Utf16ToUtf8(driveRoot));
                        RealTimeProtection::Instance().AddWatchPath(driveRoot);

                        // Trigger auto quick scan of removable drive
                        scan::Scanner::Instance().StartScan("custom", Utf16ToUtf8(driveRoot), [](const scan::ScanProgressInfo& info) {
                            if (info.threatsDetected > 0) {
                                LOG_ALERT("RTP", "Threat detected during USB auto-scan: " + info.currentFile, "{}");
                            }
                        });
                    }
                }
            }
        }
    }
    return DefWindowProcW(hWnd, message, wParam, lParam);
}

RealTimeProtection::RealTimeProtection() {}

RealTimeProtection::~RealTimeProtection() {
    Stop();
}

bool RealTimeProtection::AddWatchPath(const std::wstring& directoryPath) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    for (const auto& existing : watchPaths_) {
        if (_wcsicmp(existing.c_str(), directoryPath.c_str()) == 0) {
            return false;
        }
    }
    watchPaths_.push_back(directoryPath);

    if (running_) {
        watcherThreads_.emplace_back(&RealTimeProtection::MonitorWorker, this, directoryPath);
    }
    return true;
}

bool RealTimeProtection::Start() {
    if (running_.exchange(true)) return true;

    hStopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        watchPaths_.clear();

        // 1. Sensitive User directories
        wchar_t userProfile[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, userProfile))) {
            watchPaths_.push_back(std::wstring(userProfile) + L"\\Downloads");
            watchPaths_.push_back(std::wstring(userProfile) + L"\\Desktop");
            watchPaths_.push_back(std::wstring(userProfile) + L"\\AppData\\Local\\Temp");
        }

        // Minor 15: Add %AppData%\Roaming and %ProgramData%
        wchar_t appDataRoaming[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appDataRoaming))) {
            watchPaths_.push_back(appDataRoaming);
        }

        wchar_t programData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, programData))) {
            watchPaths_.push_back(programData);
        }

        wchar_t startupPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, startupPath))) {
            watchPaths_.push_back(startupPath);
        }

        // 2. Existing Removable USB Storage Drives
        DWORD drives = GetLogicalDrives();
        for (int i = 0; i < 26; ++i) {
            if (drives & (1 << i)) {
                wchar_t rootPath[] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', L'\0' };
                UINT driveType = GetDriveTypeW(rootPath);
                if (driveType == DRIVE_REMOVABLE) {
                    watchPaths_.push_back(rootPath);
                    LOG_INFO("RTP", "Attached removable drive to real-time shield: " + Utf16ToUtf8(rootPath));
                }
            }
        }
    }

    // Minor 14: Start a pool of worker threads for parallel RTP file processing
    workerThreads_.clear();
    for (int i = 0; i < 2; ++i) {
        workerThreads_.emplace_back(&RealTimeProtection::WorkerLoop, this);
    }

    // Launch directory watcher threads
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        for (const auto& path : watchPaths_) {
            std::error_code ec;
            if (fs::exists(path, ec)) {
                watcherThreads_.emplace_back(&RealTimeProtection::MonitorWorker, this, path);
            }
        }
    }

    // Major 11: Start USB / Removable drive notification listener thread
    deviceWatcherThread_ = std::thread(&RealTimeProtection::DeviceNotificationWorker, this);

    LOG_INFO("RTP", "Real-Time Protection active (" + std::to_string(watcherThreads_.size()) +
             " monitored locations, worker pool size: 2, USB auto-scan active).");
    return true;
}

void RealTimeProtection::Stop() {
    if (!running_.exchange(false)) return;

    if (hStopEvent_) {
        SetEvent(hStopEvent_);
    }

    // Stop device watcher window
    if (hDeviceWnd_) {
        PostMessageW(hDeviceWnd_, WM_CLOSE, 0, 0);
    }
    if (deviceWatcherThread_.joinable()) {
        deviceWatcherThread_.join();
    }

    // Wake worker threads to exit
    cvQueue_.notify_all();
    for (auto& wt : workerThreads_) {
        if (wt.joinable()) {
            wt.join();
        }
    }
    workerThreads_.clear();

    // Cancel directory change I/O
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

    if (hStopEvent_) {
        CloseHandle(hStopEvent_);
        hStopEvent_ = nullptr;
    }

    LOG_INFO("RTP", "Real-Time Protection engine deactivated.");
}

void RealTimeProtection::DeviceNotificationWorker() {
    WNDCLASSEXW wx{};
    wx.cbSize = sizeof(WNDCLASSEXW);
    wx.lpfnWndProc = DeviceWndProc;
    wx.hInstance = GetModuleHandleW(nullptr);
    wx.lpszClassName = L"VantorDeviceWatcherClass";
    RegisterClassExW(&wx);

    hDeviceWnd_ = CreateWindowExW(
        0, L"VantorDeviceWatcherClass", L"VantorDeviceWatcher",
        0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), nullptr
    );

    if (hDeviceWnd_) {
        DEV_BROADCAST_DEVICEINTERFACE_W dbi{};
        dbi.dbcc_size = sizeof(dbi);
        dbi.dbcc_devicetype = DBT_DEVTYP_VOLUME;
        hDevNotify_ = RegisterDeviceNotificationW(hDeviceWnd_, &dbi, DEVICE_NOTIFY_WINDOW_HANDLE);
    }

    MSG msg;
    while (running_ && GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (hDevNotify_) {
        UnregisterDeviceNotification(hDevNotify_);
        hDevNotify_ = nullptr;
    }
    if (hDeviceWnd_) {
        DestroyWindow(hDeviceWnd_);
        hDeviceWnd_ = nullptr;
    }
    UnregisterClassW(L"VantorDeviceWatcherClass", GetModuleHandleW(nullptr));
}

void RealTimeProtection::RecordEvent(const RtpEvent& ev) {
    std::lock_guard<std::mutex> lock(eventMutex_);
    eventRingBuffer_.push_front(ev);
    while (eventRingBuffer_.size() > 100) {
        eventRingBuffer_.pop_back();
    }
}

bool RealTimeProtection::TryTerminateProcessByFilePath(const std::wstring& targetPath, DWORD* outPid) {
    bool terminated = false;
    std::wstring normTarget = ToLowerW(NormalizePathSeparators(targetPath));

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4 || pe.th32ProcessID == GetCurrentProcessId()) continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hProc) {
                wchar_t procPath[MAX_PATH] = { 0 };
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, procPath, &size)) {
                    std::wstring normProc = ToLowerW(NormalizePathSeparators(procPath));
                    if (normProc == normTarget) {
                        if (outPid) *outPid = pe.th32ProcessID;
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

void RealTimeProtection::WorkerLoop() {
    while (running_) {
        std::wstring targetPath;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            cvQueue_.wait(lock, [this]() {
                return !running_ || !workQueue_.empty();
            });

            if (!running_ && workQueue_.empty()) {
                break;
            }

            if (!workQueue_.empty()) {
                targetPath = std::move(workQueue_.front());
                workQueue_.pop();
            }
        }

        if (!targetPath.empty()) {
            ProcessFile(targetPath);
        }
    }
}

void RealTimeProtection::ProcessFile(const std::wstring& fullFilePath) {
    std::string pathStr = Utf16ToUtf8(fullFilePath);
    std::string lowerPath = ToLower(pathStr);

    bool isTarget = (
        lowerPath.ends_with(".exe") || lowerPath.ends_with(".dll") ||
        lowerPath.ends_with(".sys") || lowerPath.ends_with(".scr") ||
        lowerPath.ends_with(".bat") || lowerPath.ends_with(".cmd") ||
        lowerPath.ends_with(".vbs") || lowerPath.ends_with(".ps1") ||
        lowerPath.ends_with(".js")  || lowerPath.ends_with(".hta") ||
        lowerPath.ends_with(".com") || lowerPath.ends_with(".pif")
    );

    if (!isTarget) return;

    // Minor 11: Debounce tracking with time-based expiry (erase older than 10s)
    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    {
        std::lock_guard<std::mutex> lock(debounceMutex_);
        auto it = recentEventDebounce_.find(pathStr);
        if (it != recentEventDebounce_.end()) {
            if (nowMs - it->second < 200) {
                return;
            }
        }
        recentEventDebounce_[pathStr] = nowMs;
        if (recentEventDebounce_.size() > 5000) {
            for (auto mapIt = recentEventDebounce_.begin(); mapIt != recentEventDebounce_.end(); ) {
                if (nowMs - mapIt->second > 10000) {
                    mapIt = recentEventDebounce_.erase(mapIt);
                } else {
                    ++mapIt;
                }
            }
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(40));

    std::error_code ec;
    if (!fs::exists(fullFilePath, ec) || !fs::is_regular_file(fullFilePath, ec)) {
        return;
    }

    auto ftime = fs::last_write_time(fullFilePath, ec);
    uint64_t fsize = fs::file_size(fullFilePath, ec);
    if (ec) return;

    auto sTime = std::chrono::duration_cast<std::chrono::milliseconds>(ftime.time_since_epoch()).count();
    std::string cacheKey = pathStr + "|" + std::to_string(sTime) + "|" + std::to_string(fsize);

    // Fast Path: Sub-microsecond LRU Clean Cache lookup
    ScanVerdict cachedVerdict = ScanVerdict::Clean;
    if (cleanCache_.Lookup(cacheKey, cachedVerdict)) {
        if (cachedVerdict == ScanVerdict::Clean || cachedVerdict == ScanVerdict::Safe) {
            stats_.cleanCacheHits.fetch_add(1, std::memory_order_relaxed);
            stats_.filesIntercepted.fetch_add(1, std::memory_order_relaxed);

            RtpEvent ev;
            ev.id = std::to_string(++eventCounter_);
            ev.timestamp = NowUtcIso8601();
            ev.eventType = "FILE_VERIFIED";
            ev.filePath = pathStr;
            ev.verdict = "SAFE";
            ev.actionTaken = "CACHE_HIT";
            ev.threatName = "LRU Clean Verified";
            RecordEvent(ev);
            return;
        }
    }

    stats_.filesIntercepted.fetch_add(1, std::memory_order_relaxed);
    auto result = scan::Scanner::Instance().ScanSingleFile(pathStr, "RTP-SHIELD");

    RtpEvent ev;
    ev.id = std::to_string(++eventCounter_);
    ev.timestamp = NowUtcIso8601();
    ev.filePath = pathStr;

    if (result.verdict == ScanVerdict::Malicious) {
        DWORD targetPid = 0;
        bool terminated = TryTerminateProcessByFilePath(fullFilePath, &targetPid);
        ev.processId = targetPid; // Minor 13: Populate PID

        bool quarantined = scan::Scanner::Instance().QuarantineFile(
            pathStr, "RTP-SHIELD", result.sha256, result.sha512, result.threatDescription
        );

        stats_.threatsNeutralized.fetch_add(1, std::memory_order_relaxed);

        ev.eventType = "THREAT_BLOCKED";
        ev.verdict = "MALICIOUS";
        ev.threatName = result.threatDescription.empty() ? "Trojan.Win32.Generic" : result.threatDescription;
        ev.actionTaken = quarantined ? (terminated ? "TERMINATED_&_QUARANTINED" : "QUARANTINED") : "DETECTED";

        RecordEvent(ev);
        LOG_ALERT("RTP", "Real-Time Threat Blocked & Quarantined: " + pathStr,
                  "{\"threat\":\"" + ev.threatName + "\",\"action\":\"" + ev.actionTaken + "\",\"pid\":" + std::to_string(targetPid) + "}");
    }
    else if (result.verdict == ScanVerdict::Suspicious) {
        ev.eventType = "SUSPICIOUS_ACTIVITY";
        ev.verdict = "SUSPICIOUS";
        ev.threatName = result.threatDescription;
        ev.actionTaken = "ALERTED";
        RecordEvent(ev);
    }
    else {
        cleanCache_.Insert(cacheKey, result.verdict);

        ev.eventType = "FILE_ANALYZED";
        ev.verdict = "SAFE";
        ev.actionTaken = "ANALYZED";
        ev.threatName = "Authenticode/Clean";
        RecordEvent(ev);
    }
}

// Minor 12: MonitorWorker with OVERLAPPED I/O
void RealTimeProtection::MonitorWorker(std::wstring directoryPath) {
    HANDLE hDir = CreateFileW(
        directoryPath.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        dirHandles_.push_back(hDir);
    }

    HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvent) {
        CloseHandle(hDir);
        return;
    }

    OVERLAPPED ov{};
    ov.hEvent = hEvent;

    std::vector<BYTE> buffer(64 * 1024);

    while (running_) {
        if (!config::ConfigManager::Instance().GetConfig().rtpEnabled) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        ResetEvent(hEvent);
        DWORD bytesReturned = 0;
        BOOL ok = ReadDirectoryChangesW(
            hDir,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned,
            &ov,
            nullptr
        );

        if (!ok && GetLastError() != ERROR_IO_PENDING) {
            break;
        }

        HANDLE waitHandles[2] = { hEvent, hStopEvent_ };
        DWORD waitRes = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

        if (waitRes == WAIT_OBJECT_0 + 1 || !running_) {
            CancelIoEx(hDir, &ov);
            break;
        }

        if (waitRes == WAIT_OBJECT_0) {
            if (GetOverlappedResult(hDir, &ov, &bytesReturned, FALSE) && bytesReturned > 0) {
                size_t offset = 0;
                while (offset + sizeof(FILE_NOTIFY_INFORMATION) <= bytesReturned) {
                    auto* notify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data() + offset);
                    if (notify->FileNameLength > 0 &&
                        offset + sizeof(FILE_NOTIFY_INFORMATION) - sizeof(WCHAR) + notify->FileNameLength <= bytesReturned) {
                        if (notify->Action == FILE_ACTION_ADDED || notify->Action == FILE_ACTION_MODIFIED) {
                            std::wstring relName(notify->FileName, notify->FileNameLength / sizeof(wchar_t));
                            std::wstring fullPath = directoryPath + L"\\" + relName;

                            {
                                std::lock_guard<std::mutex> lock(queueMutex_);
                                if (workQueue_.size() < MAX_QUEUE_SIZE) {
                                    workQueue_.push(std::move(fullPath));
                                }
                            }
                            cvQueue_.notify_one();
                        }
                    }
                    if (notify->NextEntryOffset == 0) break;
                    offset += notify->NextEntryOffset;
                }
            }
        }
    }

    CloseHandle(hEvent);
}

std::string RealTimeProtection::GetRtpTelemetryJson() {
    json j;
    j["status"] = running_ ? "RUNNING" : "STOPPED";
    j["files_intercepted"] = stats_.filesIntercepted.load();
    j["threats_neutralized"] = stats_.threatsNeutralized.load();
    j["clean_cache_hits"] = stats_.cleanCacheHits.load();
    j["clean_cache_size"] = cleanCache_.Size();

    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        j["monitored_paths_count"] = watchPaths_.size();
        json paths = json::array();
        for (const auto& p : watchPaths_) {
            paths.push_back(Utf16ToUtf8(p));
        }
        j["monitored_paths"] = paths;
    }

    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        json events = json::array();
        for (const auto& ev : eventRingBuffer_) {
            json item;
            item["id"] = ev.id;
            item["timestamp"] = ev.timestamp;
            item["event_type"] = ev.eventType;
            item["file_path"] = ev.filePath;
            item["verdict"] = ev.verdict;
            item["action_taken"] = ev.actionTaken;
            item["threat_name"] = ev.threatName;
            item["process_id"] = ev.processId;
            events.push_back(item);
        }
        j["recent_events"] = events;
    }

    return j.dump();
}

} // namespace rtp
} // namespace vantor
