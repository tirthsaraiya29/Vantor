#pragma once

#include "../common/Common.h"
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <list>
#include <queue>
#include <unordered_map>
#include <condition_variable>

namespace vantor {
namespace rtp {

struct RtpEvent {
    std::string id;
    std::string timestamp;
    std::string eventType;    // "FILE_CREATED", "FILE_MODIFIED", "THREAT_BLOCKED"
    std::string filePath;
    std::string verdict;      // "SAFE", "SUSPICIOUS", "MALICIOUS"
    std::string actionTaken;  // "ANALYZED", "CACHE_HIT", "QUARANTINED", "TERMINATED"
    std::string threatName;
    DWORD processId{0};
};

struct RtpStats {
    std::atomic<uint64_t> filesIntercepted{0};
    std::atomic<uint32_t> threatsNeutralized{0};
    std::atomic<uint64_t> cleanCacheHits{0};
};

// Thread-safe LRU Clean File Cache (Path + MTime + Size -> ScanVerdict)
class RtpCleanCache {
public:
    explicit RtpCleanCache(size_t capacity = 10000) : capacity_(capacity) {}

    bool Lookup(const std::string& key, ScanVerdict& verdict) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = map_.find(key);
        if (it == map_.end()) return false;

        lruList_.splice(lruList_.begin(), lruList_, it->second.second);
        verdict = it->second.first;
        return true;
    }

    void Insert(const std::string& key, ScanVerdict verdict) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = map_.find(key);
        if (it != map_.end()) {
            lruList_.splice(lruList_.begin(), lruList_, it->second.second);
            it->second.first = verdict;
            return;
        }
        if (map_.size() >= capacity_) {
            std::string oldest = lruList_.back();
            map_.erase(oldest);
            lruList_.pop_back();
        }
        lruList_.push_front(key);
        map_[key] = { verdict, lruList_.begin() };
    }

    void Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        map_.clear();
        lruList_.clear();
    }

    size_t Size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return map_.size();
    }

private:
    size_t capacity_;
    mutable std::mutex mutex_;
    std::list<std::string> lruList_;
    std::unordered_map<std::string, std::pair<ScanVerdict, std::list<std::string>::iterator>> map_;
};

class RealTimeProtection {
public:
    static RealTimeProtection& Instance() {
        static RealTimeProtection instance;
        return instance;
    }

    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }

    // Dynamic watch path addition (e.g. on USB / removable drive insertion)
    bool AddWatchPath(const std::wstring& directoryPath);

    // Telemetry retrieval for Desktop GUI and IPC
    std::string GetRtpTelemetryJson();

    uint64_t GetFilesIntercepted() const { return stats_.filesIntercepted.load(); }
    uint32_t GetThreatsNeutralized() const { return stats_.threatsNeutralized.load(); }
    uint64_t GetCleanCacheHits() const { return stats_.cleanCacheHits.load(); }
    size_t GetMonitoredPathsCount() const {
        std::lock_guard<std::mutex> lock(stateMutex_);
        return watchPaths_.size();
    }

    RtpCleanCache& GetCleanCache() { return cleanCache_; }
    void RecordEvent(const RtpEvent& ev);

private:
    RealTimeProtection();
    ~RealTimeProtection();

    void MonitorWorker(std::wstring directoryPath);
    void WorkerLoop();
    void DeviceNotificationWorker();
    void ProcessFile(const std::wstring& fullFilePath);
    bool TryTerminateProcessByFilePath(const std::wstring& targetPath, DWORD* outPid = nullptr);

    std::atomic<bool> running_{false};
    std::vector<std::thread> watcherThreads_;
    std::vector<std::thread> workerThreads_;
    std::thread deviceWatcherThread_;
    std::vector<std::wstring> watchPaths_;
    std::vector<HANDLE> dirHandles_;
    HANDLE hStopEvent_{nullptr};
    HWND hDeviceWnd_{nullptr};
    HDEVNOTIFY hDevNotify_{nullptr};
    mutable std::mutex stateMutex_;

    // Asynchronous Bounded Work Queue
    std::queue<std::wstring> workQueue_;
    std::mutex queueMutex_;
    std::condition_variable cvQueue_;
    static constexpr size_t MAX_QUEUE_SIZE = 5000;

    // LRU Clean File Cache
    RtpCleanCache cleanCache_{10000};

    // Debounce tracking (file path -> last timestamp ms)
    std::unordered_map<std::string, int64_t> recentEventDebounce_;
    std::mutex debounceMutex_;

    // Ring Buffer for recent 100 events
    std::deque<RtpEvent> eventRingBuffer_;
    mutable std::mutex eventMutex_;
    std::atomic<uint64_t> eventCounter_{0};

    // Real-Time Statistics
    RtpStats stats_;
};

} // namespace rtp
} // namespace vantor
