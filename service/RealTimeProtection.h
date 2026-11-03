#pragma once

#include "../common/Common.h"
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>

namespace vantor {
namespace rtp {

class RealTimeProtection {
public:
    static RealTimeProtection& Instance() {
        static RealTimeProtection instance;
        return instance;
    }

    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }

private:
    RealTimeProtection();
    ~RealTimeProtection();

    void MonitorWorker(std::wstring directoryPath);
    void HandleFileEvent(const std::wstring& fullFilePath);
    bool TryTerminateProcessByFilePath(const std::wstring& targetPath);

    std::atomic<bool> running_{false};
    std::vector<std::thread> watcherThreads_;
    std::vector<std::wstring> watchPaths_;
    std::vector<HANDLE> dirHandles_;
    std::mutex stateMutex_;
};

} // namespace rtp
} // namespace vantor
