#pragma once

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>

namespace vantor {
namespace backend {

struct UpdateResult {
    bool success = false;
    size_t signaturesAdded = 0;
    size_t totalSignatures = 0;
    std::string version;
    std::string lastUpdatedIso;
    std::string errorMessage;
};

class SignatureUpdater {
public:
    static SignatureUpdater& Instance() {
        static SignatureUpdater instance;
        return instance;
    }

    SignatureUpdater();
    ~SignatureUpdater();

    // Start background polling worker
    bool Start(const std::string& serverUrl, int intervalMinutes);
    void Stop();
    bool IsRunning() const { return running_; }

    // Execute update check synchronously
    UpdateResult CheckAndUpdate(const std::string& overrideUrl = "");

    // Status queries
    std::string GetLastUpdatedIso() const;
    size_t GetLastAddedCount() const;
    std::string GetCurrentVersion() const;

private:
    void WorkerLoop();
    bool FetchJsonFromUrl(const std::string& url, std::string& outJson, std::string& outError);

    std::string serverUrl_;
    int intervalMinutes_ = 60;
    std::atomic<bool> running_{false};
    std::thread workerThread_;

    mutable std::mutex statsMutex_;
    std::string lastUpdatedIso_;
    size_t lastAddedCount_ = 0;
    std::string currentVersion_ = "2026.11.04";
};

} // namespace backend
} // namespace vantor
