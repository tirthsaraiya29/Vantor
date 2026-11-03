#pragma once

#include "../common/Common.h"
#include "../service/Scanner.h"
#include <string>
#include <vector>
#include <memory>
#include <future>

namespace vantor {
namespace ui {

class GrpcClient {
public:
    static GrpcClient& Instance() {
        static GrpcClient instance;
        return instance;
    }

    void Configure(const std::string& host = "127.0.0.1", int port = 50051, const std::string& token = "vantor-secure-token-v2");

    bool CheckConnection();

    // Core Scan Operations
    bool TriggerScan(const std::string& scanType, const std::string& customPath = "");
    bool CancelScan();
    bool GetScanStatus(scan::ScanProgressInfo& outInfo);

    // Config Operations
    EngineConfig GetConfig();
    bool UpdateConfig(const EngineConfig& cfg);

    // Quarantine Operations
    std::vector<QuarantineEntry> GetQuarantineList();
    bool RestoreQuarantine(int64_t recordId, const std::string& targetPath = "");
    bool DeleteQuarantine(int64_t recordId);

    // Signature Update
    bool TriggerSignatureUpdate(const std::vector<std::string>& hashes, int& addedCount);

private:
    GrpcClient();
    ~GrpcClient() = default;

    std::string SendRpc(const std::string& method, const std::string& jsonPayload);

    std::string host_;
    int port_;
    std::string authToken_;
};

} // namespace ui
} // namespace vantor
