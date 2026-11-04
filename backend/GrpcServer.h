#pragma once

#include "../common/Common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <functional>
#include <mutex>
#include <chrono>

namespace vantor {
namespace backend {

// Token bucket rate limiter for REST API endpoints
class RateLimiter {
public:
    RateLimiter(double refillRatePerSec = 10.0, double maxTokens = 60.0)
        : refillRate_(refillRatePerSec), maxTokens_(maxTokens), tokens_(maxTokens),
          lastRefill_(std::chrono::steady_clock::now()) {}

    bool Consume() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();
        double elapsedSec = std::chrono::duration<double>(now - lastRefill_).count();
        lastRefill_ = now;
        tokens_ = (std::min)(maxTokens_, tokens_ + elapsedSec * refillRate_);

        if (tokens_ >= 1.0) {
            tokens_ -= 1.0;
            return true;
        }
        return false;
    }

private:
    std::mutex mutex_;
    double refillRate_;
    double maxTokens_;
    double tokens_;
    std::chrono::steady_clock::time_point lastRefill_;
};

struct GrpcServerOptions {
    std::string host = "127.0.0.1";
    int port = 50051;
    bool enableTls = false;
    std::string certPath;
    std::string keyPath;
    std::string authToken = "vantor-secure-token-v2";
    int maxConcurrentConnections = 16;
};

class VantorGrpcServer {
public:
    VantorGrpcServer(GrpcServerOptions options = {});
    ~VantorGrpcServer();

    bool Start();
    void Stop();
    void WaitForShutdown();
    bool IsRunning() const { return running_; }

    // RPC & REST Handler implementations
    std::string ProcessRpc(const std::string& method, const std::string& requestPayloadJson, const std::string& clientToken = "");
    std::string ProcessRest(const std::string& httpVerb, const std::string& path, const std::string& body, const std::string& clientToken, int& outStatusCode);

private:
    void ServerWorker();

    GrpcServerOptions options_;
    std::atomic<bool> running_{false};
    std::thread workerThread_;
    SOCKET listenSocket_ = INVALID_SOCKET;

    std::atomic<int> activeConnections_{0};
    RateLimiter rateLimiter_{10.0, 60.0};
};

} // namespace backend
} // namespace vantor
