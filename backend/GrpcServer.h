#pragma once

#include "../common/Common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <functional>

namespace vantor {
namespace backend {

struct GrpcServerOptions {
    std::string host = "127.0.0.1";
    int port = 50051;
    bool enableTls = false;
    std::string certPath;
    std::string keyPath;
    std::string authToken = "vantor-secure-token-v2";
};

class VantorGrpcServer {
public:
    VantorGrpcServer(GrpcServerOptions options = {});
    ~VantorGrpcServer();

    bool Start();
    void Stop();
    void WaitForShutdown();
    bool IsRunning() const { return running_; }

    // RPC Handler implementations
    std::string ProcessRpc(const std::string& method, const std::string& requestPayloadJson, const std::string& clientToken = "");

private:
    void ServerWorker();

    GrpcServerOptions options_;
    std::atomic<bool> running_{false};
    std::thread workerThread_;
    SOCKET listenSocket_ = INVALID_SOCKET;
};

} // namespace backend
} // namespace vantor
