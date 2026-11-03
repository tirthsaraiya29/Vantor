#include "GrpcServer.h"
#include "SignatureStore.h"
#include "../common/NamedPipe.h"
#include "../common/Logger.h"
#include "../common/nlohmann/json.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;

namespace vantor {
namespace backend {

VantorGrpcServer::VantorGrpcServer(GrpcServerOptions options)
    : options_(std::move(options)) {}

VantorGrpcServer::~VantorGrpcServer() {
    Stop();
}

bool VantorGrpcServer::Start() {
    if (running_.exchange(true)) return true;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_ERROR("GrpcServer", "WSAStartup failed.");
        running_ = false;
        return false;
    }

    listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket_ == INVALID_SOCKET) {
        LOG_ERROR("GrpcServer", "socket() failed: " + std::to_string(WSAGetLastError()));
        WSACleanup();
        running_ = false;
        return false;
    }

    int opt = 1;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(static_cast<u_short>(options_.port));
    inet_pton(AF_INET, options_.host.c_str(), &serverAddr.sin_addr);

    if (bind(listenSocket_, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        LOG_ERROR("GrpcServer", "bind() failed on " + options_.host + ":" + std::to_string(options_.port) + " : " + std::to_string(WSAGetLastError()));
        closesocket(listenSocket_);
        WSACleanup();
        running_ = false;
        return false;
    }

    if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
        LOG_ERROR("GrpcServer", "listen() failed: " + std::to_string(WSAGetLastError()));
        closesocket(listenSocket_);
        WSACleanup();
        running_ = false;
        return false;
    }

    workerThread_ = std::thread(&VantorGrpcServer::ServerWorker, this);
    LOG_INFO("GrpcServer", "Vantor gRPC Server listening on " + options_.host + ":" + std::to_string(options_.port));
    return true;
}

void VantorGrpcServer::Stop() {
    if (!running_.exchange(false)) return;

    if (listenSocket_ != INVALID_SOCKET) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
    }

    if (workerThread_.joinable()) {
        workerThread_.join();
    }

    WSACleanup();
    LOG_INFO("GrpcServer", "Vantor gRPC Server stopped.");
}

void VantorGrpcServer::WaitForShutdown() {
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
}

std::string VantorGrpcServer::ProcessRpc(const std::string& method, const std::string& payload, const std::string& clientToken) {
    try {
        json req = payload.empty() ? json::object() : json::parse(payload);
        json resp;

        std::string effectiveToken = clientToken;
        if (effectiveToken.empty() && req.is_object()) {
            if (req.contains("token") && req["token"].is_string()) effectiveToken = req["token"].get<std::string>();
            else if (req.contains("auth_token") && req["auth_token"].is_string()) effectiveToken = req["auth_token"].get<std::string>();
        }

        auto requireAuth = [&]() -> bool {
            if (options_.authToken.empty()) return true;
            if (effectiveToken == options_.authToken) return true;
            return false;
        };

        if (method == "/vantor.VantorBackendService/UpdateSignatures" || method == "UpdateSignatures") {
            if (!requireAuth()) {
                resp["error"] = "Unauthorized: invalid or missing auth token";
                return resp.dump();
            }
            std::vector<std::string> hashes;
            if (req.contains("sha256_hashes") && req["sha256_hashes"].is_array()) {
                hashes = req["sha256_hashes"].get<std::vector<std::string>>();
            }
            size_t added = SignatureStore::Instance().BulkImport(hashes);
            resp["success"] = true;
            resp["signatures_added"] = added;
            resp["total_signatures"] = SignatureStore::Instance().GetTotalSignatures();
            resp["message"] = "Imported " + std::to_string(added) + " signatures successfully.";
            resp["index_timestamp"] = std::chrono::system_clock::now().time_since_epoch().count();
        }
        else if (method == "/vantor.VantorBackendService/SubmitTelemetry" || method == "SubmitTelemetry") {
            // Append telemetry event to JSONL
            std::string logFile = "telemetry.jsonl";
            std::ofstream out(logFile, std::ios::app);
            if (out) {
                out << req.dump() << "\n";
            }
            resp["accepted"] = true;
            resp["server_time"] = NowUtcIso8601();
        }
        else if (method == "/vantor.VantorBackendService/GetConfig" || method == "GetConfig") {
            ipc::NamedPipeClient pipeClient;
            std::string pipeResp;
            json cmd;
            cmd["cmd"] = "get_config";

            if (pipeClient.SendRequest(cmd.dump(), pipeResp)) {
                json p = json::parse(pipeResp);
                resp["config"] = p.value("config", json::object());
            } else {
                resp["config"] = json::object();
            }
            resp["version"] = "2.0.0-PROD";
            resp["total_signatures"] = SignatureStore::Instance().GetTotalSignatures();
            resp["anti_tamper_enforced"] = true;
            resp["last_updated"] = NowUtcIso8601();
        }
        else if (method == "/vantor.VantorBackendService/TriggerScan" || method == "TriggerScan") {
            if (!requireAuth()) {
                resp["error"] = "Unauthorized: invalid or missing auth token";
                return resp.dump();
            }
            ipc::NamedPipeClient pipeClient;
            json cmd;
            cmd["cmd"] = "start_scan";
            cmd["type"] = req.value("scan_type", "quick");
            cmd["path"] = req.value("target_path", "");

            std::string pipeResp;
            if (pipeClient.SendRequest(cmd.dump(), pipeResp)) {
                resp = json::parse(pipeResp);
            } else {
                resp["status"] = "error";
                resp["error"] = "Cannot communicate with Vantor Windows Service via Named Pipe.";
            }
        }
        else if (method == "/vantor.VantorBackendService/GetQuarantineList" || method == "GetQuarantineList") {
            ipc::NamedPipeClient pipeClient;
            json cmd;
            cmd["cmd"] = "get_quarantine";
            std::string pipeResp;
            if (pipeClient.SendRequest(cmd.dump(), pipeResp)) {
                resp = json::parse(pipeResp);
            } else {
                resp["records"] = json::array();
                resp["count"] = 0;
            }
        }
        else if (method == "/vantor.VantorBackendService/RestoreQuarantine" || method == "RestoreQuarantine") {
            if (!requireAuth()) {
                resp["error"] = "Unauthorized: invalid or missing auth token";
                return resp.dump();
            }
            ipc::NamedPipeClient pipeClient;
            json cmd;
            cmd["cmd"] = "restore_quarantine";
            cmd["id"] = req.value("item_id", (int64_t)0);
            cmd["destination"] = req.value("target_restore_path", "");
            std::string pipeResp;
            if (pipeClient.SendRequest(cmd.dump(), pipeResp)) {
                resp = json::parse(pipeResp);
            } else {
                resp["success"] = false;
                resp["message"] = "Service IPC error";
            }
        }
        else if (method == "/vantor.VantorBackendService/DeleteQuarantine" || method == "DeleteQuarantine") {
            if (!requireAuth()) {
                resp["error"] = "Unauthorized: invalid or missing auth token";
                return resp.dump();
            }
            ipc::NamedPipeClient pipeClient;
            json cmd;
            cmd["cmd"] = "delete_quarantine";
            cmd["id"] = req.value("item_id", (int64_t)0);
            std::string pipeResp;
            if (pipeClient.SendRequest(cmd.dump(), pipeResp)) {
                resp = json::parse(pipeResp);
            } else {
                resp["success"] = false;
                resp["message"] = "Service IPC error";
            }
        }
        else {
            resp["error"] = "Method not found: " + method;
        }

        return resp.dump();
    } catch (const std::exception& e) {
        json err;
        err["error"] = e.what();
        return err.dump();
    }
}

void VantorGrpcServer::ServerWorker() {
    while (running_) {
        SOCKET clientSocket = accept(listenSocket_, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            if (running_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            continue;
        }

        // Handle connection in a dedicated thread
        std::thread([this, clientSocket]() {
            // Set 5-second socket timeout for read/write
            DWORD timeout = 5000;
            setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

            std::string raw;
            std::vector<char> chunk(8192);
            size_t expectedContentLength = 0;
            bool headersComplete = false;
            size_t headerEndPos = std::string::npos;

            while (raw.length() < 10 * 1024 * 1024) { // 10MB safety cap
                int bytesRead = recv(clientSocket, chunk.data(), static_cast<int>(chunk.size()), 0);
                if (bytesRead <= 0) break;
                raw.append(chunk.data(), bytesRead);

                if (!headersComplete) {
                    headerEndPos = raw.find("\r\n\r\n");
                    if (headerEndPos != std::string::npos) {
                        headersComplete = true;
                        // Look for Content-Length
                        std::string lowerHeader = raw.substr(0, headerEndPos);
                        for (auto& c : lowerHeader) c = static_cast<char>(tolower(c));
                        size_t clPos = lowerHeader.find("content-length:");
                        if (clPos != std::string::npos) {
                            size_t numStart = clPos + 15;
                            while (numStart < lowerHeader.length() && lowerHeader[numStart] == ' ') numStart++;
                            size_t lineEnd = lowerHeader.find("\r\n", numStart);
                            if (lineEnd != std::string::npos) {
                                try {
                                    expectedContentLength = std::stoul(lowerHeader.substr(numStart, lineEnd - numStart));
                                } catch (...) {
                                    expectedContentLength = 0;
                                }
                            }
                        }
                    }
                }

                if (headersComplete) {
                    size_t bodyReceived = raw.length() - (headerEndPos + 4);
                    if (bodyReceived >= expectedContentLength) {
                        break;
                    }
                }
            }

            if (!raw.empty()) {
                // Browser CSRF & DNS Rebinding Mitigation:
                // Reject requests containing Origin: or cross-origin headers to prevent web pages from probing local RPC
                if (raw.find("\nOrigin:") != std::string::npos ||
                    raw.find("\r\nOrigin:") != std::string::npos ||
                    raw.find("Sec-Fetch-Site: cross-site") != std::string::npos) {
                    std::string forbid = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nCross-origin browser requests rejected.";
                    send(clientSocket, forbid.data(), static_cast<int>(forbid.length()), 0);
                    closesocket(clientSocket);
                    return;
                }

                // Extract Authorization header if present
                std::string clientToken;
                size_t authPos = raw.find("Authorization: Bearer ");
                if (authPos != std::string::npos) {
                    size_t tokenStart = authPos + 22;
                    size_t tokenEnd = raw.find("\r\n", tokenStart);
                    if (tokenEnd != std::string::npos) {
                        clientToken = raw.substr(tokenStart, tokenEnd - tokenStart);
                    }
                }

                // Parse simple HTTP/1.1 or gRPC-JSON framing
                std::string method = "GetConfig";
                std::string body;

                if (raw.rfind("POST ", 0) == 0) {
                    size_t pathEnd = raw.find(' ', 5);
                    if (pathEnd != std::string::npos) {
                        method = raw.substr(5, pathEnd - 5);
                    }
                    if (headerEndPos != std::string::npos) {
                        body = raw.substr(headerEndPos + 4);
                    }
                } else if (raw.rfind("GET ", 0) == 0) {
                    method = "GetConfig";
                } else {
                    body = raw; // Raw JSON direct RPC
                }

                std::string responseBody = ProcessRpc(method, body, clientToken);

                std::ostringstream httpResp;
                httpResp << "HTTP/1.1 200 OK\r\n"
                         << "Content-Type: application/json\r\n"
                         << "X-Content-Type-Options: nosniff\r\n"
                         << "Content-Length: " << responseBody.length() << "\r\n"
                         << "Connection: close\r\n\r\n"
                         << responseBody;

                std::string httpRespStr = httpResp.str();
                send(clientSocket, httpRespStr.data(), static_cast<int>(httpRespStr.length()), 0);
            }

            closesocket(clientSocket);
        }).detach();
    }
}

} // namespace backend
} // namespace vantor
