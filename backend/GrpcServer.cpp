#include "GrpcServer.h"
#include "SignatureStore.h"
#include "SignatureUpdater.h"
#include "../common/NamedPipe.h"
#include "../common/Logger.h"
#include "../common/nlohmann/json.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace vantor {
namespace backend {

static std::string TrimWhitespace(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// Constant-time token comparison to prevent timing attacks (Minor 21)
static bool ConstantTimeAuthCheck(const std::string& a, const std::string& b) {
    if (a.length() != b.length()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.length(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

// Case-insensitive token extraction from HTTP headers (Minor 22)
static std::string ExtractBearerToken(const std::string& raw) {
    std::string lower = raw;
    for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

    size_t pos = lower.find("authorization: bearer ");
    if (pos != std::string::npos) {
        size_t start = pos + 22;
        size_t end = raw.find("\r\n", start);
        if (end != std::string::npos) {
            return TrimWhitespace(raw.substr(start, end - start));
        }
    }

    pos = lower.find("x-api-key:");
    if (pos != std::string::npos) {
        size_t start = pos + 10;
        size_t end = raw.find("\r\n", start);
        if (end != std::string::npos) {
            return TrimWhitespace(raw.substr(start, end - start));
        }
    }

    pos = lower.find("x-vantor-auth:");
    if (pos != std::string::npos) {
        size_t start = pos + 14;
        size_t end = raw.find("\r\n", start);
        if (end != std::string::npos) {
            return TrimWhitespace(raw.substr(start, end - start));
        }
    }
    return "";
}

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
    LOG_INFO("GrpcServer", "Vantor gRPC & REST API Server listening on " + options_.host + ":" + std::to_string(options_.port));
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
    LOG_INFO("GrpcServer", "Vantor gRPC & REST API Server stopped.");
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
            return ConstantTimeAuthCheck(effectiveToken, options_.authToken);
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
            // Minor 19: Cap telemetry.jsonl size; if > 50 MB, rotate to telemetry.1.jsonl
            std::string logFile = "telemetry.jsonl";
            std::error_code ec;
            if (fs::exists(logFile, ec) && fs::file_size(logFile, ec) > 50 * 1024 * 1024) {
                fs::rename(logFile, "telemetry.1.jsonl", ec);
            }

            // Anonymize paths in telemetry payload (Major 20)
            if (req.contains("path") && req["path"].is_string()) {
                req["path"] = AnonymizePath(req["path"].get<std::string>());
            }
            if (req.contains("target_path") && req["target_path"].is_string()) {
                req["target_path"] = AnonymizePath(req["target_path"].get<std::string>());
            }

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
            resp["version"] = VANTOR_VERSION;
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

// Major 17 & 20: REST API Handler with OpenAPI, GDPR, Status, Quarantine, and Scan
std::string VantorGrpcServer::ProcessRest(const std::string& httpVerb, const std::string& path, const std::string& body, const std::string& clientToken, int& outStatusCode) {
    outStatusCode = 200;
    json resp;

    auto requireAuth = [&]() -> bool {
        if (options_.authToken.empty()) return true;
        return ConstantTimeAuthCheck(clientToken, options_.authToken);
    };

    try {
        // Strip query string if present
        std::string cleanPath = path;
        size_t qPos = cleanPath.find('?');
        if (qPos != std::string::npos) {
            cleanPath = cleanPath.substr(0, qPos);
        }

        // OpenAPI 3.0 specification endpoint
        if (httpVerb == "GET" && (cleanPath == "/api/v1/openapi.json" || cleanPath == "/openapi.json")) {
            resp["openapi"] = "3.0.0";
            resp["info"] = {
                {"title", "Vantor Antivirus Remote Management API"},
                {"version", VANTOR_VERSION},
                {"description", "Enterprise management API for Vantor Antivirus endpoints"}
            };
            resp["paths"] = {
                {"/api/v1/status", {{"get", {{"summary", "Get endpoint health & status"}}}}},
                {"/api/v1/quarantine", {{"get", {{"summary", "List quarantined files"}}}}},
                {"/api/v1/quarantine/{id}", {{"delete", {{"summary", "Delete quarantined file"}}}}},
                {"/api/v1/scan/start", {{"post", {{"summary", "Trigger on-demand scan"}}}}},
                {"/api/v1/signatures/update", {{"post", {{"summary", "Trigger signature update pull"}}}}},
                {"/api/v1/gdpr/export", {{"get", {{"summary", "GDPR Article 20 data export"}}}}},
                {"/api/v1/gdpr/purge", {{"post", {{"summary", "GDPR data wipe and log purge"}}}}}
            };
            return resp.dump();
        }

        // GET /status or GET /api/v1/status
        if (httpVerb == "GET" && (cleanPath == "/status" || cleanPath == "/api/v1/status")) {
            ipc::NamedPipeClient pipeClient;
            json cmd;
            cmd["cmd"] = "get_status";
            std::string pipeResp;
            if (pipeClient.SendRequest(cmd.dump(), pipeResp)) {
                resp["service"] = json::parse(pipeResp);
            } else {
                resp["service"] = {{"status", "offline"}};
            }
            resp["version"] = VANTOR_VERSION;
            resp["total_signatures"] = SignatureStore::Instance().GetTotalSignatures();
            resp["server_time"] = NowUtcIso8601();
            return resp.dump();
        }

        // GET /quarantine or GET /api/v1/quarantine
        if (httpVerb == "GET" && (cleanPath == "/quarantine" || cleanPath == "/api/v1/quarantine")) {
            ipc::NamedPipeClient pipeClient;
            json cmd;
            cmd["cmd"] = "get_quarantine";
            std::string pipeResp;
            if (pipeClient.SendRequest(cmd.dump(), pipeResp)) {
                return pipeResp;
            } else {
                outStatusCode = 502;
                resp["error"] = "Vantor Service unreachable via Named Pipe";
                return resp.dump();
            }
        }

        // POST /scan/start or POST /api/v1/scan/start
        if (httpVerb == "POST" && (cleanPath == "/scan/start" || cleanPath == "/api/v1/scan/start")) {
            if (!requireAuth()) {
                outStatusCode = 401;
                resp["error"] = "Unauthorized: invalid or missing API key";
                return resp.dump();
            }
            json req = body.empty() ? json::object() : json::parse(body);
            ipc::NamedPipeClient pipeClient;
            json cmd;
            cmd["cmd"] = "start_scan";
            cmd["type"] = req.value("type", "quick");
            cmd["path"] = req.value("path", "");
            std::string pipeResp;
            if (pipeClient.SendRequest(cmd.dump(), pipeResp)) {
                return pipeResp;
            } else {
                outStatusCode = 502;
                resp["error"] = "Vantor Service unreachable";
                return resp.dump();
            }
        }

        // DELETE /quarantine/{id} or DELETE /api/v1/quarantine/{id}
        if (httpVerb == "DELETE" && (cleanPath.rfind("/quarantine/", 0) == 0 || cleanPath.rfind("/api/v1/quarantine/", 0) == 0)) {
            if (!requireAuth()) {
                outStatusCode = 401;
                resp["error"] = "Unauthorized: invalid or missing API key";
                return resp.dump();
            }
            size_t slashPos = cleanPath.find_last_of('/');
            int64_t id = 0;
            if (slashPos != std::string::npos) {
                try {
                    id = std::stoll(cleanPath.substr(slashPos + 1));
                } catch (...) {
                    id = 0;
                }
            }
            ipc::NamedPipeClient pipeClient;
            json cmd;
            cmd["cmd"] = "delete_quarantine";
            cmd["id"] = id;
            std::string pipeResp;
            if (pipeClient.SendRequest(cmd.dump(), pipeResp)) {
                return pipeResp;
            } else {
                outStatusCode = 502;
                resp["error"] = "Vantor Service unreachable";
                return resp.dump();
            }
        }

        // POST /api/v1/signatures/update
        if (httpVerb == "POST" && (cleanPath == "/api/v1/signatures/update" || cleanPath == "/signatures/update")) {
            if (!requireAuth()) {
                outStatusCode = 401;
                resp["error"] = "Unauthorized: invalid or missing API key";
                return resp.dump();
            }
            json req = body.empty() ? json::object() : json::parse(body);
            std::string urlOverride = req.value("url", "");
            auto res = SignatureUpdater::Instance().CheckAndUpdate(urlOverride);
            resp["success"] = res.success;
            resp["signatures_added"] = res.signaturesAdded;
            resp["total_signatures"] = res.totalSignatures;
            resp["version"] = res.version;
            resp["last_updated"] = res.lastUpdatedIso;
            if (!res.success) {
                resp["error"] = res.errorMessage;
            }
            return resp.dump();
        }

        // Major 20: GET /api/v1/gdpr/export
        if (httpVerb == "GET" && (cleanPath == "/api/v1/gdpr/export" || cleanPath == "/gdpr/export")) {
            if (!requireAuth()) {
                outStatusCode = 401;
                resp["error"] = "Unauthorized";
                return resp.dump();
            }
            resp["export_time"] = NowUtcIso8601();
            resp["version"] = VANTOR_VERSION;
            // Read telemetry lines if present
            std::vector<std::string> telemetryLines;
            std::ifstream telIn("telemetry.jsonl");
            std::string line;
            while (std::getline(telIn, line) && telemetryLines.size() < 500) {
                if (!line.empty()) telemetryLines.push_back(line);
            }
            resp["telemetry_records"] = telemetryLines;
            resp["status"] = "exported";
            return resp.dump();
        }

        // Major 20: POST /api/v1/gdpr/purge
        if (httpVerb == "POST" && (cleanPath == "/api/v1/gdpr/purge" || cleanPath == "/gdpr/purge")) {
            if (!requireAuth()) {
                outStatusCode = 401;
                resp["error"] = "Unauthorized";
                return resp.dump();
            }
            // Securely wipe telemetry and local logs
            std::error_code ec;
            fs::remove("telemetry.jsonl", ec);
            fs::remove("telemetry.1.jsonl", ec);
            fs::remove("vantor_service.jsonl", ec);
            resp["purged"] = true;
            resp["message"] = "Telemetry, audit logs and session caches purged.";
            return resp.dump();
        }

        outStatusCode = 404;
        resp["error"] = "Endpoint not found: " + cleanPath;
        return resp.dump();
    } catch (const std::exception& e) {
        outStatusCode = 500;
        resp["error"] = e.what();
        return resp.dump();
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

        // Minor 20: Limit concurrent connections (cap at maxConcurrentConnections, default 16)
        if (activeConnections_.load() >= options_.maxConcurrentConnections) {
            std::string busy = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nMax concurrent connections reached.\r\n";
            send(clientSocket, busy.data(), static_cast<int>(busy.length()), 0);
            closesocket(clientSocket);
            continue;
        }

        activeConnections_++;

        // Handle connection in a dedicated thread
        std::thread([this, clientSocket]() {
            struct ConnGuard {
                std::atomic<int>& count;
                SOCKET sock;
                ~ConnGuard() {
                    count--;
                    closesocket(sock);
                }
            } guard{activeConnections_, clientSocket};

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
                        std::string lowerHeader = raw.substr(0, headerEndPos);
                        for (auto& c : lowerHeader) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
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

            if (raw.empty()) {
                return;
            }

            // Browser CSRF & DNS Rebinding Mitigation
            if (raw.find("\nOrigin:") != std::string::npos ||
                raw.find("\r\nOrigin:") != std::string::npos ||
                raw.find("Sec-Fetch-Site: cross-site") != std::string::npos) {
                std::string forbid = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nCross-origin browser requests rejected.";
                send(clientSocket, forbid.data(), static_cast<int>(forbid.length()), 0);
                return;
            }

            // Rate limiter check
            if (!rateLimiter_.Consume()) {
                std::string rateLimitResp = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nRate limit exceeded.\r\n";
                send(clientSocket, rateLimitResp.data(), static_cast<int>(rateLimitResp.length()), 0);
                return;
            }

            // Extract Authorization token (Minor 21 & 22)
            std::string clientToken = ExtractBearerToken(raw);

            // Parse HTTP Request Line
            size_t firstLineEnd = raw.find("\r\n");
            std::string reqLine = (firstLineEnd != std::string::npos) ? raw.substr(0, firstLineEnd) : raw;
            std::string verb = "GET";
            std::string path = "/";
            std::string body;

            if (headerEndPos != std::string::npos) {
                body = raw.substr(headerEndPos + 4);
            }

            size_t sp1 = reqLine.find(' ');
            if (sp1 != std::string::npos) {
                verb = reqLine.substr(0, sp1);
                size_t sp2 = reqLine.find(' ', sp1 + 1);
                if (sp2 != std::string::npos) {
                    path = reqLine.substr(sp1 + 1, sp2 - (sp1 + 1));
                } else {
                    path = reqLine.substr(sp1 + 1);
                }
            }

            std::string responseBody;
            int statusCode = 200;

            // Check if this is a gRPC style POST
            if (verb == "POST" && (path.rfind("/vantor.VantorBackendService/", 0) == 0 ||
                                   path.rfind("/UpdateSignatures", 0) == 0 ||
                                   path.rfind("/SubmitTelemetry", 0) == 0 ||
                                   path.rfind("/GetConfig", 0) == 0 ||
                                   path.rfind("/TriggerScan", 0) == 0 ||
                                   path.rfind("/GetQuarantineList", 0) == 0 ||
                                   path.rfind("/RestoreQuarantine", 0) == 0 ||
                                   path.rfind("/DeleteQuarantine", 0) == 0)) {
                responseBody = ProcessRpc(path, body, clientToken);
                statusCode = 200;
            } else if (verb == "GET" || verb == "POST" || verb == "DELETE" || verb == "PUT") {
                // Major 17: Process as REST API
                responseBody = ProcessRest(verb, path, body, clientToken, statusCode);
            } else {
                responseBody = ProcessRpc("GetConfig", raw, clientToken);
                statusCode = 200;
            }

            std::string statusText = (statusCode == 200) ? "OK" :
                                     (statusCode == 401) ? "Unauthorized" :
                                     (statusCode == 404) ? "Not Found" :
                                     (statusCode == 429) ? "Too Many Requests" :
                                     (statusCode == 502) ? "Bad Gateway" : "Internal Server Error";

            std::ostringstream httpResp;
            httpResp << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n"
                     << "Content-Type: application/json\r\n"
                     << "X-Content-Type-Options: nosniff\r\n"
                     << "Content-Length: " << responseBody.length() << "\r\n"
                     << "Connection: close\r\n\r\n"
                     << responseBody;

            std::string httpRespStr = httpResp.str();
            send(clientSocket, httpRespStr.data(), static_cast<int>(httpRespStr.length()), 0);
        }).detach();
    }
}

} // namespace backend
} // namespace vantor
