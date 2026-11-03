#include "GrpcClient.h"
#include "../common/NamedPipe.h"
#include "../common/Logger.h"
#include "../common/nlohmann/json.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <sstream>

using json = nlohmann::json;

namespace vantor {
namespace ui {

GrpcClient::GrpcClient()
    : host_("127.0.0.1"), port_(50051), authToken_("vantor-secure-token-v2") {}

void GrpcClient::Configure(const std::string& host, int port, const std::string& token) {
    host_ = host;
    port_ = port;
    authToken_ = token;
}

std::string GrpcClient::SendRpc(const std::string& method, const std::string& jsonPayload) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return "";
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return "";
    }

    // Set connection timeout (1.5 seconds)
    DWORD timeout = 1500;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(static_cast<u_short>(port_));
    inet_pton(AF_INET, host_.c_str(), &server.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&server), sizeof(server)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();

        // Fallback: Direct Local Named Pipe to Service
        ipc::NamedPipeClient pipeClient;
        if (pipeClient.Connect(1000)) {
            std::string pipeResp;
            if (pipeClient.SendRequest(jsonPayload, pipeResp)) {
                return pipeResp;
            }
        }
        return "";
    }

    std::ostringstream req;
    req << "POST /vantor.VantorBackendService/" << method << " HTTP/1.1\r\n"
        << "Host: " << host_ << ":" << port_ << "\r\n"
        << "Content-Type: application/json\r\n"
        << "x-vantor-auth: " << authToken_ << "\r\n"
        << "Content-Length: " << jsonPayload.length() << "\r\n"
        << "Connection: close\r\n\r\n"
        << jsonPayload;

    std::string reqStr = req.str();
    send(sock, reqStr.data(), static_cast<int>(reqStr.length()), 0);

    std::vector<char> buffer(64 * 1024);
    int bytes = recv(sock, buffer.data(), static_cast<int>(buffer.size()) - 1, 0);

    closesocket(sock);
    WSACleanup();

    if (bytes <= 0) return "";
    buffer[bytes] = '\0';
    std::string respRaw(buffer.data(), bytes);

    size_t bodyPos = respRaw.find("\r\n\r\n");
    if (bodyPos != std::string::npos) {
        return respRaw.substr(bodyPos + 4);
    }
    return respRaw;
}

bool GrpcClient::CheckConnection() {
    std::string r = SendRpc("GetConfig", "{}");
    return !r.empty();
}

bool GrpcClient::TriggerScan(const std::string& scanType, const std::string& customPath) {
    json j;
    j["cmd"] = "start_scan";
    j["scan_type"] = scanType;
    j["target_path"] = customPath;

    std::string res = SendRpc("TriggerScan", j.dump());
    if (res.empty()) return false;

    try {
        json parsed = json::parse(res);
        return parsed.value("started", true);
    } catch (...) {
        return false;
    }
}

bool GrpcClient::CancelScan() {
    json j;
    j["cmd"] = "cancel_scan";
    std::string res = SendRpc("TriggerScan", j.dump());
    return !res.empty();
}

bool GrpcClient::GetScanStatus(scan::ScanProgressInfo& outInfo) {
    json j;
    j["cmd"] = "get_status";
    std::string res = SendRpc("GetConfig", j.dump());
    if (res.empty()) return false;

    try {
        json p = json::parse(res);
        outInfo.sessionId = p.value("session_id", "");
        outInfo.filesScanned = p.value("files_scanned", 0);
        outInfo.threatsDetected = p.value("threats_detected", 0);
        outInfo.currentFile = p.value("current_file", "");
        outInfo.percentComplete = p.value("percent", 0.0f);
        outInfo.isComplete = p.value("is_complete", false);
        return true;
    } catch (...) {
        return false;
    }
}

EngineConfig GrpcClient::GetConfig() {
    EngineConfig cfg;
    std::string res = SendRpc("GetConfig", "{}");
    if (res.empty()) return cfg;

    try {
        json p = json::parse(res);
        if (p.contains("config")) {
            json c = p["config"];
            cfg.rtpEnabled = c.value("rtpEnabled", true);
            cfg.heuristicThreshold = c.value("heuristicThreshold", 0.75);
            cfg.zipBombRatioLimit = c.value("zipBombRatioLimit", 10.0);
            cfg.maxArchiveUncompressedBytes = c.value("maxArchiveUncompressedBytes", 1024ULL * 1024ULL * 1024ULL);
            cfg.antiTamperEnabled = c.value("antiTamperEnabled", true);
            cfg.updateServerUrl = c.value("updateServerUrl", "https://signatures.vantor.local/v1/updates");
        }
    } catch (...) {}
    return cfg;
}

bool GrpcClient::UpdateConfig(const EngineConfig& cfg) {
    json j;
    j["cmd"] = "update_config";
    json c;
    c["rtpEnabled"] = cfg.rtpEnabled;
    c["heuristicThreshold"] = cfg.heuristicThreshold;
    c["zipBombRatioLimit"] = cfg.zipBombRatioLimit;
    c["maxArchiveUncompressedBytes"] = cfg.maxArchiveUncompressedBytes;
    c["antiTamperEnabled"] = cfg.antiTamperEnabled;
    c["updateServerUrl"] = cfg.updateServerUrl;
    c["excludedPaths"] = cfg.excludedPaths;
    j["config"] = c;

    std::string res = SendRpc("GetConfig", j.dump());
    return !res.empty();
}

std::vector<QuarantineEntry> GrpcClient::GetQuarantineList() {
    std::vector<QuarantineEntry> list;
    json j;
    j["cmd"] = "get_quarantine";
    std::string res = SendRpc("GetQuarantineList", j.dump());
    if (res.empty()) return list;

    try {
        json p = json::parse(res);
        if (p.contains("records") && p["records"].is_array()) {
            for (const auto& r : p["records"]) {
                QuarantineEntry e;
                e.id = r.value("id", (int64_t)0);
                e.originalPath = r.value("original_path", "");
                e.encryptedFilename = r.value("encrypted_filename", "");
                e.timestamp = r.value("timestamp", "");
                e.sha256 = r.value("sha256", "");
                e.sha512 = r.value("sha512", "");
                e.threatName = r.value("threat_name", "");
                e.fileSizeBytes = r.value("file_size", (uint64_t)0);
                list.push_back(e);
            }
        }
    } catch (...) {}
    return list;
}

bool GrpcClient::RestoreQuarantine(int64_t recordId, const std::string& targetPath) {
    json j;
    j["cmd"] = "restore_quarantine";
    j["id"] = recordId;
    j["destination"] = targetPath;
    std::string res = SendRpc("RestoreQuarantine", j.dump());
    if (res.empty()) return false;
    try {
        json p = json::parse(res);
        return p.value("success", false);
    } catch (...) {
        return false;
    }
}

bool GrpcClient::DeleteQuarantine(int64_t recordId) {
    json j;
    j["cmd"] = "delete_quarantine";
    j["id"] = recordId;
    std::string res = SendRpc("DeleteQuarantine", j.dump());
    if (res.empty()) return false;
    try {
        json p = json::parse(res);
        return p.value("success", false);
    } catch (...) {
        return false;
    }
}

bool GrpcClient::TriggerSignatureUpdate(const std::vector<std::string>& hashes, int& addedCount) {
    json j;
    j["sha256_hashes"] = hashes;
    std::string res = SendRpc("UpdateSignatures", j.dump());
    if (res.empty()) return false;
    try {
        json p = json::parse(res);
        addedCount = p.value("signatures_added", 0);
        return p.value("success", false);
    } catch (...) {
        return false;
    }
}

} // namespace ui
} // namespace vantor
