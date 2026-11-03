#include "IPC.h"
#include "Scanner.h"
#include "ConfigManager.h"
#include "AntiTamper.h"
#include "../common/Logger.h"
#include "../common/nlohmann/json.hpp"

using json = nlohmann::json;

namespace vantor {
namespace service {

static scan::ScanProgressInfo g_lastProgress;
static std::mutex g_progressMutex;

ServiceIPC::ServiceIPC() {
    server_ = std::make_unique<ipc::NamedPipeServer>(IPC_PIPE_NAME);
}

ServiceIPC::~ServiceIPC() {
    Stop();
}

bool ServiceIPC::Start() {
    LOG_INFO("IPC", "Starting Named Pipe IPC service on: " + Utf16ToUtf8(IPC_PIPE_NAME));
    return server_->Start([this](const std::string& req) {
        return HandleRequest(req);
    });
}

void ServiceIPC::Stop() {
    if (server_) {
        server_->Stop();
    }
    LOG_INFO("IPC", "Named Pipe IPC service stopped.");
}

std::string ServiceIPC::HandleRequest(const std::string& requestJson) {
    try {
        json req = json::parse(requestJson);
        std::string cmd = req.value("cmd", "");
        json resp;
        resp["cmd"] = cmd;
        resp["status"] = "ok";

        if (cmd == "ping") {
            resp["message"] = "pong";
            resp["time"] = NowUtcIso8601();
        }
        else if (cmd == "start_scan") {
            std::string type = req.value("type", "quick");
            std::string path = req.value("path", "");

            {
                std::lock_guard<std::mutex> lock(g_progressMutex);
                g_lastProgress = scan::ScanProgressInfo();
                g_lastProgress.sessionId = "INIT";
                g_lastProgress.filesScanned = 0;
                g_lastProgress.threatsDetected = 0;
                g_lastProgress.currentFile = "Initializing scan pipeline...";
                g_lastProgress.percentComplete = 0.0f;
                g_lastProgress.isComplete = false;
            }

            bool started = scan::Scanner::Instance().StartScan(type, path, [](const scan::ScanProgressInfo& info) {
                std::lock_guard<std::mutex> lock(g_progressMutex);
                g_lastProgress = info;
            });

            resp["started"] = started;
            resp["message"] = started ? "Scan started successfully" : "Scan already in progress";
        }
        else if (cmd == "cancel_scan") {
            scan::Scanner::Instance().CancelScan();
            resp["message"] = "Cancellation requested";
        }
        else if (cmd == "get_status") {
            std::lock_guard<std::mutex> lock(g_progressMutex);
            resp["is_scanning"] = scan::Scanner::Instance().IsScanning();
            resp["session_id"] = g_lastProgress.sessionId;
            resp["files_scanned"] = g_lastProgress.filesScanned;
            resp["threats_detected"] = g_lastProgress.threatsDetected;
            resp["current_file"] = g_lastProgress.currentFile;
            resp["percent"] = g_lastProgress.percentComplete;
            resp["is_complete"] = g_lastProgress.isComplete;
        }
        else if (cmd == "get_quarantine") {
            auto records = scan::Scanner::Instance().GetQuarantineRecords();
            json items = json::array();
            for (const auto& r : records) {
                json item;
                item["id"] = r.id;
                item["original_path"] = r.originalPath;
                item["encrypted_filename"] = r.encryptedFilename;
                item["timestamp"] = r.timestamp;
                item["sha256"] = r.sha256;
                item["sha512"] = r.sha512;
                item["threat_name"] = r.threatName;
                item["file_size"] = r.fileSizeBytes;
                items.push_back(item);
            }
            resp["records"] = items;
            resp["count"] = records.size();
        }
        else if (cmd == "restore_quarantine") {
            int64_t id = req.value("id", (int64_t)0);
            std::string dest = req.value("destination", "");
            bool ok = scan::Scanner::Instance().RestoreQuarantinedFile(id, dest);
            resp["success"] = ok;
            resp["message"] = ok ? "File restored" : "Restore failed";
        }
        else if (cmd == "delete_quarantine") {
            int64_t id = req.value("id", (int64_t)0);
            bool ok = scan::Scanner::Instance().DeleteQuarantinedFile(id);
            resp["success"] = ok;
            resp["message"] = ok ? "Quarantine file deleted" : "Delete failed";
        }
        else if (cmd == "get_config") {
            resp["config"] = json::parse(config::ConfigManager::Instance().ToJson());
        }
        else if (cmd == "update_config") {
            if (req.contains("config")) {
                bool ok = config::ConfigManager::Instance().FromJson(req["config"].dump());
                if (ok) config::ConfigManager::Instance().Save();
                resp["success"] = ok;
            }
        }
        else if (cmd == "check_integrity") {
            auto alert = antitamper::AntiTamper::Instance().RunComprehensiveIntegrityCheck();
            resp["tampered"] = alert.tampered;
            resp["reason"] = alert.reason;
            resp["target"] = alert.affectedTarget;
            resp["mechanism"] = alert.detectionMechanism;
        }
        else {
            resp["status"] = "error";
            resp["error"] = "Unknown command: " + cmd;
        }

        return resp.dump();
    } catch (const std::exception& e) {
        json err;
        err["status"] = "error";
        err["error"] = e.what();
        return err.dump();
    }
}

} // namespace service
} // namespace vantor
