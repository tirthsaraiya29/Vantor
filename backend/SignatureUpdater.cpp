#include "SignatureUpdater.h"
#include "SignatureStore.h"
#include "../common/Logger.h"
#include "../common/Common.h"
#include "../common/nlohmann/json.hpp"

#include <windows.h>
#include <winhttp.h>
#include <sstream>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

namespace vantor {
namespace backend {

SignatureUpdater::SignatureUpdater()
    : lastUpdatedIso_(NowUtcIso8601()) {}

SignatureUpdater::~SignatureUpdater() {
    Stop();
}

bool SignatureUpdater::Start(const std::string& serverUrl, int intervalMinutes) {
    if (running_.exchange(true)) return true;

    serverUrl_ = serverUrl;
    intervalMinutes_ = (intervalMinutes > 0) ? intervalMinutes : 60;

    workerThread_ = std::thread(&SignatureUpdater::WorkerLoop, this);
    LOG_INFO("SignatureUpdater", "SignatureUpdater started with poll interval " +
             std::to_string(intervalMinutes_) + " minutes. Target: " + serverUrl_);
    return true;
}

void SignatureUpdater::Stop() {
    if (!running_.exchange(false)) return;

    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    LOG_INFO("SignatureUpdater", "SignatureUpdater stopped.");
}

std::string SignatureUpdater::GetLastUpdatedIso() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return lastUpdatedIso_;
}

size_t SignatureUpdater::GetLastAddedCount() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return lastAddedCount_;
}

std::string SignatureUpdater::GetCurrentVersion() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return currentVersion_;
}

void SignatureUpdater::WorkerLoop() {
    while (running_) {
        // Run update check
        CheckAndUpdate();

        // Sleep for interval in small increments to allow rapid shutdown
        int sleepSeconds = intervalMinutes_ * 60;
        for (int i = 0; i < sleepSeconds && running_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

bool SignatureUpdater::FetchJsonFromUrl(const std::string& url, std::string& outJson, std::string& outError) {
    if (url.empty()) {
        outError = "Empty URL";
        return false;
    }

    std::wstring wUrl = Utf8ToUtf16(url);
    URL_COMPONENTS urlComp{};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength    = (DWORD)-1;
    urlComp.dwHostNameLength  = (DWORD)-1;
    urlComp.dwUrlPathLength   = (DWORD)-1;
    urlComp.dwExtraInfoLength = (DWORD)-1;

    if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.length(), 0, &urlComp)) {
        outError = "Failed to parse URL: " + std::to_string(GetLastError());
        return false;
    }

    std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring urlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    if (urlComp.dwExtraInfoLength > 0) {
        urlPath.append(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
    }
    INTERNET_PORT port = urlComp.nPort;
    bool isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET hSession = WinHttpOpen(
        L"Vantor-SignatureUpdater/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) {
        outError = "WinHttpOpen failed: " + std::to_string(GetLastError());
        return false;
    }

    // Set connection timeouts (10s connect, 15s send/recv)
    WinHttpSetTimeouts(hSession, 10000, 10000, 15000, 15000);

    HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(), port, 0);
    if (!hConnect) {
        outError = "WinHttpConnect failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD reqFlags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        urlPath.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        reqFlags
    );

    if (!hRequest) {
        outError = "WinHttpOpenRequest failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Accept application/json and gzip
    LPCWSTR headers = L"Accept: application/json\r\nAccept-Encoding: gzip, deflate\r\n";
    WinHttpAddRequestHeaders(hRequest, headers, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    BOOL bResults = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0
    );

    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, nullptr);
    }

    if (!bResults) {
        outError = "WinHttp network transaction failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Check HTTP status code
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusSize,
        WINHTTP_NO_HEADER_INDEX
    );

    if (statusCode != 200) {
        outError = "HTTP error: status code " + std::to_string(statusCode);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Read payload
    std::string responseData;
    DWORD bytesAvailable = 0;
    std::vector<char> buffer(8192);

    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        DWORD bytesToRead = (std::min)(bytesAvailable, static_cast<DWORD>(buffer.size()));
        DWORD bytesRead = 0;
        if (WinHttpReadData(hRequest, buffer.data(), bytesToRead, &bytesRead) && bytesRead > 0) {
            responseData.append(buffer.data(), bytesRead);
        } else {
            break;
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    outJson = std::move(responseData);
    return true;
}

UpdateResult SignatureUpdater::CheckAndUpdate(const std::string& overrideUrl) {
    UpdateResult result;
    std::string targetUrl = overrideUrl.empty() ? serverUrl_ : overrideUrl;

    if (targetUrl.empty()) {
        result.success = false;
        result.errorMessage = "No update server URL configured.";
        return result;
    }

    LOG_INFO("SignatureUpdater", "Checking for signature updates at: " + targetUrl);

    std::string responseJson;
    std::string err;
    if (!FetchJsonFromUrl(targetUrl, responseJson, err)) {
        LOG_WARN("SignatureUpdater", "Failed to fetch updates from " + targetUrl + ": " + err);
        result.success = false;
        result.errorMessage = err;
        return result;
    }

    try {
        json j = json::parse(responseJson);

        std::string newVersion;
        if (j.contains("version") && j["version"].is_string()) {
            newVersion = j["version"].get<std::string>();
        }

        std::vector<std::string> newHashes;
        if (j.contains("signatures") && j["signatures"].is_array()) {
            for (const auto& item : j["signatures"]) {
                if (item.is_string()) {
                    newHashes.push_back(item.get<std::string>());
                }
            }
        }

        size_t added = 0;
        if (!newHashes.empty()) {
            added = SignatureStore::Instance().BulkImport(newHashes, true);
        }

        std::string nowIso = NowUtcIso8601();

        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            lastUpdatedIso_ = nowIso;
            lastAddedCount_ = added;
            if (!newVersion.empty()) {
                currentVersion_ = newVersion;
            }
        }

        result.success = true;
        result.signaturesAdded = added;
        result.totalSignatures = SignatureStore::Instance().GetTotalSignatures();
        result.version = currentVersion_;
        result.lastUpdatedIso = nowIso;

        LOG_INFO("SignatureUpdater", "Signature update successful: +" + std::to_string(added) +
                 " signatures. Total database signatures: " + std::to_string(result.totalSignatures));
        return result;
    } catch (const std::exception& e) {
        LOG_ERROR("SignatureUpdater", "Failed to parse signature update payload: " + std::string(e.what()));
        result.success = false;
        result.errorMessage = std::string("JSON parse error: ") + e.what();
        return result;
    }
}

} // namespace backend
} // namespace vantor
