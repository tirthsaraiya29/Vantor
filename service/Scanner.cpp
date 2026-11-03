#include "Scanner.h"
#include "ConfigManager.h"
#include "../common/Crypto.h"
#include "../common/Logger.h"
#include "../common/sqlite3.h"

#include <shlobj.h>
#include <wintrust.h>
#include <softpub.h>
#include <filesystem>
#include <fstream>
#include <thread>
#include <cmath>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

namespace vantor {
namespace scan {

// Helper to calculate Shannon entropy
static double CalculateBufferEntropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    size_t freq[256] = { 0 };
    for (size_t i = 0; i < size; ++i) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / size;
            entropy -= p * std::log2(p);
        }
    }
    return entropy; // 0.0 to 8.0
}

Scanner::Scanner() {
    quarantineDir_ = "quarantine";
    baseDir_ = ".";
}

Scanner::~Scanner() {
    CancelScan();
}

bool Scanner::Initialize(const std::string& baseDir) {
    if (!baseDir.empty()) {
        baseDir_ = baseDir;
    }
    quarantineDir_ = baseDir_ + "/quarantine";

    std::error_code ec;
    fs::create_directories(quarantineDir_, ec);

    // Initialize Quarantine Database
    sqlite3* db = nullptr;
    std::string dbPath = quarantineDir_ + "/quarantine.db";
    if (sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK) {
        const char* sql =
            "CREATE TABLE IF NOT EXISTS quarantined_files ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT, "
            "scan_id TEXT, "
            "original_path TEXT, "
            "encrypted_filename TEXT, "
            "sha256 TEXT, "
            "sha512 TEXT, "
            "threat_name TEXT, "
            "file_size INTEGER);";
        sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
        sqlite3_close(db);
    }

    LOG_INFO("Scanner", "Scanner engine initialized. Quarantine storage ready.");
    return true;
}

bool Scanner::VerifyAuthenticode(const std::wstring& filePath) {
    if (!fs::exists(filePath)) return false;

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policyGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &trustData);

    return (status == ERROR_SUCCESS);
}

double Scanner::CalculateHeuristicScore(const std::string& filePath, const std::vector<uint8_t>& peBuf) {
    int points = 0;
    std::string lowerPath = ToLower(filePath);

    // 1. Digital Signature Filter (Strongest FP mitigation)
    if (VerifyAuthenticode(Utf8ToUtf16(filePath))) {
        points -= 60; // Trusted signed binaries get massive point reduction
    } else {
        points += 20; // Unsigned executable
    }

    // 2. Contextual Path Risks
    if (lowerPath.find("\\temp\\") != std::string::npos ||
        lowerPath.find("\\appdata\\") != std::string::npos ||
        lowerPath.find("\\downloads\\") != std::string::npos) {
        points += 20;
    }

    // 3. Double Extension checks (e.g., malware.pdf.exe)
    if (lowerPath.find(".pdf.exe") != std::string::npos ||
        lowerPath.find(".docx.exe") != std::string::npos ||
        lowerPath.find(".txt.exe") != std::string::npos ||
        lowerPath.find(".jpg.exe") != std::string::npos) {
        points += 50;
    }

    // 4. PE Header structural parsing
    if (peBuf.size() >= sizeof(IMAGE_DOS_HEADER)) {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(peBuf.data());
        if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
            static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) <= peBuf.size()) {

            auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(peBuf.data() + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                // Section count anomaly
                if (nt->FileHeader.NumberOfSections > 12) points += 15;
                if (nt->FileHeader.NumberOfSections == 0) points += 35;

                // Check sections
                auto* section = IMAGE_FIRST_SECTION(nt);
                bool hasWxSection = false;
                double maxEntropy = 0.0;

                for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                    if (reinterpret_cast<const uint8_t*>(&section[i]) + sizeof(IMAGE_SECTION_HEADER) > peBuf.data() + peBuf.size())
                        break;

                    // W^X Violation: Section has both Write and Execute permissions
                    if ((section[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
                        (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                        hasWxSection = true;
                    }

                    // Suspicious packer section names
                    const char* secName = reinterpret_cast<const char*>(section[i].Name);
                    if (strncmp(secName, ".upx", 4) == 0 ||
                        strncmp(secName, ".aspack", 7) == 0 ||
                        strncmp(secName, ".vmp", 4) == 0 ||
                        strncmp(secName, ".themida", 8) == 0) {
                        points += 30;
                    }
                }

                if (hasWxSection) points += 40; // Shellcode stub / unpacked malware hallmark

                // Buffer entropy
                maxEntropy = CalculateBufferEntropy(peBuf.data(), peBuf.size());
                if (maxEntropy > 7.2) {
                    points += 25; // Heavily encrypted or packed payload
                }
            }
        }
    }

    // Clamp score to 0.0 - 1.0
    double score = static_cast<double>(points) / 100.0;
    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;
    return score;
}

ScanResult Scanner::ScanSingleFile(const std::string& filePath, const std::string& sessionId) {
    ScanResult result;
    result.filePath = filePath;

    if (config::ConfigManager::Instance().IsPathExcluded(filePath)) {
        result.verdict = ScanVerdict::Safe;
        return result;
    }

    std::error_code ec;
    result.fileSizeBytes = fs::file_size(filePath, ec);
    if (ec) {
        result.verdict = ScanVerdict::Error;
        return result;
    }

    // 1. Compute Cryptographic Hashes
    if (!crypto::ComputeFileHashes(filePath, result.sha256, result.sha512)) {
        result.verdict = ScanVerdict::Error;
        return result;
    }

    // 2. Fast Safe DB Cache Check
    {
        std::lock_guard<std::mutex> lock(safeDbMutex_);
        if (inMemorySafeCache_.count(result.sha512) > 0) {
            result.verdict = ScanVerdict::Safe;
            return result;
        }
    }

    // 3. Signature Lookup
    sqlite3* db = nullptr;
    if (sqlite3_open_v2("signatures.db", &db, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK) {
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT 1 FROM malware_hashes WHERE hash = ? LIMIT 1;";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, result.sha256.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                result.signatureHit = true;
                result.threatDescription = "Trojan.Win32.KnownSignature";
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }

    // 4. Read initial 64 KB for PE header inspection
    std::vector<uint8_t> headerBuf(64 * 1024);
    size_t bytesRead = 0;
    std::ifstream f(filePath, std::ios::binary);
    if (f) {
        f.read(reinterpret_cast<char*>(headerBuf.data()), headerBuf.size());
        bytesRead = static_cast<size_t>(f.gcount());
        headerBuf.resize(bytesRead);
    }

    // 5. Compute Heuristics
    result.heuristicScore = CalculateHeuristicScore(filePath, headerBuf);
    result.finalScore = result.heuristicScore;

    // 6. Verdict Calculation
    double threshold = config::ConfigManager::Instance().GetConfig().heuristicThreshold;
    if (result.signatureHit || result.finalScore >= threshold) {
        result.verdict = ScanVerdict::Malicious;
        if (result.threatDescription.empty()) {
            result.threatDescription = "Heuristic.HighRiskPayload";
        }
        // Auto-quarantine
        QuarantineFile(filePath, sessionId, result.sha256, result.sha512);
    } else if (result.finalScore >= 0.50) {
        result.verdict = ScanVerdict::Suspicious;
        result.threatDescription = "Suspicious.LowConfidenceIndicator";
    } else {
        result.verdict = ScanVerdict::Clean;
        std::lock_guard<std::mutex> lock(safeDbMutex_);
        inMemorySafeCache_.insert(result.sha512);
    }

    return result;
}

bool Scanner::QuarantineFile(const std::string& filePath, const std::string& sessionId,
                             const std::string& sha256, const std::string& sha512) {
    if (!fs::exists(filePath)) return false;

    // 1. Read plaintext file data
    std::ifstream in(filePath, std::ios::binary);
    if (!in) return false;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), {});
    in.close();

    // 2. Load or create DPAPI master key
    fs::path keyPath = fs::path(quarantineDir_) / "master.key";
    std::vector<uint8_t> key(32);

    if (fs::exists(keyPath)) {
        std::ifstream keyIn(keyPath, std::ios::binary);
        std::vector<uint8_t> encKey((std::istreambuf_iterator<char>(keyIn)), {});
        crypto::DPAPIUnprotect(encKey, key);
    } else {
        crypto::GenerateRandomBytes(key.data(), 32);
        std::vector<uint8_t> encKey;
        crypto::DPAPIProtect(key, encKey, true);
        std::ofstream keyOut(keyPath, std::ios::binary);
        keyOut.write(reinterpret_cast<const char*>(encKey.data()), encKey.size());
    }

    // 3. Encrypt via AES-256-GCM
    std::vector<uint8_t> ciphertext, iv, tag;
    if (!crypto::AES256GCMEncrypt(data, key, ciphertext, iv, tag)) {
        return false;
    }

    // 4. Save to quarantine directory
    fs::path originalPath(filePath);
    std::string encName = originalPath.filename().string() + "_" + sha256.substr(0, 8) + ".enc";
    fs::path dstEnc = fs::path(quarantineDir_) / encName;

    std::ofstream out(dstEnc, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    out.write(reinterpret_cast<const char*>(tag.data()), tag.size());
    out.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    out.close();

    // 5. Record metadata in SQLite
    sqlite3* db = nullptr;
    std::string dbPath = quarantineDir_ + "/quarantine.db";
    if (sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK) {
        const char* sql = "INSERT INTO quarantined_files "
                          "(timestamp, scan_id, original_path, encrypted_filename, sha256, sha512, threat_name, file_size) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            std::string ts = NowUtcIso8601();
            sqlite3_bind_text(stmt, 1, ts.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, sessionId.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, filePath.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 4, encName.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 5, sha256.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 6, sha512.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 7, "MaliciousPayload", -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 8, static_cast<sqlite3_int64>(data.size()));
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }

    // 6. Delete original file
    std::error_code ec;
    fs::remove(filePath, ec);
    LOG_ALERT("Scanner", "Quarantined threat: " + filePath, "{\"sha256\":\"" + sha256 + "\"}");
    return true;
}

std::vector<QuarantineEntry> Scanner::GetQuarantineRecords() {
    std::vector<QuarantineEntry> entries;
    sqlite3* db = nullptr;
    std::string dbPath = quarantineDir_ + "/quarantine.db";

    if (sqlite3_open_v2(dbPath.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK) {
        const char* sql = "SELECT id, timestamp, scan_id, original_path, encrypted_filename, sha256, sha512, threat_name, file_size "
                          "FROM quarantined_files ORDER BY id DESC;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                QuarantineEntry e;
                e.id = sqlite3_column_int64(stmt, 0);
                e.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                e.scanId = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                e.originalPath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
                e.encryptedFilename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
                e.sha256 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
                e.sha512 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
                e.threatName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
                e.fileSizeBytes = static_cast<uint64_t>(sqlite3_column_int64(stmt, 8));
                entries.push_back(e);
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
    return entries;
}

bool Scanner::RestoreQuarantinedFile(int64_t recordId, const std::string& destinationPath) {
    sqlite3* db = nullptr;
    std::string dbPath = quarantineDir_ + "/quarantine.db";
    std::string encName, origPath;

    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) return false;

    const char* sql = "SELECT original_path, encrypted_filename FROM quarantined_files WHERE id = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, recordId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            origPath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            encName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        }
        sqlite3_finalize(stmt);
    }

    if (encName.empty()) {
        sqlite3_close(db);
        return false;
    }

    fs::path srcEnc = fs::path(quarantineDir_) / encName;
    std::ifstream in(srcEnc, std::ios::binary);
    if (!in) {
        sqlite3_close(db);
        return false;
    }

    std::vector<uint8_t> iv(12);
    std::vector<uint8_t> tag(16);
    in.read(reinterpret_cast<char*>(iv.data()), 12);
    in.read(reinterpret_cast<char*>(tag.data()), 16);
    std::vector<uint8_t> ciphertext((std::istreambuf_iterator<char>(in)), {});
    in.close();

    fs::path keyPath = fs::path(quarantineDir_) / "master.key";
    std::ifstream keyIn(keyPath, std::ios::binary);
    std::vector<uint8_t> encKey((std::istreambuf_iterator<char>(keyIn)), {});
    std::vector<uint8_t> key;
    crypto::DPAPIUnprotect(encKey, key);

    std::vector<uint8_t> plaintext;
    if (!crypto::AES256GCMDecrypt(ciphertext, key, iv, tag, plaintext)) {
        sqlite3_close(db);
        return false;
    }

    std::string target = destinationPath.empty() ? origPath : destinationPath;
    std::ofstream out(target, std::ios::binary);
    if (!out) {
        sqlite3_close(db);
        return false;
    }
    out.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    out.close();

    // Delete record from DB
    const char* delSql = "DELETE FROM quarantined_files WHERE id = ?;";
    if (sqlite3_prepare_v2(db, delSql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, recordId);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);

    std::error_code ec;
    fs::remove(srcEnc, ec);
    LOG_INFO("Scanner", "Restored quarantined file to: " + target);
    return true;
}

bool Scanner::DeleteQuarantinedFile(int64_t recordId) {
    sqlite3* db = nullptr;
    std::string dbPath = quarantineDir_ + "/quarantine.db";
    std::string encName;

    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) return false;

    const char* sql = "SELECT encrypted_filename FROM quarantined_files WHERE id = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, recordId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            encName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }

    if (!encName.empty()) {
        fs::path srcEnc = fs::path(quarantineDir_) / encName;
        std::error_code ec;
        fs::remove(srcEnc, ec);
    }

    const char* delSql = "DELETE FROM quarantined_files WHERE id = ?;";
    if (sqlite3_prepare_v2(db, delSql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, recordId);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return true;
}

bool Scanner::StartScan(const std::string& scanType, const std::string& customPath, ProgressCallback progressCb) {
    if (isScanning_.exchange(true)) {
        return false; // Already running
    }
    cancelRequested_ = false;
    activeSessionId_ = GenerateSessionId(scanType == "quick" ? "QS" : scanType == "full" ? "FS" : "CS");

    std::thread([this, scanType, customPath, progressCb]() {
        ScanWorker(scanType, customPath, progressCb);
    }).detach();

    return true;
}

void Scanner::CancelScan() {
    cancelRequested_ = true;
}

void Scanner::ScanWorker(std::string scanType, std::string customPath, ProgressCallback progressCb) {
    LOG_INFO("Scanner", "Starting scan session: " + activeSessionId_ + " (" + scanType + ")");

    int filesScanned = 0;
    int threatsFound = 0;
    int estimatedFiles = EstimateFileCount(scanType, customPath);

    std::vector<std::wstring> targets;

    if (scanType == "quick") {
        wchar_t userProfile[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, userProfile))) {
            targets.push_back(std::wstring(userProfile) + L"\\Downloads");
            targets.push_back(std::wstring(userProfile) + L"\\Desktop");
            targets.push_back(std::wstring(userProfile) + L"\\Documents");
            targets.push_back(std::wstring(userProfile) + L"\\AppData\\Local\\Temp");
        }
    } else if (scanType == "full") {
        DWORD drives = GetLogicalDrives();
        for (int i = 0; i < 26; ++i) {
            if (drives & (1 << i)) {
                wchar_t root[4] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', 0 };
                if (GetDriveTypeW(root) == DRIVE_FIXED) {
                    targets.push_back(root);
                }
            }
        }
    } else if (scanType == "custom" && !customPath.empty()) {
        targets.push_back(Utf8ToUtf16(customPath));
    }

    for (const auto& target : targets) {
        if (cancelRequested_) break;
        TraverseDirectory(target, filesScanned, threatsFound, estimatedFiles, progressCb);
    }

    isScanning_ = false;
    ScanProgressInfo finalInfo;
    finalInfo.sessionId = activeSessionId_;
    finalInfo.filesScanned = filesScanned;
    finalInfo.threatsDetected = threatsFound;
    finalInfo.percentComplete = 100.0f;
    finalInfo.isComplete = true;

    if (progressCb) {
        progressCb(finalInfo);
    }

    LOG_INFO("Scanner", "Scan complete. Files scanned: " + std::to_string(filesScanned) +
             ", Threats: " + std::to_string(threatsFound));
}

void Scanner::TraverseDirectory(const std::wstring& root, int& scanned, int& threats, int totalEst, ProgressCallback progressCb) {
    std::error_code ec;
    if (!fs::exists(root, ec)) return;

    if (fs::is_regular_file(root, ec)) {
        if (cancelRequested_) return;
        auto res = ScanSingleFile(Utf16ToUtf8(root), activeSessionId_);
        scanned++;
        if (res.verdict == ScanVerdict::Malicious) threats++;

        if (progressCb) {
            ScanProgressInfo info;
            info.sessionId = activeSessionId_;
            info.filesScanned = scanned;
            info.threatsDetected = threats;
            info.currentFile = Utf16ToUtf8(root);
            info.percentComplete = totalEst > 0 ? (std::min)(99.0f, (static_cast<float>(scanned) / totalEst) * 100.0f) : 50.0f;
            progressCb(info);
        }
        return;
    }

    for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec)) {
        if (cancelRequested_) break;
        if (entry.is_regular_file(ec)) {
            std::string pathStr = Utf16ToUtf8(entry.path().wstring());
            auto res = ScanSingleFile(pathStr, activeSessionId_);
            scanned++;
            if (res.verdict == ScanVerdict::Malicious) threats++;

            if (progressCb && (scanned % 5 == 0 || res.verdict == ScanVerdict::Malicious)) {
                ScanProgressInfo info;
                info.sessionId = activeSessionId_;
                info.filesScanned = scanned;
                info.threatsDetected = threats;
                info.currentFile = pathStr;
                info.percentComplete = totalEst > 0 ? (std::min)(99.0f, (static_cast<float>(scanned) / totalEst) * 100.0f) : 50.0f;
                progressCb(info);
            }
        }
    }
}

int Scanner::EstimateFileCount(const std::string& scanType, const std::string& customPath) {
    (void)customPath;
    if (scanType == "quick") return 2500;
    if (scanType == "full") return 50000;
    return 1000;
}

} // namespace scan
} // namespace vantor
