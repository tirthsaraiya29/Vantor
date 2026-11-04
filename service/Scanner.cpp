#include "Scanner.h"
#include "ConfigManager.h"
#include "ThreatClassifier.h"
#include "MLEngine.h"
#include "DetonationChamber.h"
#include "ScanHistoryStore.h"
#include "../backend/SignatureStore.h"
#include "../common/Crypto.h"
#include "../common/Logger.h"
#include "../common/AuthenticodeVerifier.h"
#include "../common/sqlite3.h"

#include <shlobj.h>
#include <wintrust.h>
#include <softpub.h>
#include <filesystem>
#include <fstream>
#include <thread>
#include <cmath>
#include <algorithm>
#include <deque>
#include <queue>
#include <condition_variable>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

namespace vantor {
namespace scan {

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
    return entropy;
}

Scanner::Scanner() {
    baseDir_ = Utf16ToUtf8(GetExecutableDirectory());
    quarantineDir_ = baseDir_ + "/quarantine";
}

Scanner::~Scanner() {
    CancelScan();
    std::lock_guard<std::mutex> lock(quarantineMutex_);
    if (quarantineDb_) {
        sqlite3_close(quarantineDb_);
        quarantineDb_ = nullptr;
    }
}

bool Scanner::Initialize(const std::string& baseDir) {
    if (!baseDir.empty()) {
        baseDir_ = baseDir;
    } else {
        baseDir_ = Utf16ToUtf8(GetExecutableDirectory());
    }
    quarantineDir_ = baseDir_ + "/quarantine";

    std::error_code ec;
    fs::create_directories(quarantineDir_, ec);

    // Initialize Quarantine Database with persistent handle and WAL mode (Minor 9)
    {
        std::lock_guard<std::mutex> lock(quarantineMutex_);
        if (quarantineDb_) {
            sqlite3_close(quarantineDb_);
            quarantineDb_ = nullptr;
        }
        std::string dbPath = quarantineDir_ + "/quarantine.db";
        if (sqlite3_open(dbPath.c_str(), &quarantineDb_) == SQLITE_OK) {
            sqlite3_exec(quarantineDb_, "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;", nullptr, nullptr, nullptr);
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
            sqlite3_exec(quarantineDb_, sql, nullptr, nullptr, nullptr);
        } else {
            LOG_ERROR("Scanner", "Failed to open quarantine SQLite database.");
        }
    }

    // Initialize SignatureStore using absolute paths in baseDir if present
    std::string sigDbPath = baseDir_ + "/signatures.db";
    std::string sigIdxPath = baseDir_ + "/signatures.idx";
    if (baseDir.empty() || fs::exists(sigDbPath) || fs::exists(sigIdxPath)) {
        backend::SignatureStore::Instance().Initialize(sigDbPath, sigIdxPath);
    }

    // Initialize AI/ML, Threat Family Classifier, and Scan History Store
    ThreatClassifier::Instance().Initialize(baseDir_);
    MLEngine::Instance().Initialize(baseDir_);
    ScanHistoryStore::Instance().Initialize(baseDir_);

    LOG_INFO("Scanner", "Scanner engine initialized with multi-layer heuristics, XGBoost ML, and scan history.");
    return true;
}

bool Scanner::VerifyAuthenticode(const std::wstring& filePath) {
    return authenticode::VerifyAuthenticodeSignature(filePath);
}

double Scanner::CalculateHeuristicScore(const std::string& filePath, const std::vector<uint8_t>& peBuf) {
    int riskPoints = 0;
    bool isTrustedSigned = false;

    // 1. Digital Signature Filter (FP mitigation)
    if (VerifyAuthenticode(Utf8ToUtf16(filePath))) {
        isTrustedSigned = true;
    } else {
        riskPoints += 20; // Unsigned executable
    }

    // 2. Contextual Path Risks (Temp, AppData, Downloads)
    std::string lowerPath = ToLower(NormalizePathSeparators(filePath));
    if (lowerPath.find("\\temp\\") != std::string::npos ||
        lowerPath.find("\\appdata\\") != std::string::npos ||
        lowerPath.find("\\downloads\\") != std::string::npos) {
        riskPoints += 15;
    }

    // 3. Double Extension checks on filename ONLY (Minor 7)
    std::string filename = ToLower(fs::path(filePath).filename().string());
    if (filename.ends_with(".exe") || filename.ends_with(".scr") ||
        filename.ends_with(".com") || filename.ends_with(".pif") || filename.ends_with(".cpl")) {
        static const std::vector<std::string> deceptiveExtensions = {
            ".pdf.", ".docx.", ".doc.", ".txt.", ".jpg.", ".png.",
            ".xlsx.", ".xls.", ".mp3.", ".mp4.", ".ppt.", ".pptx.", ".zip.", ".rar."
        };
        for (const auto& deceptive : deceptiveExtensions) {
            if (filename.find(deceptive) != std::string::npos) {
                riskPoints += 50;
                break;
            }
        }
    }

    // 4. PE Header structural parsing & Major 12: Import Directory API scoring
    if (peBuf.size() >= sizeof(IMAGE_DOS_HEADER)) {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(peBuf.data());
        if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
            static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) <= peBuf.size()) {

            const uint8_t* ntBase = peBuf.data() + dos->e_lfanew;
            uint32_t ntSig = *reinterpret_cast<const uint32_t*>(ntBase);
            if (ntSig == IMAGE_NT_SIGNATURE) {
                auto* fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + sizeof(DWORD));
                WORD numSections = fileHdr->NumberOfSections;
                WORD sizeOfOptHdr = fileHdr->SizeOfOptionalHeader;

                if (numSections > 12) riskPoints += 15;
                if (numSections == 0) riskPoints += 35;

                size_t optHdrOffset = static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
                size_t sectionHdrOffset = optHdrOffset + sizeOfOptHdr;

                bool hasWxSection = false;
                std::vector<IMAGE_SECTION_HEADER> sections;
                if (sectionHdrOffset <= peBuf.size()) {
                    for (WORD i = 0; i < numSections; ++i) {
                        size_t curOffset = sectionHdrOffset + (i * sizeof(IMAGE_SECTION_HEADER));
                        if (curOffset + sizeof(IMAGE_SECTION_HEADER) > peBuf.size()) break;

                        auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(peBuf.data() + curOffset);
                        sections.push_back(*sec);

                        if ((sec->Characteristics & IMAGE_SCN_MEM_WRITE) &&
                            (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                            hasWxSection = true;
                        }

                        char secName[9] = { 0 };
                        memcpy(secName, sec->Name, 8);
                        std::string lowerSec = ToLower(secName);

                        if (lowerSec.rfind(".upx", 0) == 0 ||
                            lowerSec.rfind(".aspack", 0) == 0 ||
                            lowerSec.rfind(".vmp", 0) == 0 ||
                            lowerSec.rfind(".themida", 0) == 0) {
                            riskPoints += 30;
                        }
                    }
                }

                if (hasWxSection) riskPoints += 40;

                double maxEntropy = CalculateBufferEntropy(peBuf.data(), peBuf.size());
                if (maxEntropy > 7.4) {
                    riskPoints += 25;
                }

                // Major 12: PE Import Directory & Dangerous API Combination Reputation Scoring
                if (optHdrOffset + sizeof(WORD) <= peBuf.size()) {
                    WORD optMagic = *reinterpret_cast<const WORD*>(peBuf.data() + optHdrOffset);
                    DWORD importRva = 0;
                    DWORD importSize = 0;

                    if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                        optHdrOffset + sizeof(IMAGE_OPTIONAL_HEADER32) <= peBuf.size()) {
                        auto* opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(peBuf.data() + optHdrOffset);
                        if (opt32->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                            importRva = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                            importSize = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                        }
                    } else if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                               optHdrOffset + sizeof(IMAGE_OPTIONAL_HEADER64) <= peBuf.size()) {
                        auto* opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(peBuf.data() + optHdrOffset);
                        if (opt64->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                            importRva = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                            importSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                        }
                    }

                    if (importRva > 0 && importSize > 0) {
                        auto RvaToOffset = [&](DWORD rva) -> size_t {
                            for (const auto& sec : sections) {
                                if (rva >= sec.VirtualAddress &&
                                    rva < sec.VirtualAddress + sec.Misc.VirtualSize) {
                                    return static_cast<size_t>(sec.PointerToRawData + (rva - sec.VirtualAddress));
                                }
                            }
                            return 0;
                        };

                        size_t impOffset = RvaToOffset(importRva);
                        if (impOffset > 0 && impOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= peBuf.size()) {
                            std::unordered_set<std::string> importedApis;
                            size_t curImp = impOffset;

                            while (curImp + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= peBuf.size()) {
                                auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(peBuf.data() + curImp);
                                if (desc->Name == 0 && desc->FirstThunk == 0) break;

                                DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
                                size_t thunkOffset = RvaToOffset(thunkRva);

                                if (thunkOffset > 0) {
                                    size_t curThunk = thunkOffset;
                                    bool is64 = (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
                                    size_t step = is64 ? sizeof(uint64_t) : sizeof(uint32_t);

                                    for (int count = 0; count < 100 && curThunk + step <= peBuf.size(); ++count, curThunk += step) {
                                        uint64_t val = is64 ? *reinterpret_cast<const uint64_t*>(peBuf.data() + curThunk)
                                                            : *reinterpret_cast<const uint32_t*>(peBuf.data() + curThunk);
                                        if (val == 0) break;
                                        bool isOrdinal = is64 ? (val & 0x8000000000000000ULL) : (val & 0x80000000);
                                        if (!isOrdinal) {
                                            DWORD nameRva = static_cast<DWORD>(val & 0xFFFFFFFF);
                                            size_t nameOff = RvaToOffset(nameRva);
                                            if (nameOff > 0 && nameOff + sizeof(WORD) + 1 < peBuf.size()) {
                                                const char* apiName = reinterpret_cast<const char*>(peBuf.data() + nameOff + sizeof(WORD));
                                                size_t apiLen = strnlen(apiName, 64);
                                                std::string nameLower(apiName, apiLen);
                                                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), [](unsigned char c) {
                                                    return static_cast<char>(std::tolower(c));
                                                });
                                                importedApis.insert(nameLower);
                                            }
                                        }
                                    }
                                }
                                curImp += sizeof(IMAGE_IMPORT_DESCRIPTOR);
                            }

                            // 1. Process Injection & Remote Code Execution (+40)
                            bool hasAlloc = (importedApis.count("virtualalloc") || importedApis.count("virtualallocex") || importedApis.count("zwallocatevirtualmemory"));
                            bool hasWrite = (importedApis.count("writeprocessmemory") || importedApis.count("ntwritevirtualmemory"));
                            bool hasThread = (importedApis.count("createremotethread") || importedApis.count("ntcreatethreadex") || importedApis.count("queueuserapc") || importedApis.count("setthreadcontext"));
                            if (hasAlloc && hasWrite && hasThread) {
                                riskPoints += 40;
                            }

                            // 2. Anti-Debugging & Evasion (+15)
                            bool hasDebug = (importedApis.count("isdebuggerpresent") || importedApis.count("checkremotedebuggerpresent"));
                            bool hasNtSet = (importedApis.count("ntsetinformationthread") || importedApis.count("ntqueryinformationprocess"));
                            if (hasDebug && hasNtSet) {
                                riskPoints += 15;
                            }

                            // 3. Persistence Installation (+20)
                            bool hasReg = (importedApis.count("regsetvalueexa") || importedApis.count("regsetvalueexw") || importedApis.count("regcreatekeyexa") || importedApis.count("regcreatekeyexw"));
                            bool hasSvc = (importedApis.count("createservicew") || importedApis.count("createservicea") || importedApis.count("openscmanagerw"));
                            if (hasReg || hasSvc) {
                                riskPoints += 20;
                            }

                            // 4. Ransomware Encryption & Mass File Enumeration (+35)
                            bool hasCrypt = (importedApis.count("cryptencrypt") || importedApis.count("bcryptexportkey") || importedApis.count("cryptgenrandom") || importedApis.count("cryptacquirecontexta") || importedApis.count("cryptacquirecontextw"));
                            bool hasFileFind = (importedApis.count("findfirstfilew") || importedApis.count("findnextfilew") || importedApis.count("findfirstfilea") || importedApis.count("findfirstfileexw"));
                            if (hasCrypt && hasFileFind) {
                                riskPoints += 35;
                            }
                        }
                    }
                }
            }
        }
    }

    // 5. Script & LOLBIN Obfuscation Heuristics (Minor 6: full script read up to 4 MB)
    std::string lowerExt = ToLower(fs::path(filePath).extension().string());
    if (lowerExt == ".ps1" || lowerExt == ".bat" || lowerExt == ".cmd" ||
        lowerExt == ".vbs" || lowerExt == ".js"  || lowerExt == ".hta") {

        std::string scriptContent;
        std::error_code ec;
        uint64_t sz = fs::file_size(filePath, ec);
        if (!ec && sz > 0 && sz <= 4ULL * 1024ULL * 1024ULL) {
            std::ifstream sf(filePath, std::ios::binary);
            if (sf) {
                scriptContent.assign((std::istreambuf_iterator<char>(sf)), {});
            }
        }
        if (scriptContent.empty() && !peBuf.empty()) {
            scriptContent.assign(reinterpret_cast<const char*>(peBuf.data()), peBuf.size());
        }

        std::string lowerScript = ToLower(scriptContent);

        // Dynamic download cradles
        bool hasDownload = (
            lowerScript.find("downloadstring") != std::string::npos ||
            lowerScript.find("downloadfile") != std::string::npos ||
            lowerScript.find("invoke-webrequest") != std::string::npos ||
            lowerScript.find("iwr ") != std::string::npos ||
            (lowerScript.find("certutil") != std::string::npos &&
             (lowerScript.find("-urlcache") != std::string::npos || lowerScript.find("-split") != std::string::npos)) ||
            (lowerScript.find("bitsadmin") != std::string::npos && lowerScript.find("/transfer") != std::string::npos) ||
            lowerScript.find("msxml2.xmlhttp") != std::string::npos ||
            lowerScript.find("winhttp.winhttprequest") != std::string::npos
        );

        // Dynamic execution / hidden process cradles
        bool hasExec = (
            lowerScript.find("invoke-expression") != std::string::npos ||
            lowerScript.find("iex(") != std::string::npos ||
            lowerScript.find("iex ") != std::string::npos ||
            lowerScript.find("-windowstyle hidden") != std::string::npos ||
            lowerScript.find("-w hidden") != std::string::npos ||
            lowerScript.find("-ep bypass") != std::string::npos ||
            lowerScript.find("-executionpolicy bypass") != std::string::npos ||
            (lowerScript.find("wscript.shell") != std::string::npos && lowerScript.find(".run") != std::string::npos)
        );

        // Base64 payload encoding & multi-layer obfuscation
        bool hasBase64 = (
            lowerScript.find("frombase64string") != std::string::npos ||
            lowerScript.find("-encodedcommand") != std::string::npos ||
            lowerScript.find("-enc ") != std::string::npos ||
            lowerScript.find("frombase64transform") != std::string::npos ||
            (lowerScript.find("certutil") != std::string::npos && lowerScript.find("-decode") != std::string::npos)
        );

        // LOLBIN Weaponization
        bool hasLolbin = (
            (lowerScript.find("mshta") != std::string::npos && lowerScript.find("http") != std::string::npos) ||
            (lowerScript.find("regsvr32") != std::string::npos && lowerScript.find("/i:http") != std::string::npos) ||
            (lowerScript.find("rundll32") != std::string::npos && lowerScript.find("javascript:") != std::string::npos)
        );

        if (hasDownload && (hasExec || hasBase64)) {
            riskPoints += 75;
        } else if (hasBase64 && hasExec) {
            riskPoints += 65;
        } else if (hasLolbin) {
            riskPoints += 70;
        } else if (hasDownload) {
            riskPoints += 35;
        } else if (hasBase64) {
            riskPoints += 30;
        }

        size_t carets = std::count(scriptContent.begin(), scriptContent.end(), '^');
        size_t backticks = std::count(scriptContent.begin(), scriptContent.end(), '`');
        if (carets > 20 || backticks > 20) {
            riskPoints += 40;
        }
    }

    // Apply digital signature trust discount (Minor 8: never underflows negative)
    if (isTrustedSigned) {
        riskPoints = (std::max)(0, riskPoints - 60);
    }

    double score = static_cast<double>(riskPoints) / 100.0;
    return std::clamp(score, 0.0, 1.0);
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

    // 2. Fast Safe DB Cache Check (Minor 3: Safe verdict for verified cached files)
    {
        std::lock_guard<std::mutex> lock(safeDbMutex_);
        if (inMemorySafeCache_.count(result.sha512) > 0) {
            result.verdict = ScanVerdict::Safe;
            return result;
        }
    }

    // 3. High-Speed Signature Lookup via Bloom Filter & Memory-Mapped Index
    if (backend::SignatureStore::Instance().Contains(result.sha256)) {
        result.signatureHit = true;
        result.threatDescription = "Trojan.Win32.KnownSignature";
    }

    // 4. Read initial 64 KB for PE header & signature inspection
    std::vector<uint8_t> headerBuf(64 * 1024);
    size_t bytesRead = 0;
    std::ifstream f(filePath, std::ios::binary);
    if (f) {
        f.read(reinterpret_cast<char*>(headerBuf.data()), headerBuf.size());
        bytesRead = static_cast<size_t>(f.gcount());
        headerBuf.resize(bytesRead);
    }

    // 5. Heuristic & ML Inference (Major 3 & Major 12)
    result.heuristicScore = CalculateHeuristicScore(filePath, headerBuf);
    result.mlScore = MLEngine::Instance().PredictMLScore(filePath, headerBuf.data(), headerBuf.size());
    result.finalScore = MLEngine::Instance().BlendScores(result.heuristicScore, result.mlScore);

    // 6. Threat Family Classification (Major 16)
    std::string familyName = ThreatClassifier::Instance().ClassifyThreat(filePath, headerBuf.data(), headerBuf.size());
    if (!familyName.empty()) {
        result.threatDescription = familyName;
    }

    // 7. Sandboxed Detonation Chamber for borderline executables (Major 10)
    double threshold = config::ConfigManager::Instance().GetConfig().heuristicThreshold;
    std::string ext = ToLower(fs::path(filePath).extension().string());
    if (result.finalScore >= 0.50 && result.finalScore < threshold && (ext == ".exe" || ext == ".scr" || ext == ".com")) {
        auto detRep = DetonationChamber::Instance().DetonateSample(filePath, 4000);
        if (detRep.anomalousBehavior) {
            result.finalScore = (std::max)(result.finalScore, threshold + 0.10);
            if (result.threatDescription.empty()) {
                result.threatDescription = "Dynamic.DetonationAnomaly";
            }
        }
    }

    // 8. Verdict Determination & Policy Engine (Major 13)
    if (result.signatureHit || result.finalScore >= threshold) {
        result.verdict = ScanVerdict::Malicious;
        if (result.threatDescription.empty()) {
            if (ext == ".ps1" || ext == ".bat" || ext == ".cmd" || ext == ".vbs" || ext == ".js") {
                result.threatDescription = "Heuristic.Script.MaliciousCradle";
            } else {
                result.threatDescription = "Heuristic.HighRiskPayload";
            }
        }

        // Evaluate Policy Action
        PolicyAction action = config::ConfigManager::Instance().EvaluatePolicy(result);
        if (action == PolicyAction::Allow) {
            result.verdict = ScanVerdict::Safe;
        } else {
            if (action == PolicyAction::Quarantine || action == PolicyAction::Block) {
                QuarantineFile(filePath, sessionId, result.sha256, result.sha512, result.threatDescription);
            }
            ScanHistoryStore::Instance().RecordThreat(
                sessionId, filePath, result.threatDescription,
                VerdictToString(result.verdict), PolicyActionToString(action), result.sha256
            );
        }
    } else if (result.finalScore >= 0.50) {
        result.verdict = ScanVerdict::Suspicious;
        if (result.threatDescription.empty()) {
            result.threatDescription = "Suspicious.LowConfidenceIndicator";
        }
        PolicyAction action = config::ConfigManager::Instance().EvaluatePolicy(result);
        if (action == PolicyAction::Allow) {
            result.verdict = ScanVerdict::Safe;
        } else {
            ScanHistoryStore::Instance().RecordThreat(
                sessionId, filePath, result.threatDescription,
                VerdictToString(result.verdict), PolicyActionToString(action), result.sha256
            );
        }
    } else {
        result.verdict = ScanVerdict::Clean;
        // Minor 4: In-memory safe cache capped at 50,000 entries
        std::lock_guard<std::mutex> lock(safeDbMutex_);
        if (inMemorySafeCache_.size() >= 50000) {
            inMemorySafeCache_.clear();
        }
        inMemorySafeCache_.insert(result.sha512);
    }

    return result;
}

bool Scanner::QuarantineFile(const std::string& filePath, const std::string& sessionId,
                             const std::string& sha256In, const std::string& sha512In,
                             const std::string& threatName) {
    std::lock_guard<std::mutex> lock(quarantineMutex_);

    std::string sha256 = sha256In;
    std::string sha512 = sha512In;
    if (sha256.empty() || sha512.empty()) {
        crypto::ComputeFileHashes(filePath, sha256, sha512);
    }

    std::error_code ec;
    if (!fs::exists(filePath, ec) || !fs::is_regular_file(filePath, ec)) return false;

    uint64_t fileSize = fs::file_size(filePath, ec);
    if (ec) return false;

    constexpr uint64_t MAX_QUARANTINE_BYTES = 512ULL * 1024ULL * 1024ULL;
    if (fileSize > MAX_QUARANTINE_BYTES) {
        LOG_WARN("Scanner", "File too large for quarantine (" + std::to_string(fileSize) + " bytes): " + filePath);
        return false;
    }

    // 1. Read plaintext file data
    std::ifstream in(filePath, std::ios::binary);
    if (!in) return false;
    std::vector<uint8_t> data(static_cast<size_t>(fileSize));
    if (fileSize > 0) {
        in.read(reinterpret_cast<char*>(data.data()), fileSize);
        if (static_cast<uint64_t>(in.gcount()) != fileSize) {
            return false;
        }
    }
    in.close();

    // 2. Load or create DPAPI master key
    fs::path keyPath = fs::path(quarantineDir_) / "master.key";
    std::vector<uint8_t> key(32);

    if (fs::exists(keyPath)) {
        std::ifstream keyIn(keyPath, std::ios::binary);
        if (!keyIn) return false;
        std::vector<uint8_t> encKey((std::istreambuf_iterator<char>(keyIn)), {});
        keyIn.close();
        if (!crypto::DPAPIUnprotect(encKey, key) || key.size() != 32) {
            LOG_ERROR("Scanner", "Failed to unprotect quarantine master key.");
            return false;
        }
    } else {
        crypto::GenerateRandomBytes(key.data(), 32);
        std::vector<uint8_t> encKey;
        if (!crypto::DPAPIProtect(key, encKey, true)) {
            LOG_ERROR("Scanner", "Failed to DPAPI protect new quarantine master key.");
            return false;
        }
        std::ofstream keyOut(keyPath, std::ios::binary);
        if (!keyOut) return false;
        keyOut.write(reinterpret_cast<const char*>(encKey.data()), encKey.size());
        keyOut.close();
    }

    // 3. Encrypt via AES-256-GCM
    std::vector<uint8_t> ciphertext, iv, tag;
    bool encOk = crypto::AES256GCMEncrypt(data, key, ciphertext, iv, tag);
    SecureZeroMemory(key.data(), key.size());
    if (!encOk) {
        LOG_ERROR("Scanner", "AES256GCMEncrypt failed during quarantine.");
        return false;
    }

    // 4. Save to quarantine directory with temporary file
    fs::path originalPath(filePath);
    std::string hashSuffix = sha256.size() >= 8 ? sha256.substr(0, 8) : "vault";
    std::string encName = originalPath.filename().string() + "_" + hashSuffix + ".enc";
    fs::path dstEnc = fs::path(quarantineDir_) / encName;
    fs::path dstTmp = fs::path(quarantineDir_) / (encName + ".tmp");

    std::ofstream out(dstTmp, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    out.write(reinterpret_cast<const char*>(tag.data()), tag.size());
    if (!ciphertext.empty()) {
        out.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    }
    out.close();

    uint64_t expectedEncSize = iv.size() + tag.size() + ciphertext.size();
    if (fs::file_size(dstTmp, ec) != expectedEncSize) {
        fs::remove(dstTmp, ec);
        return false;
    }

    // 5. Transactional insert into SQLite using cached handle (Minor 9 & Minor 2)
    if (!quarantineDb_) {
        std::string dbPath = quarantineDir_ + "/quarantine.db";
        sqlite3_open(dbPath.c_str(), &quarantineDb_);
    }
    if (!quarantineDb_) {
        fs::remove(dstTmp, ec);
        return false;
    }

    bool dbSuccess = false;
    sqlite3_exec(quarantineDb_, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    const char* sql = "INSERT INTO quarantined_files "
                      "(timestamp, scan_id, original_path, encrypted_filename, sha256, sha512, threat_name, file_size) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(quarantineDb_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        std::string ts = NowUtcIso8601();
        sqlite3_bind_text(stmt, 1, ts.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, sessionId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, filePath.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, encName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, sha256.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, sha512.c_str(), -1, SQLITE_TRANSIENT);
        std::string finalThreatName = threatName.empty() ? "MaliciousPayload" : threatName;
        sqlite3_bind_text(stmt, 7, finalThreatName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 8, static_cast<sqlite3_int64>(data.size()));
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            dbSuccess = true;
        }
        sqlite3_finalize(stmt);
    }

    if (dbSuccess) {
        sqlite3_exec(quarantineDb_, "COMMIT;", nullptr, nullptr, nullptr);
    } else {
        sqlite3_exec(quarantineDb_, "ROLLBACK;", nullptr, nullptr, nullptr);
    }

    if (!dbSuccess) {
        fs::remove(dstTmp, ec);
        LOG_ERROR("Scanner", "Failed to commit quarantine record to database for: " + filePath);
        return false;
    }

    // Atomic move temp to final .enc
    fs::rename(dstTmp, dstEnc, ec);
    if (ec) {
        fs::copy_file(dstTmp, dstEnc, fs::copy_options::overwrite_existing, ec);
        fs::remove(dstTmp, ec);
    }

    // 6. Delete the original file
    fs::remove(filePath, ec);
    LOG_ALERT("Scanner", "Quarantined threat: " + filePath, "{\"sha256\":\"" + sha256 + "\"}");
    return true;
}

std::vector<QuarantineEntry> Scanner::GetQuarantineRecords() {
    std::lock_guard<std::mutex> lock(quarantineMutex_);
    std::vector<QuarantineEntry> entries;
    sqlite3* db = quarantineDb_;
    bool needClose = false;

    if (!db) {
        std::string dbPath = quarantineDir_ + "/quarantine.db";
        if (sqlite3_open_v2(dbPath.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
            return entries;
        }
        needClose = true;
    }

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

    if (needClose) {
        sqlite3_close(db);
    }
    return entries;
}

bool Scanner::RestoreQuarantinedFile(int64_t recordId, const std::string& destinationPath) {
    std::lock_guard<std::mutex> lock(quarantineMutex_);
    std::string encName, origPath;

    if (!quarantineDb_) {
        std::string dbPath = quarantineDir_ + "/quarantine.db";
        sqlite3_open(dbPath.c_str(), &quarantineDb_);
    }
    if (!quarantineDb_) return false;

    const char* sql = "SELECT original_path, encrypted_filename FROM quarantined_files WHERE id = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(quarantineDb_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, recordId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            origPath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            encName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        }
        sqlite3_finalize(stmt);
    }

    if (encName.empty() || origPath.empty()) {
        return false;
    }

    // Determine target path and validate against path traversal (Minor 10)
    std::string target = destinationPath.empty() ? origPath : destinationPath;
    if (target.find("..") != std::string::npos) {
        LOG_ALERT("Scanner", "Path traversal detected in restore path: " + target, "{}");
        return false;
    }

    std::error_code ec;
    fs::path canonTarget = fs::weakly_canonical(fs::path(target), ec);
    std::string canonStr = ToLower(canonTarget.string());

    // Security boundary: disallow restoring directly into Windows core system directories
    wchar_t winDir[MAX_PATH];
    if (GetWindowsDirectoryW(winDir, MAX_PATH)) {
        std::string winStr = ToLower(Utf16ToUtf8(winDir));
        if (canonStr.find(winStr + "\\system32") == 0 || canonStr.find(winStr + "\\syswow64") == 0) {
            LOG_ALERT("Scanner", "Path traversal / system overwrite blocked on restore: " + target, "{}");
            return false;
        }
    }

    fs::path targetPath(target);
    if (fs::exists(targetPath, ec)) {
        std::string stem = targetPath.stem().string();
        std::string fext = targetPath.extension().string();
        targetPath = targetPath.parent_path() / (stem + "_restored" + fext);
    }

    if (targetPath.has_parent_path()) {
        fs::create_directories(targetPath.parent_path(), ec);
    }

    fs::path srcEnc = fs::path(quarantineDir_) / encName;
    std::ifstream in(srcEnc, std::ios::binary);
    if (!in) return false;

    std::vector<uint8_t> iv(12);
    std::vector<uint8_t> tag(16);
    in.read(reinterpret_cast<char*>(iv.data()), 12);
    in.read(reinterpret_cast<char*>(tag.data()), 16);
    if (in.gcount() != 16) {
        return false;
    }

    std::vector<uint8_t> ciphertext((std::istreambuf_iterator<char>(in)), {});
    in.close();

    fs::path keyPath = fs::path(quarantineDir_) / "master.key";
    std::ifstream keyIn(keyPath, std::ios::binary);
    if (!keyIn) return false;
    std::vector<uint8_t> encKey((std::istreambuf_iterator<char>(keyIn)), {});
    keyIn.close();

    std::vector<uint8_t> key;
    if (!crypto::DPAPIUnprotect(encKey, key) || key.size() != 32) {
        return false;
    }

    std::vector<uint8_t> plaintext;
    bool decOk = crypto::AES256GCMDecrypt(ciphertext, key, iv, tag, plaintext);
    SecureZeroMemory(key.data(), key.size());

    if (!decOk) {
        LOG_ERROR("Scanner", "AES256GCMDecrypt failed during quarantine restoration.");
        return false;
    }

    std::ofstream out(targetPath, std::ios::binary);
    if (!out) return false;
    if (!plaintext.empty()) {
        out.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    }
    out.close();

    // Remove entry from SQLite database
    const char* delSql = "DELETE FROM quarantined_files WHERE id = ?;";
    if (sqlite3_prepare_v2(quarantineDb_, delSql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, recordId);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    fs::remove(srcEnc, ec);
    LOG_INFO("Scanner", "Restored quarantined file to: " + targetPath.string());
    return true;
}

bool Scanner::DeleteQuarantinedFile(int64_t recordId) {
    std::lock_guard<std::mutex> lock(quarantineMutex_);
    if (!quarantineDb_) {
        std::string dbPath = quarantineDir_ + "/quarantine.db";
        sqlite3_open(dbPath.c_str(), &quarantineDb_);
    }
    if (!quarantineDb_) return false;

    std::string encName;
    const char* sql = "SELECT encrypted_filename FROM quarantined_files WHERE id = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(quarantineDb_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, recordId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            encName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }

    if (!encName.empty()) {
        std::error_code ec;
        fs::path p = fs::path(quarantineDir_) / encName;
        fs::remove(p, ec);
    }

    const char* delSql = "DELETE FROM quarantined_files WHERE id = ?;";
    if (sqlite3_prepare_v2(quarantineDb_, delSql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, recordId);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    LOG_INFO("Scanner", "Permanently deleted quarantined entry ID: " + std::to_string(recordId));
    return true;
}

bool Scanner::StartScan(const std::string& scanType, const std::string& customPath, ProgressCallback progressCb) {
    if (isScanning_.exchange(true)) {
        return false;
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

// Major 2: Multi-threaded parallel scanner with work-stealing queue
void Scanner::ScanWorker(std::string scanType, std::string customPath, ProgressCallback progressCb) {
    LOG_INFO("Scanner", "Starting parallel scan session: " + activeSessionId_ + " (" + scanType + ")");
    ScanHistoryStore::Instance().RecordSessionStart(activeSessionId_, scanType);

    std::atomic<int> filesScanned{0};
    std::atomic<int> threatsFound{0};
    std::atomic<int> filesQuarantined{0};
    int estimatedFiles = EstimateFileCount(scanType, customPath);

    // Bounded Work Queue
    constexpr size_t MAX_QUEUE_DEPTH = 10000;
    struct WorkQueue {
        std::mutex mtx;
        std::condition_variable cvNotEmpty;
        std::condition_variable cvNotFull;
        std::deque<std::string> items;
        bool done = false;
    } queue;

    unsigned int workerCount = (std::max)(2u, std::thread::hardware_concurrency());
    std::vector<std::thread> workers;

    for (unsigned int i = 0; i < workerCount; ++i) {
        workers.emplace_back([this, &queue, &filesScanned, &threatsFound, &filesQuarantined, estimatedFiles, progressCb]() {
            while (true) {
                std::string path;
                {
                    std::unique_lock<std::mutex> lock(queue.mtx);
                    queue.cvNotEmpty.wait(lock, [&queue, this]() {
                        return !queue.items.empty() || queue.done || cancelRequested_;
                    });

                    if (cancelRequested_ || (queue.done && queue.items.empty())) {
                        break;
                    }

                    path = queue.items.front();
                    queue.items.pop_front();
                    queue.cvNotFull.notify_one();
                }

                auto res = ScanSingleFile(path, activeSessionId_);
                int scanned = ++filesScanned;

                if (res.verdict == ScanVerdict::Malicious) {
                    threatsFound++;
                    filesQuarantined++;
                } else if (res.verdict == ScanVerdict::Suspicious) {
                    threatsFound++;
                }

                if (progressCb && (scanned <= 10 || scanned % 10 == 0 || res.verdict == ScanVerdict::Malicious)) {
                    ScanProgressInfo info;
                    info.sessionId = activeSessionId_;
                    info.filesScanned = scanned;
                    info.threatsDetected = threatsFound.load();
                    info.filesQuarantined = filesQuarantined.load();
                    info.currentFile = path;
                    info.percentComplete = estimatedFiles > 0 ? (std::min)(99.0f, (static_cast<float>(scanned) / estimatedFiles) * 100.0f) : 50.0f;
                    info.isComplete = false;
                    progressCb(info);
                }
            }
        });
    }

    // Producer Directory Traversal Targets
    std::vector<std::wstring> targets;
    if (scanType == "quick") {
        wchar_t userProfile[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, userProfile))) {
            std::wstring profileStr(userProfile);
            if (profileStr.find(L"systemprofile") == std::wstring::npos) {
                targets.push_back(profileStr + L"\\Downloads");
                targets.push_back(profileStr + L"\\Desktop");
                targets.push_back(profileStr + L"\\Documents");
                targets.push_back(profileStr + L"\\AppData\\Local\\Temp");
            }
        }

        std::error_code ec;
        fs::path usersDir = L"C:\\Users";
        if (fs::exists(usersDir, ec)) {
            for (const auto& entry : fs::directory_iterator(usersDir, fs::directory_options::skip_permission_denied, ec)) {
                if (entry.is_directory(ec)) {
                    std::wstring name = entry.path().filename().wstring();
                    if (name != L"Public" && name != L"Default" && name != L"Default User" && name != L"All Users") {
                        fs::path p = entry.path();
                        if (fs::exists(p / L"Downloads", ec)) targets.push_back((p / L"Downloads").wstring());
                        if (fs::exists(p / L"Desktop", ec)) targets.push_back((p / L"Desktop").wstring());
                        if (fs::exists(p / L"Documents", ec)) targets.push_back((p / L"Documents").wstring());
                        if (fs::exists(p / L"AppData\\Local\\Temp", ec)) targets.push_back((p / L"AppData\\Local\\Temp").wstring());
                    }
                }
            }
        }
        targets.push_back(L"C:\\Windows\\Temp");
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

    // Traverse directories and push into work queue
    for (const auto& root : targets) {
        if (cancelRequested_) break;
        std::error_code ec;
        if (!fs::exists(root, ec)) continue;

        if (fs::is_regular_file(root, ec)) {
            std::unique_lock<std::mutex> lock(queue.mtx);
            queue.cvNotFull.wait(lock, [&queue, this]() {
                return queue.items.size() < MAX_QUEUE_DEPTH || cancelRequested_;
            });
            if (cancelRequested_) break;
            queue.items.push_back(Utf16ToUtf8(root));
            queue.cvNotEmpty.notify_one();
            continue;
        }

        auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
        auto end = fs::recursive_directory_iterator();
        while (!ec && it != end && !cancelRequested_) {
            try {
                if (it->is_regular_file(ec)) {
                    std::string pStr = Utf16ToUtf8(it->path().wstring());
                    std::unique_lock<std::mutex> lock(queue.mtx);
                    queue.cvNotFull.wait(lock, [&queue, this]() {
                        return queue.items.size() < MAX_QUEUE_DEPTH || cancelRequested_;
                    });
                    if (cancelRequested_) break;
                    queue.items.push_back(std::move(pStr));
                    queue.cvNotEmpty.notify_one();
                }
            } catch (...) {}
            it.increment(ec);
            if (ec) {
                ec.clear();
                it.pop();
            }
        }
    }

    // Notify workers traversal has completed
    {
        std::lock_guard<std::mutex> lock(queue.mtx);
        queue.done = true;
    }
    queue.cvNotEmpty.notify_all();

    for (auto& w : workers) {
        if (w.joinable()) {
            w.join();
        }
    }

    isScanning_ = false;
    std::string scanStatus = cancelRequested_ ? "CANCELLED" : "COMPLETED";
    ScanHistoryStore::Instance().RecordSessionEnd(
        activeSessionId_, filesScanned.load(), threatsFound.load(), filesQuarantined.load(), scanStatus
    );

    ScanProgressInfo finalInfo;
    finalInfo.sessionId = activeSessionId_;
    finalInfo.filesScanned = filesScanned.load();
    finalInfo.threatsDetected = threatsFound.load();
    finalInfo.filesQuarantined = filesQuarantined.load();
    finalInfo.percentComplete = 100.0f;
    finalInfo.isComplete = true;

    if (progressCb) {
        progressCb(finalInfo);
    }

    LOG_INFO("Scanner", "Parallel scan finished (" + scanStatus + "). Files scanned: " +
             std::to_string(filesScanned.load()) + ", Threats: " + std::to_string(threatsFound.load()));
}

int Scanner::EstimateFileCount(const std::string& scanType, const std::string& customPath) {
    if (scanType == "quick") return 2500;
    if (scanType == "full") return 50000;
    if (!customPath.empty()) {
        std::error_code ec;
        if (fs::is_regular_file(fs::path(Utf8ToUtf16(customPath)), ec)) return 1;
        return 500;
    }
    return 1000;
}

} // namespace scan
} // namespace vantor
