#include "ThreatClassifier.h"
#include "../common/Logger.h"
#include "../common/nlohmann/json.hpp"
#include <fstream>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace vantor {
namespace scan {

ThreatClassifier::ThreatClassifier() {
    LoadDefaultRules();
}

std::vector<uint8_t> ThreatClassifier::ParseHexPattern(const std::string& hexStr) {
    std::vector<uint8_t> bytes;
    std::string clean;
    for (char c : hexStr) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            clean += c;
        }
    }
    if (clean.size() < 2 || clean.size() % 2 != 0) return bytes;
    for (size_t i = 0; i < clean.size(); i += 2) {
        std::string byteStr = clean.substr(i, 2);
        uint8_t b = static_cast<uint8_t>(std::strtoul(byteStr.c_str(), nullptr, 16));
        bytes.push_back(b);
    }
    return bytes;
}

void ThreatClassifier::LoadDefaultRules() {
    rules_.clear();

    FamilyRule emotet;
    emotet.name = "Trojan.Win32.Emotet";
    emotet.category = "Trojan / Downloader";
    emotet.severity = "CRITICAL";
    emotet.minMatches = 1;
    emotet.stringPatterns = { "cookie_str", "powershell -w hidden -enc", "geodo" };
    emotet.bytePatterns = { ParseHexPattern("E5 8B 4D 0C 85 C9 74") };
    rules_.push_back(emotet);

    FamilyRule cs;
    cs.name = "Backdoor.Win32.CobaltStrike";
    cs.category = "Command & Control / Beacon";
    cs.severity = "CRITICAL";
    cs.minMatches = 1;
    cs.stringPatterns = { "beacon.dll", "ReflectiveLoader", "application/octet-stream" };
    cs.bytePatterns = { ParseHexPattern("FC 48 83 E4 F0 E8 C0") };
    rules_.push_back(cs);

    FamilyRule mimikatz;
    mimikatz.name = "HackTool.Win32.Mimikatz";
    mimikatz.category = "Credential Access";
    mimikatz.severity = "CRITICAL";
    mimikatz.minMatches = 1;
    mimikatz.stringPatterns = { "sekurlsa::logonpasswords", "lsadump::sam", "privilege::debug", "gentilkiwi" };
    rules_.push_back(mimikatz);

    FamilyRule lockbit;
    lockbit.name = "Ransom.Win32.LockBit";
    lockbit.category = "Ransomware";
    lockbit.severity = "CRITICAL";
    lockbit.minMatches = 1;
    lockbit.stringPatterns = { "Restore-My-Files.txt", ".lockbit", "vssadmin delete shadows /all /quiet" };
    rules_.push_back(lockbit);

    FamilyRule tesla;
    tesla.name = "Spyware.Win32.AgentTesla";
    tesla.category = "InfoStealer / Keylogger";
    tesla.severity = "HIGH";
    tesla.minMatches = 1;
    tesla.stringPatterns = { "AgentTesla", "smtp.mail.", "webbrowserpassview", "password_recovery" };
    rules_.push_back(tesla);

    FamilyRule trickbot;
    trickbot.name = "Trojan.Win32.TrickBot";
    trickbot.category = "Banking Trojan";
    trickbot.severity = "CRITICAL";
    trickbot.minMatches = 1;
    trickbot.stringPatterns = { "pwgrab64", "networkdll64", "mailsearcher64", "wormdll64" };
    rules_.push_back(trickbot);

    initialized_ = true;
}

bool ThreatClassifier::LoadRulesFromJson(const std::string& jsonPath) {
    std::error_code ec;
    if (!fs::exists(jsonPath, ec)) return false;

    std::ifstream in(jsonPath);
    if (!in) return false;

    try {
        json j = json::parse(in);
        if (!j.contains("families") || !j["families"].is_array()) return false;

        std::vector<FamilyRule> newRules;
        for (const auto& item : j["families"]) {
            FamilyRule rule;
            rule.name = item.value("name", "Malware.Generic");
            rule.category = item.value("category", "Trojan");
            rule.severity = item.value("severity", "HIGH");
            rule.minMatches = item.value("min_matches", 1);

            if (item.contains("patterns") && item["patterns"].is_array()) {
                for (const auto& p : item["patterns"]) {
                    std::string patStr = p.get<std::string>();
                    // If pattern looks like hex bytes
                    if (patStr.find(' ') != std::string::npos && patStr.size() >= 5 &&
                        std::all_of(patStr.begin(), patStr.end(), [](char c) {
                            return std::isxdigit(static_cast<unsigned char>(c)) || c == ' ';
                        })) {
                        auto bp = ParseHexPattern(patStr);
                        if (!bp.empty()) rule.bytePatterns.push_back(bp);
                    } else {
                        rule.stringPatterns.push_back(patStr);
                    }
                }
            }
            newRules.push_back(rule);
        }

        if (!newRules.empty()) {
            rules_ = std::move(newRules);
            LOG_INFO("ThreatClassifier", "Loaded " + std::to_string(rules_.size()) + " malware family definitions from: " + jsonPath);
            return true;
        }
    } catch (const std::exception& e) {
        LOG_WARN("ThreatClassifier", "Failed to parse families.json: " + std::string(e.what()));
    }
    return false;
}

bool ThreatClassifier::Initialize(const std::string& baseDir) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> searchPaths = {
        baseDir + "/families.json",
        "families.json",
        "../families.json"
    };

    for (const auto& p : searchPaths) {
        if (LoadRulesFromJson(p)) {
            return true;
        }
    }

    LoadDefaultRules();
    return true;
}

static bool BufferContainsBytes(const uint8_t* haystack, size_t haystackLen, const uint8_t* needle, size_t needleLen) {
    if (needleLen == 0 || haystackLen < needleLen) return false;
    auto it = std::search(haystack, haystack + haystackLen, needle, needle + needleLen);
    return it != (haystack + haystackLen);
}

static bool BufferContainsIcaseString(const uint8_t* haystack, size_t haystackLen, const std::string& str) {
    if (str.empty() || haystackLen < str.size()) return false;
    auto it = std::search(
        haystack, haystack + haystackLen,
        str.begin(), str.end(),
        [](uint8_t h, char n) {
            return std::tolower(static_cast<unsigned char>(h)) == std::tolower(static_cast<unsigned char>(n));
        }
    );
    return it != (haystack + haystackLen);
}

std::string ThreatClassifier::ClassifyThreat(const std::string& filePath, const uint8_t* data, size_t size) {
    (void)filePath;
    if (!data || size == 0) return "";

    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& rule : rules_) {
        int matches = 0;

        for (const auto& s : rule.stringPatterns) {
            if (BufferContainsIcaseString(data, size, s)) {
                matches++;
                if (matches >= rule.minMatches) {
                    return rule.name;
                }
            }
        }

        for (const auto& bp : rule.bytePatterns) {
            if (BufferContainsBytes(data, size, bp.data(), bp.size())) {
                matches++;
                if (matches >= rule.minMatches) {
                    return rule.name;
                }
            }
        }
    }

    return "";
}

} // namespace scan
} // namespace vantor
