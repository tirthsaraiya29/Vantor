#include "ConfigManager.h"
#include "../common/Crypto.h"
#include "../common/Logger.h"
#include "../common/nlohmann/json.hpp"
#include <fstream>
#include <filesystem>
#include <regex>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace vantor {
namespace config {

static std::string GlobToRegex(const std::string& glob) {
    std::string rx = "^";
    for (size_t i = 0; i < glob.size(); ++i) {
        char c = glob[i];
        if (c == '\\' || c == '/') {
            rx += "[\\\\/]";
        } else if (c == '*') {
            if (i + 1 < glob.size() && glob[i + 1] == '*') {
                rx += ".*";
                i++;
                if (i + 1 < glob.size() && (glob[i + 1] == '\\' || glob[i + 1] == '/')) {
                    rx += "[\\\\/]?";
                    i++;
                }
            } else {
                rx += "[^\\\\/]*";
            }
        } else if (c == '?') {
            rx += "[^\\\\/]";
        } else if (c == '.' || c == '(' || c == ')' || c == '+' || c == '[' || c == ']' ||
                   c == '{' || c == '}' || c == '^' || c == '$' || c == '|') {
            rx += "\\";
            rx += c;
        } else {
            rx += c;
        }
    }
    rx += "$";
    return rx;
}

ConfigManager::ConfigManager() {
    currentPath_ = "config.json";
}

EngineConfig ConfigManager::GetConfig() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return config_;
}

void ConfigManager::UpdateConfig(const EngineConfig& newConfig) {
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        config_ = newConfig;
    }
    Save(currentPath_);
}

bool ConfigManager::ValidateExclusionPattern(const std::string& pattern, std::string& errorMsg) {
    if (pattern.empty()) {
        errorMsg = "Pattern cannot be empty.";
        return false;
    }
    std::string raw = pattern;
    if (raw.front() == '!') {
        raw = raw.substr(1);
    }
    if (raw.empty()) {
        errorMsg = "Negation pattern must specify a target path.";
        return false;
    }
    try {
        std::string rx = GlobToRegex(raw);
        std::regex re(rx, std::regex::icase);
        return true;
    } catch (const std::exception& e) {
        errorMsg = e.what();
        return false;
    }
}

bool ConfigManager::IsPathExcluded(const std::string& path) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    bool matchedExclusion = false;

    // Check normal exclusions first
    for (const auto& pattern : config_.excludedPaths) {
        if (pattern.empty() || pattern.front() == '!') continue;

        bool matches = false;
        if (pattern.find('*') != std::string::npos || pattern.find('?') != std::string::npos) {
            try {
                std::regex re(GlobToRegex(pattern), std::regex::icase);
                matches = std::regex_match(path, re);
            } catch (...) {
                matches = false;
            }
        } else {
            matches = IsPathPrefixOf(pattern, path);
        }

        if (matches) {
            matchedExclusion = true;
            break;
        }
    }

    if (!matchedExclusion) {
        return false;
    }

    // Check negation rules (!pattern) that override exclusions
    for (const auto& pattern : config_.excludedPaths) {
        if (pattern.size() > 1 && pattern.front() == '!') {
            std::string neg = pattern.substr(1);
            bool unexcluded = false;
            if (neg.find('*') != std::string::npos || neg.find('?') != std::string::npos) {
                try {
                    std::regex re(GlobToRegex(neg), std::regex::icase);
                    unexcluded = std::regex_match(path, re);
                } catch (...) {}
            } else {
                unexcluded = IsPathPrefixOf(neg, path);
            }
            if (unexcluded) {
                return false; // Negation rule matched: file is NOT excluded
            }
        }
    }

    return true;
}

PolicyAction ConfigManager::EvaluatePolicy(const ScanResult& result) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (const auto& rule : config_.policyRules) {
        if (!rule.enabled) continue;

        if (rule.verdictMatch != "ANY") {
            std::string vStr = VerdictToString(result.verdict);
            std::string ruleV = rule.verdictMatch;
            std::transform(ruleV.begin(), ruleV.end(), ruleV.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            if (ruleV != vStr) continue;
        }

        if (!rule.threatNameRegex.empty()) {
            try {
                std::regex re(rule.threatNameRegex, std::regex::icase);
                if (!std::regex_search(result.threatDescription, re)) {
                    continue;
                }
            } catch (...) {
                continue;
            }
        }

        if (!rule.pathGlob.empty()) {
            try {
                std::regex re(GlobToRegex(rule.pathGlob), std::regex::icase);
                if (!std::regex_match(result.filePath, re) && !IsPathPrefixOf(rule.pathGlob, result.filePath)) {
                    continue;
                }
            } catch (...) {
                continue;
            }
        }

        return rule.action;
    }

    // Default policy action fallback
    if (result.verdict == ScanVerdict::Malicious) {
        return PolicyAction::Quarantine;
    }
    if (result.verdict == ScanVerdict::Suspicious) {
        return PolicyAction::Alert;
    }
    return PolicyAction::Allow;
}

void ConfigManager::AddExclusion(const std::string& path) {
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        if (std::find(config_.excludedPaths.begin(), config_.excludedPaths.end(), path) == config_.excludedPaths.end()) {
            config_.excludedPaths.push_back(path);
        }
    }
    Save(currentPath_);
}

void ConfigManager::RemoveExclusion(const std::string& path) {
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto it = std::remove(config_.excludedPaths.begin(), config_.excludedPaths.end(), path);
        config_.excludedPaths.erase(it, config_.excludedPaths.end());
    }
    Save(currentPath_);
}

std::string ConfigManager::ToJson() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json j;
    j["rtpEnabled"] = config_.rtpEnabled;
    j["heuristicThreshold"] = config_.heuristicThreshold;
    j["zipBombRatioLimit"] = config_.zipBombRatioLimit;
    j["maxArchiveUncompressedBytes"] = config_.maxArchiveUncompressedBytes;
    j["antiTamperEnabled"] = config_.antiTamperEnabled;
    j["updateServerUrl"] = config_.updateServerUrl;
    j["updateIntervalMinutes"] = config_.updateIntervalMinutes;
    j["excludedPaths"] = config_.excludedPaths;

    json rules = json::array();
    for (const auto& r : config_.policyRules) {
        json ruleJson;
        ruleJson["id"] = r.id;
        ruleJson["name"] = r.name;
        ruleJson["verdictMatch"] = r.verdictMatch;
        ruleJson["threatNameRegex"] = r.threatNameRegex;
        ruleJson["pathGlob"] = r.pathGlob;
        ruleJson["action"] = PolicyActionToString(r.action);
        ruleJson["enabled"] = r.enabled;
        rules.push_back(ruleJson);
    }
    j["policyRules"] = rules;

    j["telemetryEnabled"] = config_.telemetryEnabled;
    j["telemetryCategory"] = config_.telemetryCategory;
    j["telemetryRetentionDays"] = config_.telemetryRetentionDays;

    return j.dump(4);
}

bool ConfigManager::FromJson(const std::string& jsonString) {
    try {
        json j = json::parse(jsonString);
        std::unique_lock<std::shared_mutex> lock(mutex_);
        config_.rtpEnabled = j.value("rtpEnabled", true);
        config_.heuristicThreshold = j.value("heuristicThreshold", 0.75);
        config_.zipBombRatioLimit = j.value("zipBombRatioLimit", 10.0);
        config_.maxArchiveUncompressedBytes = j.value("maxArchiveUncompressedBytes", 1024ULL * 1024ULL * 1024ULL);
        config_.antiTamperEnabled = j.value("antiTamperEnabled", true);
        config_.updateServerUrl = j.value("updateServerUrl", "https://signatures.vantor.local/v1/updates");
        config_.updateIntervalMinutes = j.value("updateIntervalMinutes", 60);

        if (j.contains("excludedPaths") && j["excludedPaths"].is_array()) {
            config_.excludedPaths = j["excludedPaths"].get<std::vector<std::string>>();
        }

        if (j.contains("policyRules") && j["policyRules"].is_array()) {
            config_.policyRules.clear();
            for (const auto& r : j["policyRules"]) {
                PolicyRule rule;
                rule.id = r.value("id", "");
                rule.name = r.value("name", "");
                rule.verdictMatch = r.value("verdictMatch", "ANY");
                rule.threatNameRegex = r.value("threatNameRegex", "");
                rule.pathGlob = r.value("pathGlob", "");
                rule.action = StringToPolicyAction(r.value("action", "Quarantine"));
                rule.enabled = r.value("enabled", true);
                config_.policyRules.push_back(rule);
            }
        }

        config_.telemetryEnabled = j.value("telemetryEnabled", false);
        config_.telemetryCategory = j.value("telemetryCategory", "threats_only");
        config_.telemetryRetentionDays = j.value("telemetryRetentionDays", 30);

        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("ConfigManager", "Failed to parse JSON config: " + std::string(e.what()));
        return false;
    }
}

bool ConfigManager::Load(const std::string& configFilePath) {
    currentPath_ = configFilePath;
    if (!fs::exists(configFilePath)) {
        LOG_INFO("ConfigManager", "No config file found, creating default encrypted configuration.");
        return Save(configFilePath);
    }

    std::ifstream in(configFilePath, std::ios::binary);
    if (!in) {
        LOG_ERROR("ConfigManager", "Cannot open config file for reading: " + configFilePath);
        return false;
    }

    std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(in)), {});
    in.close();

    std::vector<uint8_t> decrypted;
    if (!crypto::DPAPIUnprotect(encrypted, decrypted)) {
        LOG_WARN("ConfigManager", "Failed DPAPI unprotect on config. Trying plaintext fallback.");
        decrypted = encrypted;
    }

    std::string jsonStr(decrypted.begin(), decrypted.end());
    if (FromJson(jsonStr)) {
        LOG_INFO("ConfigManager", "Configuration loaded and validated successfully.");
        return true;
    }
    return false;
}

bool ConfigManager::Save(const std::string& configFilePath) {
    currentPath_ = configFilePath;
    std::string jsonStr = ToJson();
    std::vector<uint8_t> plaintext(jsonStr.begin(), jsonStr.end());
    std::vector<uint8_t> encrypted;

    // Fail hard if DPAPI protection fails (Minor 49)
    if (!crypto::DPAPIProtect(plaintext, encrypted, true)) {
        if (!crypto::DPAPIProtect(plaintext, encrypted, false)) {
            LOG_ERROR("ConfigManager", "DPAPI encryption failed. Refusing to write unencrypted configuration.");
            return false;
        }
    }

    std::string tmpPath = configFilePath + ".tmp";
    std::ofstream out(tmpPath, std::ios::binary);
    if (!out) {
        LOG_ERROR("ConfigManager", "Failed to open temporary file for writing config: " + tmpPath);
        return false;
    }

    out.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    out.close();

    std::error_code ec;
    fs::rename(tmpPath, configFilePath, ec);
    if (ec) {
        fs::copy_file(tmpPath, configFilePath, fs::copy_options::overwrite_existing, ec);
        fs::remove(tmpPath, ec);
    }
    return true;
}

} // namespace config
} // namespace vantor
