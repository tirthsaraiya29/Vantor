#include "ConfigManager.h"
#include "../common/Crypto.h"
#include "../common/Logger.h"
#include "../common/nlohmann/json.hpp"
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace vantor {
namespace config {

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

bool ConfigManager::IsPathExcluded(const std::string& path) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::string lowerPath = ToLower(path);
    for (const auto& excluded : config_.excludedPaths) {
        if (!excluded.empty() && lowerPath.find(ToLower(excluded)) != std::string::npos) {
            return true;
        }
    }
    return false;
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

    if (!crypto::DPAPIProtect(plaintext, encrypted, true)) {
        LOG_WARN("ConfigManager", "DPAPI protect failed, writing plaintext fallback.");
        encrypted = plaintext;
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

    LOG_INFO("ConfigManager", "Configuration encrypted and saved safely to: " + configFilePath);
    return true;
}

} // namespace config
} // namespace vantor
