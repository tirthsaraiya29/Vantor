#pragma once

#include "../common/Common.h"
#include <shared_mutex>
#include <vector>
#include <string>

namespace vantor {
namespace config {

class ConfigManager {
public:
    static ConfigManager& Instance() {
        static ConfigManager instance;
        return instance;
    }

    bool Load(const std::string& configFilePath = "config.json");
    bool Save(const std::string& configFilePath = "config.json");

    EngineConfig GetConfig() const;
    void UpdateConfig(const EngineConfig& newConfig);

    bool IsPathExcluded(const std::string& path) const;
    void AddExclusion(const std::string& path);
    void RemoveExclusion(const std::string& path);
    static bool ValidateExclusionPattern(const std::string& pattern, std::string& errorMsg);

    // Policy Engine Evaluation (Major 13)
    PolicyAction EvaluatePolicy(const ScanResult& result) const;

    // Export/import JSON representation
    std::string ToJson() const;
    bool FromJson(const std::string& jsonString);

private:
    ConfigManager();
    ~ConfigManager() = default;

    mutable std::shared_mutex mutex_;
    EngineConfig config_;
    std::string currentPath_;
};

} // namespace config
} // namespace vantor
