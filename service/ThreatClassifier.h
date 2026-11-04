#pragma once

#include "../common/Common.h"
#include <string>
#include <vector>
#include <mutex>

namespace vantor {
namespace scan {

struct FamilyRule {
    std::string name;
    std::string category;
    std::string severity;
    int minMatches = 2;
    std::vector<std::string> stringPatterns;
    std::vector<std::vector<uint8_t>> bytePatterns;
};

class ThreatClassifier {
public:
    static ThreatClassifier& Instance() {
        static ThreatClassifier instance;
        return instance;
    }

    bool Initialize(const std::string& baseDir = "");
    std::string ClassifyThreat(const std::string& filePath, const uint8_t* data, size_t size);

private:
    ThreatClassifier();
    ~ThreatClassifier() = default;

    void LoadDefaultRules();
    bool LoadRulesFromJson(const std::string& jsonPath);
    static std::vector<uint8_t> ParseHexPattern(const std::string& hexStr);

    mutable std::mutex mutex_;
    std::vector<FamilyRule> rules_;
    bool initialized_{false};
};

} // namespace scan
} // namespace vantor
