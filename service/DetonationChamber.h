#pragma once

#include "../common/Common.h"
#include <string>

namespace vantor {
namespace scan {

struct DetonationReport {
    bool executed = false;
    bool anomalousBehavior = false;
    int childProcessesSpawned = 0;
    DWORD exitCode = 0;
    uint32_t executionTimeMs = 0;
    double behaviorRiskScore = 0.0;
    std::string summary;
};

class DetonationChamber {
public:
    static DetonationChamber& Instance() {
        static DetonationChamber instance;
        return instance;
    }

    DetonationReport DetonateSample(const std::string& filePath, uint32_t timeoutMs = 5000);

private:
    DetonationChamber() = default;
    ~DetonationChamber() = default;
};

} // namespace scan
} // namespace vantor
