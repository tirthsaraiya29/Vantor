#pragma once

#include "../common/Common.h"
#include <string>
#include <vector>
#include <mutex>

namespace vantor {
namespace scan {

struct MLDecisionTree {
    std::vector<int> leftChildren;
    std::vector<int> rightChildren;
    std::vector<int> splitIndices;
    std::vector<float> splitConditions;
    std::vector<float> baseWeights;
};

class MLEngine {
public:
    static MLEngine& Instance() {
        static MLEngine instance;
        return instance;
    }

    bool Initialize(const std::string& baseDir = "");
    bool IsModelLoaded() const { return modelLoaded_; }

    double PredictMLScore(const std::string& filePath, const uint8_t* peBuf, size_t size);
    double BlendScores(double heuristicScore, double mlScore, double mlWeight = 0.40) const;

    // Calibration Mode
    void RecordCalibrationSample(const std::string& filePath, double score, bool isSafe);
    double GetCalibratedThreshold() const;

private:
    MLEngine();
    ~MLEngine() = default;

    bool LoadModelJson(const std::string& jsonPath);
    void ExtractFeatures(const std::string& filePath, const uint8_t* peBuf, size_t size, std::vector<float>& features);

    mutable std::mutex mutex_;
    std::vector<MLDecisionTree> trees_;
    bool modelLoaded_{false};
    std::string modelName_;

    // Calibration statistics
    std::vector<double> safeScores_;
    std::vector<double> maliciousScores_;
    double calibratedThreshold_{0.75};
};

} // namespace scan
} // namespace vantor
