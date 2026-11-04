#include "MLEngine.h"
#include "../common/Logger.h"
#include "../common/nlohmann/json.hpp"
#include <fstream>
#include <filesystem>
#include <cmath>
#include <numeric>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace vantor {
namespace scan {

MLEngine::MLEngine() {
}

bool MLEngine::Initialize(const std::string& baseDir) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (modelLoaded_) return true;

    std::vector<std::string> searchPaths = {
        baseDir + "/models/bodmas.json",
        baseDir + "/models/ember.json",
        baseDir + "/models/avast.json",
        "models/bodmas.json",
        "models/ember.json",
        "models/avast.json",
        "../models/bodmas.json",
        "VantorBackend/models/bodmas.json"
    };

    for (const auto& path : searchPaths) {
        if (LoadModelJson(path)) {
            LOG_INFO("MLEngine", "XGBoost ML classification engine initialized with: " + path +
                     " (" + std::to_string(trees_.size()) + " trees)");
            modelLoaded_ = true;
            return true;
        }
    }

    LOG_INFO("MLEngine", "No pre-trained ML model JSON located. Operating in high-speed rule-based mode.");
    return false;
}

bool MLEngine::LoadModelJson(const std::string& jsonPath) {
    std::error_code ec;
    if (!fs::exists(jsonPath, ec)) return false;

    std::ifstream in(jsonPath);
    if (!in) return false;

    try {
        json j = json::parse(in);
        if (!j.contains("learner") || !j["learner"].contains("gradient_booster")) return false;

        auto& booster = j["learner"]["gradient_booster"];
        if (!booster.contains("model") || !booster["model"].contains("trees")) return false;

        auto& treesArray = booster["model"]["trees"];
        trees_.clear();

        for (const auto& t : treesArray) {
            MLDecisionTree tree;
            if (t.contains("left_children")) tree.leftChildren = t["left_children"].get<std::vector<int>>();
            if (t.contains("right_children")) tree.rightChildren = t["right_children"].get<std::vector<int>>();
            if (t.contains("split_indices")) tree.splitIndices = t["split_indices"].get<std::vector<int>>();
            if (t.contains("split_conditions")) tree.splitConditions = t["split_conditions"].get<std::vector<float>>();
            if (t.contains("base_weights")) tree.baseWeights = t["base_weights"].get<std::vector<float>>();

            if (!tree.leftChildren.empty() && tree.leftChildren.size() == tree.baseWeights.size()) {
                trees_.push_back(std::move(tree));
            }
        }

        modelName_ = fs::path(jsonPath).filename().string();
        return !trees_.empty();
    } catch (const std::exception& e) {
        LOG_WARN("MLEngine", "Failed parsing model JSON: " + std::string(e.what()));
        return false;
    }
}

void MLEngine::ExtractFeatures(const std::string& filePath, const uint8_t* peBuf, size_t size, std::vector<float>& features) {
    features.assign(2381, 0.0f); // Standard 2381-feature EMBER/BODMAS feature space

    if (!peBuf || size == 0) return;

    // Feature 0: File Size
    std::error_code ec;
    uint64_t fsz = fs::file_size(filePath, ec);
    features[0] = static_cast<float>(fsz);

    // Byte histogram (features 1 to 256)
    size_t byteFreq[256] = { 0 };
    for (size_t i = 0; i < size; ++i) {
        byteFreq[peBuf[i]]++;
    }
    for (size_t i = 0; i < 256; ++i) {
        features[1 + i] = static_cast<float>(byteFreq[i]) / static_cast<float>(size);
    }

    // Byte entropy (features 257 to 512)
    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (byteFreq[i] > 0) {
            double p = static_cast<double>(byteFreq[i]) / size;
            entropy -= p * std::log2(p);
        }
    }
    features[257] = static_cast<float>(entropy);

    // PE Header Analysis
    if (size >= sizeof(IMAGE_DOS_HEADER)) {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(peBuf);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
            static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) <= size) {

            const uint8_t* ntBase = peBuf + dos->e_lfanew;
            if (*reinterpret_cast<const uint32_t*>(ntBase) == IMAGE_NT_SIGNATURE) {
                auto* fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + sizeof(DWORD));
                features[520] = static_cast<float>(fileHdr->NumberOfSections);
                features[521] = static_cast<float>(fileHdr->TimeDateStamp);
                features[522] = static_cast<float>(fileHdr->Characteristics);

                size_t optHdrOffset = static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
                if (optHdrOffset + sizeof(WORD) <= size) {
                    WORD optMagic = *reinterpret_cast<const WORD*>(peBuf + optHdrOffset);
                    features[523] = static_cast<float>(optMagic);

                    size_t sectionHdrOffset = optHdrOffset + fileHdr->SizeOfOptionalHeader;
                    WORD numSec = fileHdr->NumberOfSections;
                    for (WORD i = 0; i < numSec && i < 10; ++i) {
                        size_t curSecOff = sectionHdrOffset + (i * sizeof(IMAGE_SECTION_HEADER));
                        if (curSecOff + sizeof(IMAGE_SECTION_HEADER) > size) break;
                        auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(peBuf + curSecOff);
                        features[600 + i * 5] = static_cast<float>(sec->Misc.VirtualSize);
                        features[601 + i * 5] = static_cast<float>(sec->SizeOfRawData);
                        features[602 + i * 5] = static_cast<float>(sec->Characteristics);
                    }
                }
            }
        }
    }
}

double MLEngine::PredictMLScore(const std::string& filePath, const uint8_t* peBuf, size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!modelLoaded_ || trees_.empty()) {
        return 0.0;
    }

    std::vector<float> features;
    ExtractFeatures(filePath, peBuf, size, features);

    double totalLogOdds = 0.0;
    for (const auto& tree : trees_) {
        int node = 0;
        while (node >= 0 && node < static_cast<int>(tree.leftChildren.size())) {
            int left = tree.leftChildren[node];
            if (left == -1) {
                // Leaf node
                totalLogOdds += tree.baseWeights[node];
                break;
            }

            int featIdx = tree.splitIndices[node];
            float featVal = (featIdx >= 0 && featIdx < static_cast<int>(features.size())) ? features[featIdx] : 0.0f;
            float threshold = tree.splitConditions[node];

            if (featVal <= threshold) {
                node = left;
            } else {
                node = tree.rightChildren[node];
            }
        }
    }

    // Sigmoid logistic function: 1.0 / (1.0 + exp(-z))
    double score = 1.0 / (1.0 + std::exp(-totalLogOdds));
    return std::clamp(score, 0.0, 1.0);
}

double MLEngine::BlendScores(double heuristicScore, double mlScore, double mlWeight) const {
    double hw = 1.0 - mlWeight;
    double blended = (heuristicScore * hw) + (mlScore * mlWeight);
    return std::clamp(blended, 0.0, 1.0);
}

void MLEngine::RecordCalibrationSample(const std::string& filePath, double score, bool isSafe) {
    (void)filePath;
    std::lock_guard<std::mutex> lock(mutex_);
    if (isSafe) {
        safeScores_.push_back(score);
    } else {
        maliciousScores_.push_back(score);
    }

    // Auto-calibrate threshold if enough samples are collected (e.g. > 20 safe files)
    if (safeScores_.size() >= 20) {
        double maxSafeScore = *std::max_element(safeScores_.begin(), safeScores_.end());
        calibratedThreshold_ = std::clamp(maxSafeScore + 0.10, 0.65, 0.90);
    }
}

double MLEngine::GetCalibratedThreshold() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return calibratedThreshold_;
}

} // namespace scan
} // namespace vantor
