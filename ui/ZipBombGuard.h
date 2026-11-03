#pragma once

#include "../backend/ZipBombDetector.h"
#include <string>

namespace vantor {
namespace ui {

class ZipBombGuard {
public:
    static ZipBombGuard& Instance() {
        static ZipBombGuard instance;
        return instance;
    }

    struct GuardCheckResult {
        bool isArchive = false;
        bool isSafe = true;
        std::string warningMessage;
        double compressionRatio = 1.0;
        uint64_t uncompressedBytes = 0;
    };

    GuardCheckResult PreCheckFile(const std::string& filePath) {
        GuardCheckResult result;
        std::string lower = ToLower(filePath);

        if (!lower.ends_with(".zip") && !lower.ends_with(".jar") && !lower.ends_with(".apk")) {
            return result; // Not a target archive
        }

        result.isArchive = true;
        backend::ZipBombDetector detector;
        auto inspect = detector.InspectArchive(filePath);

        result.compressionRatio = inspect.overallCompressionRatio;
        result.uncompressedBytes = inspect.totalUncompressedBytes;

        if (inspect.verdict != backend::ZipVerdict::Safe) {
            result.isSafe = false;
            result.warningMessage = inspect.reason;
        }

        return result;
    }

private:
    ZipBombGuard() = default;
};

} // namespace ui
} // namespace vantor
