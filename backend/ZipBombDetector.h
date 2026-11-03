#pragma once

#include "../common/Common.h"
#include <string>
#include <vector>
#include <cstdint>

namespace vantor {
namespace backend {

enum class ZipVerdict {
    Safe = 0,
    ZipBombDetected,
    ExcessiveCompressionRatio,
    SizeLimitExceeded,
    EntryCountLimitExceeded,
    OverlappingEntryAnomaly,
    PathTraversalAttempt,
    NestedArchiveRisk,
    CorruptArchive
};

inline const char* ZipVerdictToString(ZipVerdict v) {
    switch (v) {
        case ZipVerdict::Safe: return "SAFE";
        case ZipVerdict::ZipBombDetected: return "ZIP_BOMB_DETECTED";
        case ZipVerdict::ExcessiveCompressionRatio: return "EXCESSIVE_COMPRESSION_RATIO";
        case ZipVerdict::SizeLimitExceeded: return "SIZE_LIMIT_EXCEEDED";
        case ZipVerdict::EntryCountLimitExceeded: return "ENTRY_COUNT_LIMIT_EXCEEDED";
        case ZipVerdict::OverlappingEntryAnomaly: return "OVERLAPPING_ENTRY_ANOMALY";
        case ZipVerdict::PathTraversalAttempt: return "PATH_TRAVERSAL_ATTEMPT";
        case ZipVerdict::NestedArchiveRisk: return "NESTED_ARCHIVE_RISK";
        default: return "CORRUPT_ARCHIVE";
    }
}

struct ZipEntryInfo {
    std::string filename;
    uint64_t compressedSize = 0;
    uint64_t uncompressedSize = 0;
    double compressionRatio = 0.0;
    uint64_t localHeaderOffset = 0;
    bool isDirectory = false;
    bool isNestedArchive = false;
};

struct ZipInspectionResult {
    std::string archivePath;
    ZipVerdict verdict = ZipVerdict::Safe;
    uint64_t archiveFileSizeBytes = 0;
    uint64_t totalCompressedBytes = 0;
    uint64_t totalUncompressedBytes = 0;
    double overallCompressionRatio = 0.0;
    size_t totalEntries = 0;
    size_t nestedArchiveCount = 0;
    std::string reason;
    std::vector<ZipEntryInfo> suspiciousEntries;
};

class ZipBombDetector {
public:
    ZipBombDetector(double maxRatio = 10.0, uint64_t maxUncompressedBytes = 1024ULL * 1024ULL * 1024ULL, size_t maxEntries = 10000)
        : maxRatio_(maxRatio), maxUncompressedBytes_(maxUncompressedBytes), maxEntries_(maxEntries) {}

    // Main inspection API (fast, safe, zero-decompression)
    ZipInspectionResult InspectArchive(const std::string& archivePath);

    void SetMaxRatio(double ratio) { maxRatio_ = ratio; }
    void SetMaxUncompressedBytes(uint64_t bytes) { maxUncompressedBytes_ = bytes; }
    void SetMaxEntries(size_t maxEntries) { maxEntries_ = maxEntries; }

private:
    double maxRatio_;
    uint64_t maxUncompressedBytes_;
    size_t maxEntries_;
};

} // namespace backend
} // namespace vantor
