#include "ZipBombDetector.h"
#include "../common/Logger.h"

#include <fstream>
#include <filesystem>
#include <unordered_set>
#include <algorithm>
#include <cstring>

namespace fs = std::filesystem;

namespace vantor {
namespace backend {

#pragma pack(push, 1)
struct ZipEOCD {
    uint32_t signature; // 0x06054b50
    uint16_t diskNumber;
    uint16_t cdStartDisk;
    uint16_t totalEntriesDisk;
    uint16_t totalEntries;
    uint32_t cdSizeBytes;
    uint32_t cdOffset;
    uint16_t commentLength;
};

struct Zip64Locator {
    uint32_t signature; // 0x07064b50
    uint32_t cdDiskNumber;
    uint64_t eocd64Offset;
    uint32_t totalDisks;
};

struct Zip64EOCD {
    uint32_t signature; // 0x06064b50
    uint64_t recordSize;
    uint16_t versionMadeBy;
    uint16_t versionNeeded;
    uint32_t diskNumber;
    uint32_t cdStartDisk;
    uint64_t totalEntriesDisk;
    uint64_t totalEntries;
    uint64_t cdSizeBytes;
    uint64_t cdOffset;
};

struct ZipCentralDirHeader {
    uint32_t signature; // 0x02014b50
    uint16_t versionMadeBy;
    uint16_t versionNeeded;
    uint16_t flags;
    uint16_t compressionMethod;
    uint16_t lastModTime;
    uint16_t lastModDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t filenameLength;
    uint16_t extraFieldLength;
    uint16_t commentLength;
    uint16_t diskNumberStart;
    uint16_t internalFileAttr;
    uint32_t externalFileAttr;
    uint32_t localHeaderOffset;
};
#pragma pack(pop)

ZipInspectionResult ZipBombDetector::InspectArchive(const std::string& archivePath) {
    ZipInspectionResult res;
    res.archivePath = archivePath;

    std::error_code ec;
    res.archiveFileSizeBytes = fs::file_size(archivePath, ec);
    if (ec || res.archiveFileSizeBytes < sizeof(ZipEOCD)) {
        res.verdict = ZipVerdict::CorruptArchive;
        res.reason = "Archive file does not exist or is too small to contain a valid ZIP header.";
        return res;
    }

    std::ifstream file(archivePath, std::ios::binary);
    if (!file) {
        res.verdict = ZipVerdict::CorruptArchive;
        res.reason = "Cannot open archive file for inspection.";
        return res;
    }

    // 1. Locate End of Central Directory (EOCD)
    // EOCD can be preceded by variable-length comment (up to 65535 bytes)
    size_t searchLen = (std::min)(static_cast<size_t>(res.archiveFileSizeBytes), static_cast<size_t>(65535 + sizeof(ZipEOCD) + 16));
    std::vector<char> searchBuf(searchLen);

    file.seekg(-static_cast<std::streamoff>(searchLen), std::ios::end);
    file.read(searchBuf.data(), searchLen);

    int64_t eocdPosInBuf = -1;
    for (int64_t i = static_cast<int64_t>(searchLen) - sizeof(ZipEOCD); i >= 0; --i) {
        if (*reinterpret_cast<const uint32_t*>(&searchBuf[i]) == 0x06054b50) {
            eocdPosInBuf = i;
            break;
        }
    }

    if (eocdPosInBuf < 0) {
        res.verdict = ZipVerdict::CorruptArchive;
        res.reason = "Missing ZIP End of Central Directory (EOCD) signature.";
        return res;
    }

    const auto* eocd = reinterpret_cast<const ZipEOCD*>(&searchBuf[eocdPosInBuf]);
    uint64_t totalEntries = eocd->totalEntries;
    uint64_t cdOffset = eocd->cdOffset;
    uint64_t cdSize = eocd->cdSizeBytes;

    // Check for ZIP64 Locator
    if (eocdPosInBuf >= static_cast<int64_t>(sizeof(Zip64Locator))) {
        const auto* loc = reinterpret_cast<const Zip64Locator*>(&searchBuf[eocdPosInBuf - sizeof(Zip64Locator)]);
        if (loc->signature == 0x07064b50) {
            file.seekg(loc->eocd64Offset, std::ios::beg);
            Zip64EOCD eocd64{};
            if (file.read(reinterpret_cast<char*>(&eocd64), sizeof(eocd64)) && eocd64.signature == 0x06064b50) {
                totalEntries = eocd64.totalEntries;
                cdOffset = eocd64.cdOffset;
                cdSize = eocd64.cdSizeBytes;
            }
        }
    }

    res.totalEntries = totalEntries;

    // 2. Check Total Entry Count Threshold
    if (totalEntries > maxEntries_) {
        res.verdict = ZipVerdict::EntryCountLimitExceeded;
        res.reason = "Archive contains " + std::to_string(totalEntries) + " entries, exceeding maximum safety limit of " + std::to_string(maxEntries_);
        return res;
    }

    // 3. Parse Central Directory Entries
    file.seekg(cdOffset, std::ios::beg);
    std::unordered_set<uint64_t> observedOffsets;

    for (uint64_t i = 0; i < totalEntries; ++i) {
        ZipCentralDirHeader cdh{};
        if (!file.read(reinterpret_cast<char*>(&cdh), sizeof(cdh))) {
            res.verdict = ZipVerdict::CorruptArchive;
            res.reason = "Unexpected EOF while parsing central directory.";
            return res;
        }

        if (cdh.signature != 0x02014b50) {
            res.verdict = ZipVerdict::CorruptArchive;
            res.reason = "Corrupt Central Directory Header signature.";
            return res;
        }

        // Read Filename
        std::string entryName(cdh.filenameLength, '\0');
        if (cdh.filenameLength > 0) {
            file.read(&entryName[0], cdh.filenameLength);
        }

        // Skip Extra field and Comment
        if (cdh.extraFieldLength > 0 || cdh.commentLength > 0) {
            file.seekg(cdh.extraFieldLength + cdh.commentLength, std::ios::cur);
        }

        ZipEntryInfo info;
        info.filename = entryName;
        info.compressedSize = cdh.compressedSize;
        info.uncompressedSize = cdh.uncompressedSize;
        info.localHeaderOffset = cdh.localHeaderOffset;
        info.isDirectory = (!entryName.empty() && (entryName.back() == '/' || entryName.back() == '\\'));

        uint64_t denom = (info.compressedSize > 0) ? info.compressedSize : 1;
        info.compressionRatio = static_cast<double>(info.uncompressedSize) / denom;

        // Path Traversal Check (e.g. "../../../Windows/System32")
        if (entryName.find("../") != std::string::npos || entryName.find("..\\") != std::string::npos) {
            res.verdict = ZipVerdict::PathTraversalAttempt;
            res.reason = "Path traversal sequence detected in entry name: " + entryName;
            res.suspiciousEntries.push_back(info);
            return res;
        }

        // Overlapping Local Header Anomaly (classic zip-bomb trick where entries point to duplicate payload)
        if (!info.isDirectory && info.uncompressedSize > 0) {
            if (observedOffsets.count(info.localHeaderOffset) > 0) {
                res.verdict = ZipVerdict::OverlappingEntryAnomaly;
                res.reason = "Multiple directory entries point to the same local data offset (Zip Bomb technique): " + entryName;
                res.suspiciousEntries.push_back(info);
                return res;
            }
            observedOffsets.insert(info.localHeaderOffset);
        }

        // Nested archive detection
        std::string lowerName = ToLower(entryName);
        if (lowerName.ends_with(".zip") || lowerName.ends_with(".tar") ||
            lowerName.ends_with(".gz") || lowerName.ends_with(".7z") ||
            lowerName.ends_with(".rar") || lowerName.ends_with(".bz2")) {
            info.isNestedArchive = true;
            res.nestedArchiveCount++;
        }

        // Check entry compression ratio
        if (!info.isDirectory && info.compressionRatio > maxRatio_ && info.uncompressedSize > 1024 * 1024) {
            info.isNestedArchive = false;
            res.suspiciousEntries.push_back(info);
        }

        res.totalCompressedBytes += info.compressedSize;
        res.totalUncompressedBytes += info.uncompressedSize;
    }

    uint64_t overallDenom = (res.totalCompressedBytes > 0) ? res.totalCompressedBytes : 1;
    res.overallCompressionRatio = static_cast<double>(res.totalUncompressedBytes) / overallDenom;

    // 4. Overall Safety Evaluations
    if (res.totalUncompressedBytes > maxUncompressedBytes_) {
        res.verdict = ZipVerdict::SizeLimitExceeded;
        res.reason = "Total uncompressed size of " + std::to_string(res.totalUncompressedBytes / (1024 * 1024)) +
                     " MB exceeds allowed ceiling of " + std::to_string(maxUncompressedBytes_ / (1024 * 1024)) + " MB.";
        return res;
    }

    if (res.overallCompressionRatio > maxRatio_ && res.totalUncompressedBytes > 50 * 1024 * 1024) {
        res.verdict = ZipVerdict::ExcessiveCompressionRatio;
        res.reason = "Overall compression ratio is " + std::to_string(res.overallCompressionRatio) +
                     "x, exceeding allowed limit of " + std::to_string(maxRatio_) + "x (Zip Bomb pattern).";
        return res;
    }

    if (!res.suspiciousEntries.empty()) {
        res.verdict = ZipVerdict::ZipBombDetected;
        res.reason = "Contains " + std::to_string(res.suspiciousEntries.size()) + " files with extreme compression ratios (> " +
                     std::to_string(maxRatio_) + "x).";
        return res;
    }

    if (res.nestedArchiveCount > 15) {
        res.verdict = ZipVerdict::NestedArchiveRisk;
        res.reason = "Archive contains an excessive number of nested archives (" + std::to_string(res.nestedArchiveCount) + ").";
        return res;
    }

    res.verdict = ZipVerdict::Safe;
    res.reason = "Archive passed all zip-bomb, recursion, and integrity checks safely.";
    return res;
}

} // namespace backend
} // namespace vantor
