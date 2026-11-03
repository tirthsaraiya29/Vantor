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
    if (file.gcount() != static_cast<std::streamsize>(searchLen)) {
        res.verdict = ZipVerdict::CorruptArchive;
        res.reason = "Failed to read trailing archive bytes for EOCD lookup.";
        return res;
    }

    int64_t eocdPosInBuf = -1;
    for (int64_t i = static_cast<int64_t>(searchLen) - sizeof(ZipEOCD); i >= 0; --i) {
        if (static_cast<uint8_t>(searchBuf[i]) == 0x50 &&
            static_cast<uint8_t>(searchBuf[i + 1]) == 0x4b &&
            static_cast<uint8_t>(searchBuf[i + 2]) == 0x05 &&
            static_cast<uint8_t>(searchBuf[i + 3]) == 0x06) {
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
        if (loc->signature == 0x07064b50 && loc->eocd64Offset < res.archiveFileSizeBytes) {
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

    // Validate central directory boundaries
    if (cdOffset > res.archiveFileSizeBytes || cdSize > res.archiveFileSizeBytes || (cdOffset + cdSize) > res.archiveFileSizeBytes) {
        res.verdict = ZipVerdict::CorruptArchive;
        res.reason = "Central directory offset or size points outside valid file bounds.";
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
            if (file.gcount() != static_cast<std::streamsize>(cdh.filenameLength)) {
                res.verdict = ZipVerdict::CorruptArchive;
                res.reason = "Truncated filename in central directory entry.";
                return res;
            }
        }

        uint64_t entryUncompressedSize = cdh.uncompressedSize;
        uint64_t entryCompressedSize = cdh.compressedSize;
        uint64_t entryLocalHeaderOffset = cdh.localHeaderOffset;

        // Read and parse Extra Field if present (especially ZIP64 extra block)
        if (cdh.extraFieldLength > 0) {
            std::vector<uint8_t> extra(cdh.extraFieldLength);
            file.read(reinterpret_cast<char*>(extra.data()), cdh.extraFieldLength);
            if (file.gcount() != static_cast<std::streamsize>(cdh.extraFieldLength)) {
                res.verdict = ZipVerdict::CorruptArchive;
                res.reason = "Truncated extra field in central directory entry.";
                return res;
            }

            size_t exOff = 0;
            while (exOff + 4 <= extra.size()) {
                uint16_t tag = *reinterpret_cast<const uint16_t*>(&extra[exOff]);
                uint16_t len = *reinterpret_cast<const uint16_t*>(&extra[exOff + 2]);
                exOff += 4;
                if (exOff + len > extra.size()) break;

                // ZIP64 Extended Information Extra Field (Tag 0x0001)
                if (tag == 0x0001) {
                    size_t z64Off = exOff;
                    if (entryUncompressedSize == 0xFFFFFFFF && z64Off + 8 <= exOff + len) {
                        memcpy(&entryUncompressedSize, &extra[z64Off], 8);
                        z64Off += 8;
                    }
                    if (entryCompressedSize == 0xFFFFFFFF && z64Off + 8 <= exOff + len) {
                        memcpy(&entryCompressedSize, &extra[z64Off], 8);
                        z64Off += 8;
                    }
                    if (entryLocalHeaderOffset == 0xFFFFFFFF && z64Off + 8 <= exOff + len) {
                        memcpy(&entryLocalHeaderOffset, &extra[z64Off], 8);
                        z64Off += 8;
                    }
                }
                exOff += len;
            }
        }

        // Skip Comment
        if (cdh.commentLength > 0) {
            file.seekg(cdh.commentLength, std::ios::cur);
        }

        ZipEntryInfo info;
        info.filename = entryName;
        info.compressedSize = entryCompressedSize;
        info.uncompressedSize = entryUncompressedSize;
        info.localHeaderOffset = entryLocalHeaderOffset;
        info.isDirectory = (!entryName.empty() && (entryName.back() == '/' || entryName.back() == '\\'));

        uint64_t denom = (info.compressedSize > 0) ? info.compressedSize : 1;
        info.compressionRatio = static_cast<double>(info.uncompressedSize) / denom;

        // Path Traversal Check (e.g. "../../../Windows/System32" or absolute paths)
        if (entryName.find("../") != std::string::npos ||
            entryName.find("..\\") != std::string::npos ||
            entryName.find("/..") != std::string::npos ||
            entryName.find("\\..") != std::string::npos ||
            (!entryName.empty() && (entryName[0] == '/' || entryName[0] == '\\')) ||
            (entryName.length() >= 2 && entryName[1] == ':')) {
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
