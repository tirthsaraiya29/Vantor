#pragma once

#include "../common/Common.h"
#include <string>
#include <vector>
#include <shared_mutex>
#include <memory>
#include <cstdint>

namespace vantor {
namespace backend {

// 64-bit Bloom filter parameter constants
constexpr size_t BLOOM_FILTER_BYTES = 128 * 1024; // 128 KB bitset
constexpr uint32_t SIGNATURE_INDEX_MAGIC = 0x56534947; // "VSIG"
constexpr uint32_t SIGNATURE_INDEX_VERSION = 1;

#pragma pack(push, 1)
struct IndexHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t totalSignatures;
    uint64_t bloomFilterBytes;
    uint8_t bloomFilter[BLOOM_FILTER_BYTES];
};
#pragma pack(pop)

class SignatureStore {
public:
    static SignatureStore& Instance() {
        static SignatureStore instance;
        return instance;
    }

    bool Initialize(const std::string& dbPath = "signatures.db", const std::string& indexPath = "signatures.idx");
    void Close();

    // Query APIs - Ultra high performance (< 1 microsecond per check)
    bool Contains(const std::string& sha256Hex);
    bool Contains(const uint8_t rawSha256[32]);
    size_t GetTotalSignatures() const;

    // Mutation APIs
    bool AddSignature(const std::string& sha256Hex);
    size_t BulkImport(const std::vector<std::string>& sha256HexList, bool rebuildIndex = true);
    size_t ImportFromTextFile(const std::string& textFilePath);

    SignatureStore();
    ~SignatureStore();

    // Index Rebuilding
    bool RebuildMemoryMappedIndex();

private:
    // Bloom filter helper
    void BloomAdd(const uint8_t* hash32);
    bool BloomMayContain(const uint8_t* hash32) const;

    // Memory-mapped file management
    bool OpenMemoryMap();
    void CloseMemoryMap();

    std::string dbPath_;
    std::string indexPath_;
    mutable std::shared_mutex mutex_;

    // Windows Memory-Mapped File Handles
    HANDLE hFile_ = INVALID_HANDLE_VALUE;
    HANDLE hMapping_ = nullptr;
    const uint8_t* pMappedView_ = nullptr;
    size_t mappedSize_ = 0;
    const IndexHeader* pHeader_ = nullptr;
    const uint8_t* pHashArray_ = nullptr; // Array of 32-byte sorted binary hashes
    size_t hashCount_ = 0;

    // Transient in-memory Bloom filter for lookups
    std::vector<uint8_t> inMemoryBloom_;
};

} // namespace backend
} // namespace vantor
