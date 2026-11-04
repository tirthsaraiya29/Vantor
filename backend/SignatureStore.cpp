#include "SignatureStore.h"
#include "../common/Crypto.h"
#include "../common/Logger.h"
#include "../common/sqlite3.h"

#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cstring>

namespace fs = std::filesystem;

namespace vantor {
namespace backend {

// Fast non-cryptographic hash for Bloom filter (Murmur3 64-bit mixer)
static inline uint64_t MurmurMix64(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

SignatureStore::SignatureStore() {
    inMemoryBloom_.resize(BLOOM_FILTER_BYTES, 0);
}

SignatureStore::~SignatureStore() {
    Close();
}

bool SignatureStore::Initialize(const std::string& dbPath, const std::string& indexPath) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    dbPath_ = dbPath;
    indexPath_ = indexPath;

    // 1. Initialize SQLite Database
    sqlite3* db = nullptr;
    if (sqlite3_open(dbPath_.c_str(), &db) == SQLITE_OK) {
        sqlite3_exec(db, "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;", nullptr, nullptr, nullptr);
        const char* sql =
            "CREATE TABLE IF NOT EXISTS malware_hashes ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "hash TEXT NOT NULL UNIQUE);"
            "CREATE INDEX IF NOT EXISTS idx_hash ON malware_hashes(hash);";
        sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
        sqlite3_close(db);
    } else {
        LOG_ERROR("SignatureStore", "Failed to open SQLite database: " + dbPath_);
        return false;
    }

    // 2. Open or Rebuild Memory-Mapped Index
    if (!fs::exists(indexPath_) || fs::file_size(indexPath_) < sizeof(IndexHeader)) {
        LOG_INFO("SignatureStore", "Index file not found or invalid. Building from SQLite...");
        lock.unlock();
        RebuildMemoryMappedIndex();
        lock.lock();
    } else {
        OpenMemoryMap();
    }

    LOG_INFO("SignatureStore", "SignatureStore initialized with " + std::to_string(hashCount_) + " indexed signatures.");
    return true;
}

void SignatureStore::Close() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    CloseMemoryMap();
}

void SignatureStore::BloomAdd(const uint8_t* hash32) {
    uint64_t h1 = 0, h2 = 0;
    memcpy(&h1, hash32, sizeof(h1));
    memcpy(&h2, hash32 + 8, sizeof(h2));

    uint64_t totalBits = BLOOM_FILTER_BYTES * 8;

    for (int i = 0; i < 4; ++i) {
        uint64_t combined = MurmurMix64(h1 + i * h2);
        uint64_t bitIdx = combined % totalBits;
        inMemoryBloom_[bitIdx / 8] |= (1 << (bitIdx % 8));
    }
}

bool SignatureStore::BloomMayContain(const uint8_t* hash32) const {
    uint64_t h1 = 0, h2 = 0;
    memcpy(&h1, hash32, sizeof(h1));
    memcpy(&h2, hash32 + 8, sizeof(h2));

    uint64_t totalBits = BLOOM_FILTER_BYTES * 8;

    const uint8_t* bloom = pHeader_ ? pHeader_->bloomFilter : inMemoryBloom_.data();

    for (int i = 0; i < 4; ++i) {
        uint64_t combined = MurmurMix64(h1 + i * h2);
        uint64_t bitIdx = combined % totalBits;
        if ((bloom[bitIdx / 8] & (1 << (bitIdx % 8))) == 0) {
            return false; // Definitely not in set!
        }
    }
    return true; // Maybe in set
}

bool SignatureStore::OpenMemoryMap() {
    CloseMemoryMap();

    std::wstring wIndexPath = Utf8ToUtf16(indexPath_);
    hFile_ = CreateFileW(
        wIndexPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_RANDOM_ACCESS,
        nullptr
    );

    if (hFile_ == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile_, &liSize) || liSize.QuadPart < static_cast<LONGLONG>(sizeof(IndexHeader))) {
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
        return false;
    }

    mappedSize_ = static_cast<size_t>(liSize.QuadPart);
    hMapping_ = CreateFileMappingW(hFile_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping_) {
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
        return false;
    }

    pMappedView_ = reinterpret_cast<const uint8_t*>(MapViewOfFile(hMapping_, FILE_MAP_READ, 0, 0, 0));
    if (!pMappedView_) {
        CloseHandle(hMapping_);
        hMapping_ = nullptr;
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
        return false;
    }

    pHeader_ = reinterpret_cast<const IndexHeader*>(pMappedView_);
    if (pHeader_->magic != SIGNATURE_INDEX_MAGIC ||
        pHeader_->version != SIGNATURE_INDEX_VERSION ||
        pHeader_->bloomFilterBytes != BLOOM_FILTER_BYTES) {
        CloseMemoryMap();
        return false;
    }

    // Strict bounds validation: verify physical file size contains all declared signatures
    uint64_t expectedMinSize = sizeof(IndexHeader) + (pHeader_->totalSignatures * 32ULL);
    if (static_cast<uint64_t>(liSize.QuadPart) < expectedMinSize) {
        LOG_WARN("SignatureStore", "Index file is truncated or corrupted compared to signature count header.");
        CloseMemoryMap();
        return false;
    }

    pHashArray_ = pMappedView_ + sizeof(IndexHeader);
    hashCount_ = static_cast<size_t>(pHeader_->totalSignatures);
    return true;
}

void SignatureStore::CloseMemoryMap() {
    if (pMappedView_) {
        UnmapViewOfFile(pMappedView_);
        pMappedView_ = nullptr;
    }
    if (hMapping_) {
        CloseHandle(hMapping_);
        hMapping_ = nullptr;
    }
    if (hFile_ != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
    }
    pHeader_ = nullptr;
    pHashArray_ = nullptr;
    hashCount_ = 0;
}

bool SignatureStore::Contains(const uint8_t rawSha256[32]) {
    if (!rawSha256) return false;

    std::shared_lock<std::shared_mutex> lock(mutex_);

    // 1. O(1) Bloom Filter Check
    if (!BloomMayContain(rawSha256)) {
        return false; // Negative lookup finished in < 50 CPU cycles
    }

    // 2. Binary Search in Memory-Mapped File
    if (pHashArray_ && hashCount_ > 0) {
        size_t low = 0;
        size_t high = hashCount_;

        while (low < high) {
            size_t mid = low + (high - low) / 2;
            const uint8_t* midHash = pHashArray_ + (mid * 32);
            int cmp = memcmp(rawSha256, midHash, 32);
            if (cmp == 0) {
                return true; // Match found in memory map!
            } else if (cmp < 0) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }
        return false;
    }

    // 3. Fallback: Query SQLite directly
    sqlite3* db = nullptr;
    bool found = false;
    if (sqlite3_open_v2(dbPath_.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK) {
        char hexStr[65] = {0};
        for (int i = 0; i < 32; ++i) {
            snprintf(hexStr + (i * 2), 3, "%02x", rawSha256[i]);
        }
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT 1 FROM malware_hashes WHERE hash = ? LIMIT 1;";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, hexStr, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                found = true;
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }

    return found;
}

bool SignatureStore::Contains(const std::string& sha256Hex) {
    std::string lowerHex = ToLower(sha256Hex);
    if (lowerHex.length() != 64) return false;

    std::vector<uint8_t> hashBytes;
    if (!crypto::HexToBytes(lowerHex, hashBytes) || hashBytes.size() != 32) {
        return false;
    }

    return Contains(hashBytes.data());
}

size_t SignatureStore::GetTotalSignatures() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return hashCount_;
}

bool SignatureStore::AddSignature(const std::string& sha256Hex) {
    return BulkImport({ sha256Hex }) > 0;
}

size_t SignatureStore::BulkImport(const std::vector<std::string>& sha256HexList, bool rebuildIndex) {
    if (sha256HexList.empty()) return 0;

    std::unique_lock<std::shared_mutex> lock(mutex_);
    sqlite3* db = nullptr;
    if (sqlite3_open(dbPath_.c_str(), &db) != SQLITE_OK) {
        return 0;
    }

    sqlite3_exec(db, "PRAGMA synchronous = OFF; PRAGMA journal_mode = MEMORY;", nullptr, nullptr, nullptr);
    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    const char* sql = "INSERT OR IGNORE INTO malware_hashes (hash) VALUES (?);";
    sqlite3_stmt* stmt = nullptr;
    size_t imported = 0;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        for (const auto& hex : sha256HexList) {
            if (hex.length() != 64) continue;
            std::string lowerHex = ToLower(hex);
            sqlite3_bind_text(stmt, 1, lowerHex.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                imported++;
            }
            sqlite3_reset(stmt);
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    sqlite3_close(db);

    if (rebuildIndex) {
        lock.unlock();
        RebuildMemoryMappedIndex();
    }
    return imported;
}

size_t SignatureStore::ImportFromTextFile(const std::string& textFilePath) {
    std::ifstream in(textFilePath);
    if (!in) return 0;

    std::vector<std::string> batch;
    batch.reserve(50000);
    std::string line;
    size_t total = 0;

    while (std::getline(in, line)) {
        // Strip whitespace and carriage returns
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
            line.pop_back();
        }
        if (line.length() == 64) {
            batch.push_back(line);
            if (batch.size() >= 50000) {
                total += BulkImport(batch, false);
                batch.clear();
            }
        }
    }

    if (!batch.empty()) {
        total += BulkImport(batch, false);
    }
    if (total > 0) {
        RebuildMemoryMappedIndex();
    }
    return total;
}

bool SignatureStore::RebuildMemoryMappedIndex() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    CloseMemoryMap();

    sqlite3* db = nullptr;
    if (sqlite3_open_v2(dbPath_.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        return false;
    }

    // 1. Fetch all unique hashes
    const char* countSql = "SELECT COUNT(*) FROM malware_hashes;";
    sqlite3_stmt* countStmt = nullptr;
    size_t totalRows = 0;
    if (sqlite3_prepare_v2(db, countSql, -1, &countStmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(countStmt) == SQLITE_ROW) {
            totalRows = static_cast<size_t>(sqlite3_column_int64(countStmt, 0));
        }
        sqlite3_finalize(countStmt);
    }

    struct Hash32 {
        uint8_t bytes[32];
        bool operator<(const Hash32& o) const {
            return memcmp(bytes, o.bytes, 32) < 0;
        }
    };

    std::vector<Hash32> sortedHashes;
    sortedHashes.reserve(totalRows);

    const char* fetchSql = "SELECT hash FROM malware_hashes;";
    sqlite3_stmt* fetchStmt = nullptr;
    if (sqlite3_prepare_v2(db, fetchSql, -1, &fetchStmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(fetchStmt) == SQLITE_ROW) {
            const char* hex = reinterpret_cast<const char*>(sqlite3_column_text(fetchStmt, 0));
            std::vector<uint8_t> b;
            if (hex && crypto::HexToBytes(hex, b) && b.size() == 32) {
                Hash32 h;
                memcpy(h.bytes, b.data(), 32);
                sortedHashes.push_back(h);
            }
        }
        sqlite3_finalize(fetchStmt);
    }
    sqlite3_close(db);

    // 2. Sort array of raw binary hashes
    std::sort(sortedHashes.begin(), sortedHashes.end());

    // 3. Build Bloom filter & Index Header
    IndexHeader header{};
    header.magic = SIGNATURE_INDEX_MAGIC;
    header.version = SIGNATURE_INDEX_VERSION;
    header.totalSignatures = sortedHashes.size();
    header.bloomFilterBytes = BLOOM_FILTER_BYTES;
    memset(header.bloomFilter, 0, BLOOM_FILTER_BYTES);

    inMemoryBloom_.assign(BLOOM_FILTER_BYTES, 0);

    for (const auto& h : sortedHashes) {
        BloomAdd(h.bytes);
    }
    memcpy(header.bloomFilter, inMemoryBloom_.data(), BLOOM_FILTER_BYTES);

    // 4. Write temporary file and atomic replace
    std::string tmpIndexPath = indexPath_ + ".tmp";
    std::ofstream out(tmpIndexPath, std::ios::binary);
    if (!out) {
        LOG_ERROR("SignatureStore", "Failed to open temporary index file for writing: " + tmpIndexPath);
        return false;
    }

    out.write(reinterpret_cast<const char*>(&header), sizeof(header));
    if (!sortedHashes.empty()) {
        out.write(reinterpret_cast<const char*>(sortedHashes.data()), sortedHashes.size() * sizeof(Hash32));
    }
    out.close();

    std::error_code ec;
    fs::rename(tmpIndexPath, indexPath_, ec);
    if (ec) {
        fs::copy_file(tmpIndexPath, indexPath_, fs::copy_options::overwrite_existing, ec);
        fs::remove(tmpIndexPath, ec);
    }

    // 5. Open Memory Map
    bool ok = OpenMemoryMap();
    LOG_INFO("SignatureStore", "Memory-mapped index rebuilt with " + std::to_string(sortedHashes.size()) + " hashes.");
    return ok;
}

} // namespace backend
} // namespace vantor
