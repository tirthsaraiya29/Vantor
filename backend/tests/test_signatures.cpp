#include "TestHarness.h"
#include "../SignatureStore.h"
#include "../../common/Crypto.h"
#include <filesystem>

namespace fs = std::filesystem;
using namespace vantor::backend;

TEST(SignatureStoreTests, InitializationAndEmptyQuery) {
    std::string testDb = "test_signatures.db";
    std::string testIdx = "test_signatures.idx";

    fs::remove(testDb);
    fs::remove(testIdx);

    SignatureStore store;
    EXPECT_TRUE(store.Initialize(testDb, testIdx));
    EXPECT_EQ(store.GetTotalSignatures(), 0);
    EXPECT_FALSE(store.Contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    store.Close();
    fs::remove(testDb);
    fs::remove(testIdx);
}

TEST(SignatureStoreTests, BulkImportAndPositiveLookups) {
    std::string testDb = "test_bulk.db";
    std::string testIdx = "test_bulk.idx";

    fs::remove(testDb);
    fs::remove(testIdx);

    SignatureStore store;
    EXPECT_TRUE(store.Initialize(testDb, testIdx));

    std::vector<std::string> testHashes;
    for (int i = 0; i < 500; ++i) {
        std::string payload = "malware_sample_payload_" + std::to_string(i);
        std::string hash = vantor::crypto::ComputeSHA256Memory(payload.data(), payload.size());
        testHashes.push_back(hash);
    }

    size_t imported = store.BulkImport(testHashes);
    EXPECT_EQ(imported, 500);
    EXPECT_EQ(store.GetTotalSignatures(), 500);

    // Verify all 500 hashes return true
    for (const auto& h : testHashes) {
        EXPECT_TRUE(store.Contains(h));
    }

    // Verify non-existent hashes return false
    for (int i = 500; i < 600; ++i) {
        std::string clean = "clean_system_file_" + std::to_string(i);
        std::string hash = vantor::crypto::ComputeSHA256Memory(clean.data(), clean.size());
        EXPECT_FALSE(store.Contains(hash));
    }

    store.Close();
    fs::remove(testDb);
    fs::remove(testIdx);
}
