#include "TestHarness.h"
#include "../../service/Scanner.h"
#include "../../service/ConfigManager.h"
#include "../../backend/SignatureStore.h"
#include "../../common/Crypto.h"
#include <filesystem>
#include <fstream>
#include <vector>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;
using namespace vantor::scan;

static void SafeRemoveDir(const std::string& path) {
    std::error_code ec;
    for (int i = 0; i < 15; ++i) {
        fs::remove_all(path, ec);
        if (!ec || !fs::exists(path, ec)) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
}

TEST(ScannerTests, HeuristicDoubleExtension) {
    std::vector<uint8_t> dummyPe;

    // A file with double executable extension (e.g. invoice.pdf.exe)
    double score1 = Scanner::CalculateHeuristicScore("C:\\Users\\test\\Downloads\\invoice.pdf.exe", dummyPe);
    EXPECT_GT(score1, 0.20);

    // A file inside a directory with dots, but normal single extension
    double score2 = Scanner::CalculateHeuristicScore("C:\\Users\\test.corp\\Documents\\report.docx", dummyPe);
    EXPECT_LT(score2, 0.25);
}

TEST(ScannerTests, QuarantineAndRestorationLifecycle) {
    std::string testDir = "test_quarantine_sandbox";
    SafeRemoveDir(testDir);
    fs::create_directories(testDir);

    auto& scanner = Scanner::Instance();
    EXPECT_TRUE(scanner.Initialize(testDir));

    // Create a target test file to quarantine
    std::string targetFile = testDir + "\\malicious_dummy.bin";
    std::string testContent = "MALWARE_SIGNATURE_DUMMY_STRING_1234567890";
    {
        std::ofstream out(targetFile, std::ios::binary);
        out << testContent;
    }
    EXPECT_TRUE(fs::exists(targetFile));

    std::string sha256 = vantor::crypto::ComputeSHA256Memory(testContent.data(), testContent.size());
    std::string sha512 = "dummy_sha512_hash";

    // 1. Quarantine the file
    EXPECT_TRUE(scanner.QuarantineFile(targetFile, "SESSION-UT", sha256, sha512));

    // Original file must no longer exist at target path
    EXPECT_FALSE(fs::exists(targetFile));

    // Verify record in quarantine list
    auto qList = scanner.GetQuarantineRecords();
    int64_t qId = -1;
    for (const auto& r : qList) {
        if (r.sha256 == sha256) {
            qId = r.id;
            break;
        }
    }
    EXPECT_GT(qId, 0);

    // 2. Restore the file to original location
    EXPECT_TRUE(scanner.RestoreQuarantinedFile(qId, targetFile));
    EXPECT_TRUE(fs::exists(targetFile));

    // Verify restored file content matches exactly
    {
        std::ifstream in(targetFile, std::ios::binary);
        std::string restoredContent((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        EXPECT_EQ(restoredContent, testContent);
    }

    // 3. Collision Restoration Test
    // Quarantine again
    EXPECT_TRUE(scanner.QuarantineFile(targetFile, "SESSION-UT-2", sha256, sha512));
    EXPECT_FALSE(fs::exists(targetFile));

    // Get new qId
    qList = scanner.GetQuarantineRecords();
    int64_t qId2 = -1;
    for (const auto& r : qList) {
        if (r.sha256 == sha256) {
            qId2 = r.id;
            break;
        }
    }
    EXPECT_GT(qId2, 0);

    // Recreate targetFile to cause a collision
    {
        std::ofstream out(targetFile, std::ios::binary);
        out << "Existing collision file content";
    }

    // Restoring to targetFile should handle collision by appending _restored
    EXPECT_TRUE(scanner.RestoreQuarantinedFile(qId2, targetFile));

    // Verify collision file was preserved
    {
        std::ifstream in(targetFile, std::ios::binary);
        std::string existingContent((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        EXPECT_EQ(existingContent, "Existing collision file content");
    }

    // Verify restored file exists with _restored
    std::string restoredCollisionFile = testDir + "\\malicious_dummy_restored.bin";
    EXPECT_TRUE(fs::exists(restoredCollisionFile));
    {
        std::ifstream in(restoredCollisionFile, std::ios::binary);
        std::string restoredContent((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        EXPECT_EQ(restoredContent, testContent);
    }

    // Clean up
    SafeRemoveDir(testDir);
}

TEST(ScannerTests, RestorationPathTraversalPrevention) {
    std::string testDir = "test_traversal_sandbox";
    SafeRemoveDir(testDir);
    fs::create_directories(testDir);

    auto& scanner = Scanner::Instance();
    EXPECT_TRUE(scanner.Initialize(testDir));

    std::string targetFile = testDir + "\\payload.bin";
    std::string testContent = "traversal_test_data";
    {
        std::ofstream out(targetFile, std::ios::binary);
        out << testContent;
    }

    std::string sha256 = vantor::crypto::ComputeSHA256Memory(testContent.data(), testContent.size());
    EXPECT_TRUE(scanner.QuarantineFile(targetFile, "SESSION-TRAV", sha256, "sha512"));

    auto qList = scanner.GetQuarantineRecords();
    int64_t qId = -1;
    for (const auto& r : qList) {
        if (r.sha256 == sha256) {
            qId = r.id;
            break;
        }
    }
    EXPECT_GT(qId, 0);

    // Attempt restoration with path traversal
    std::string evilPath = testDir + "\\..\\..\\Windows\\System32\\evil.exe";
    EXPECT_FALSE(scanner.RestoreQuarantinedFile(qId, evilPath));

    SafeRemoveDir(testDir);
    std::cout << "[DEBUG] Exiting RestorationPathTraversalPrevention\n" << std::flush;
}
