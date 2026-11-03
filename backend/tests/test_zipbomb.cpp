#include "TestHarness.h"
#include "../ZipBombDetector.h"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using namespace vantor::backend;

// Helper to write a basic valid ZIP file to disk
static void CreateTestZip(const std::string& path, uint32_t compressed, uint32_t uncompressed, const std::string& name = "sample.txt") {
    std::ofstream f(path, std::ios::binary);

    // 1. Local File Header
    uint32_t locSig = 0x04034b50;
    uint16_t version = 20;
    uint16_t flags = 0;
    uint16_t method = 8; // Deflate
    uint16_t modTime = 0, modDate = 0;
    uint32_t crc = 0x12345678;
    uint16_t nameLen = static_cast<uint16_t>(name.length());
    uint16_t extraLen = 0;

    f.write(reinterpret_cast<char*>(&locSig), 4);
    f.write(reinterpret_cast<char*>(&version), 2);
    f.write(reinterpret_cast<char*>(&flags), 2);
    f.write(reinterpret_cast<char*>(&method), 2);
    f.write(reinterpret_cast<char*>(&modTime), 2);
    f.write(reinterpret_cast<char*>(&modDate), 2);
    f.write(reinterpret_cast<char*>(&crc), 4);
    f.write(reinterpret_cast<char*>(&compressed), 4);
    f.write(reinterpret_cast<char*>(&uncompressed), 4);
    f.write(reinterpret_cast<char*>(&nameLen), 2);
    f.write(reinterpret_cast<char*>(&extraLen), 2);
    f.write(name.data(), nameLen);

    // Write dummy compressed data
    std::vector<char> dummyData(compressed, 'X');
    if (compressed > 0) {
        f.write(dummyData.data(), compressed);
    }

    uint32_t cdOffset = static_cast<uint32_t>(f.tellp());

    // 2. Central Directory Header
    uint32_t cdSig = 0x02014b50;
    uint16_t cdVersion = 20;
    uint16_t commentLen = 0;
    uint16_t diskStart = 0;
    uint16_t intAttr = 0;
    uint32_t extAttr = 0;
    uint32_t locOffset = 0;

    f.write(reinterpret_cast<char*>(&cdSig), 4);
    f.write(reinterpret_cast<char*>(&cdVersion), 2);
    f.write(reinterpret_cast<char*>(&version), 2);
    f.write(reinterpret_cast<char*>(&flags), 2);
    f.write(reinterpret_cast<char*>(&method), 2);
    f.write(reinterpret_cast<char*>(&modTime), 2);
    f.write(reinterpret_cast<char*>(&modDate), 2);
    f.write(reinterpret_cast<char*>(&crc), 4);
    f.write(reinterpret_cast<char*>(&compressed), 4);
    f.write(reinterpret_cast<char*>(&uncompressed), 4);
    f.write(reinterpret_cast<char*>(&nameLen), 2);
    f.write(reinterpret_cast<char*>(&extraLen), 2);
    f.write(reinterpret_cast<char*>(&commentLen), 2);
    f.write(reinterpret_cast<char*>(&diskStart), 2);
    f.write(reinterpret_cast<char*>(&intAttr), 2);
    f.write(reinterpret_cast<char*>(&extAttr), 4);
    f.write(reinterpret_cast<char*>(&locOffset), 4);
    f.write(name.data(), nameLen);

    uint32_t cdSize = static_cast<uint32_t>(f.tellp()) - cdOffset;

    // 3. EOCD
    uint32_t eocdSig = 0x06054b50;
    uint16_t diskNum = 0, cdStart = 0, entries = 1;
    uint16_t eocdCommentLen = 0;

    f.write(reinterpret_cast<char*>(&eocdSig), 4);
    f.write(reinterpret_cast<char*>(&diskNum), 2);
    f.write(reinterpret_cast<char*>(&cdStart), 2);
    f.write(reinterpret_cast<char*>(&entries), 2);
    f.write(reinterpret_cast<char*>(&entries), 2);
    f.write(reinterpret_cast<char*>(&cdSize), 4);
    f.write(reinterpret_cast<char*>(&cdOffset), 4);
    f.write(reinterpret_cast<char*>(&eocdCommentLen), 2);
    f.close();
}

TEST(ZipBombTests, BenignZipInspection) {
    std::string testPath = "test_normal.zip";
    CreateTestZip(testPath, 500, 1000); // 2:1 ratio (normal)

    ZipBombDetector detector(10.0);
    auto res = detector.InspectArchive(testPath);

    EXPECT_EQ(res.verdict, ZipVerdict::Safe);
    EXPECT_EQ(res.totalEntries, 1);
    EXPECT_EQ(res.totalCompressedBytes, 500);
    EXPECT_EQ(res.totalUncompressedBytes, 1000);

    fs::remove(testPath);
}

TEST(ZipBombTests, ExtremeRatioZipBombDetection) {
    std::string testPath = "test_bomb.zip";
    // 500 bytes compressed expanding to 500,000,000 bytes (1,000,000:1 ratio)
    CreateTestZip(testPath, 500, 500000000);

    ZipBombDetector detector(10.0);
    auto res = detector.InspectArchive(testPath);

    EXPECT_NE(res.verdict, ZipVerdict::Safe);
    EXPECT_TRUE(res.overallCompressionRatio > 100.0);

    fs::remove(testPath);
}

TEST(ZipBombTests, PathTraversalRejection) {
    std::string testPath = "test_traversal.zip";
    CreateTestZip(testPath, 200, 200, "../../Windows/System32/evil.dll");

    ZipBombDetector detector(10.0);
    auto res = detector.InspectArchive(testPath);

    EXPECT_EQ(res.verdict, ZipVerdict::PathTraversalAttempt);

    fs::remove(testPath);
}
