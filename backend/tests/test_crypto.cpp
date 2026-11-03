#include "TestHarness.h"
#include "../../common/Crypto.h"
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using namespace vantor::crypto;

TEST(CryptoTests, ZeroBytePayloadAESGCM) {
    std::vector<uint8_t> key(32, 0x42);
    std::vector<uint8_t> emptyPlaintext;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;

    // Encrypt 0-byte payload: parameters are (plaintext, key, ciphertext, iv, tag)
    EXPECT_TRUE(AES256GCMEncrypt(emptyPlaintext, key, ciphertext, iv, tag));
    EXPECT_EQ(ciphertext.size(), 0);
    EXPECT_EQ(iv.size(), 12);
    EXPECT_EQ(tag.size(), 16);

    // Decrypt 0-byte payload: parameters are (ciphertext, key, iv, tag, plaintext)
    std::vector<uint8_t> decrypted;
    EXPECT_TRUE(AES256GCMDecrypt(ciphertext, key, iv, tag, decrypted));
    EXPECT_EQ(decrypted.size(), 0);
}

TEST(CryptoTests, NonEmptyPayloadAESGCMRoundtrip) {
    std::vector<uint8_t> key(32, 0x5A);
    std::string secret = "Vantor Enterprise Antivirus Protection Engine 2026 Test Payload!";
    std::vector<uint8_t> plaintext(secret.begin(), secret.end());
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;

    EXPECT_TRUE(AES256GCMEncrypt(plaintext, key, ciphertext, iv, tag));
    EXPECT_EQ(ciphertext.size(), plaintext.size());
    EXPECT_EQ(iv.size(), 12);
    EXPECT_EQ(tag.size(), 16);
    EXPECT_NE(ciphertext, plaintext);

    std::vector<uint8_t> decrypted;
    EXPECT_TRUE(AES256GCMDecrypt(ciphertext, key, iv, tag, decrypted));
    EXPECT_EQ(decrypted, plaintext);

    // Tampering test: modify 1 byte of tag -> must fail
    tag[0] ^= 0x01;
    std::vector<uint8_t> tamperedDecrypted;
    EXPECT_FALSE(AES256GCMDecrypt(ciphertext, key, iv, tag, tamperedDecrypted));
}

TEST(CryptoTests, HashComputationAccuracy) {
    std::string sample = "VantorAuditVerification";
    std::string sha256 = ComputeSHA256Memory(sample.data(), sample.size());
    EXPECT_EQ(sha256.length(), 64);

    // Write sample to a temporary file
    std::string tempFile = "crypto_test_temp.bin";
    {
        std::ofstream out(tempFile, std::ios::binary);
        out << sample;
    }

    std::string fileSha256, fileSha512;
    EXPECT_TRUE(ComputeFileHashes(tempFile, fileSha256, fileSha512));
    EXPECT_EQ(fileSha256, sha256);
    EXPECT_EQ(fileSha512.length(), 128); // 64-byte SHA-512 in hex = 128 hex characters

    fs::remove(tempFile);
}
