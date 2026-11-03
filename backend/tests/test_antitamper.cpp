#include "TestHarness.h"
#include "../../service/AntiTamper.h"

using namespace vantor::antitamper;

TEST(AntiTamperTests, InitializationAndSelfCheck) {
    auto& at = AntiTamper::Instance();
    EXPECT_TRUE(at.Initialize());

    // In a normal test runner without debugger attached, self-check should pass
    bool integrityOk = at.VerifyRuntimeCodeIntegrity();
    EXPECT_TRUE(integrityOk);
}

TEST(AntiTamperTests, ApiHookDetectionIntegrity) {
    auto& at = AntiTamper::Instance();
    // Verify that system APIs are clean and unhooked
    bool hooked = at.DetectApiHooks();
    EXPECT_FALSE(hooked);
}

TEST(AntiTamperTests, AntiVMQuery) {
    auto& at = AntiTamper::Instance();
    std::string vendor;
    bool isVm = at.CheckAntiVM(vendor);
    // Just verify the query executes safely without throwing or crashing
    if (isVm) {
        std::cout << "    [INFO] VM Environment Detected: " << vendor << "\n";
    }
    EXPECT_TRUE(true);
}
