#pragma once

#ifdef VANTOR_USE_GTEST
#include <gtest/gtest.h>
#else
#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>

namespace vantor {
namespace test {

struct TestCase {
    std::string suiteName;
    std::string testName;
    std::function<void()> func;
};

inline std::vector<TestCase>& GetTestRegistry() {
    static std::vector<TestCase> registry;
    return registry;
}

inline bool RegisterTest(const std::string& suite, const std::string& name, std::function<void()> func) {
    GetTestRegistry().push_back({ suite, name, func });
    return true;
}

inline int RunAllTests() {
    auto& tests = GetTestRegistry();
    int passed = 0;
    int failed = 0;

    std::cout << "========================================================\n";
    std::cout << "         Running " << tests.size() << " Vantor Antivirus Test Cases       \n";
    std::cout << "========================================================\n";

    for (const auto& t : tests) {
        std::cout << "[ RUN      ] " << t.suiteName << "." << t.testName << "\n";
        try {
            t.func();
            std::cout << "[       OK ] " << t.suiteName << "." << t.testName << "\n";
            passed++;
        } catch (const std::exception& e) {
            std::cerr << "[  FAILED  ] " << t.suiteName << "." << t.testName << ": " << e.what() << "\n";
            failed++;
        } catch (...) {
            std::cerr << "[  FAILED  ] " << t.suiteName << "." << t.testName << ": Unknown exception\n";
            failed++;
        }
    }

    std::cout << "========================================================\n";
    std::cout << "[==========] Total Tests: " << tests.size() << "\n";
    std::cout << "[  PASSED  ] " << passed << " tests\n";
    if (failed > 0) {
        std::cout << "[  FAILED  ] " << failed << " tests\n";
    }
    std::cout << "========================================================\n";

    return (failed == 0) ? 0 : 1;
}

} // namespace test
} // namespace vantor

#define TEST(suite, name) \
    void Test_##suite##_##name(); \
    static bool reg_##suite##_##name = vantor::test::RegisterTest(#suite, #name, Test_##suite##_##name); \
    void Test_##suite##_##name()

#define EXPECT_TRUE(cond) if (!(cond)) throw std::runtime_error("EXPECT_TRUE failed: " #cond);
#define EXPECT_FALSE(cond) if (cond) throw std::runtime_error("EXPECT_FALSE failed: " #cond);
#define EXPECT_EQ(a, b) if (!((a) == (b))) throw std::runtime_error("EXPECT_EQ failed: " #a " == " #b);
#define EXPECT_NE(a, b) if ((a) == (b)) throw std::runtime_error("EXPECT_NE failed: " #a " != " #b);
#define EXPECT_GT(a, b) if (!((a) > (b))) throw std::runtime_error("EXPECT_GT failed: " #a " > " #b);
#define EXPECT_LT(a, b) if (!((a) < (b))) throw std::runtime_error("EXPECT_LT failed: " #a " < " #b);
#define EXPECT_GE(a, b) if (!((a) >= (b))) throw std::runtime_error("EXPECT_GE failed: " #a " >= " #b);
#define EXPECT_LE(a, b) if (!((a) <= (b))) throw std::runtime_error("EXPECT_LE failed: " #a " <= " #b);
#define ASSERT_TRUE(cond) EXPECT_TRUE(cond)
#define ASSERT_NE(a, b) EXPECT_NE(a, b)
#define ASSERT_FALSE(cond) EXPECT_FALSE(cond)
#define ASSERT_EQ(a, b) EXPECT_EQ(a, b)

#endif
