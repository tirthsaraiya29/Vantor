#include "TestHarness.h"

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
#ifdef VANTOR_USE_GTEST
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
#else
    return vantor::test::RunAllTests();
#endif
}
