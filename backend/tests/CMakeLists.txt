cmake_minimum_required(VERSION 3.20)
project(VantorTests CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(TEST_SOURCES
    test_main.cpp
    test_signatures.cpp
    test_zipbomb.cpp
    test_antitamper.cpp
    test_ipc.cpp
    test_crypto.cpp
    test_scanner.cpp
    ../SignatureStore.cpp
    ../ZipBombDetector.cpp
    ../../service/AntiTamper.cpp
    ../../service/Scanner.cpp
    ../../service/ConfigManager.cpp
)

add_executable(VantorTests ${TEST_SOURCES} TestHarness.h)

target_include_directories(VantorTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../service
    ${CMAKE_CURRENT_SOURCE_DIR}/../../common
)

if(MSVC)
    target_compile_options(VantorTests PRIVATE
        /W4
        /permissive-
        /GS
        /Gy
    )
    target_link_options(VantorTests PRIVATE
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
    )
endif()

target_link_libraries(VantorTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../common/sqlite3.lib
    bcrypt
    crypt32
    wintrust
    advapi32
    ws2_32
)

enable_testing()
add_test(NAME VantorBackendTests COMMAND VantorTests)
