cmake_minimum_required(VERSION 3.20)
project(VantorService CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SERVICE_SOURCES
    main.cpp
    Scanner.cpp
    ConfigManager.cpp
    IPC.cpp
    AntiTamper.cpp
    RealTimeProtection.cpp
)

set(SERVICE_HEADERS
    Scanner.h
    ConfigManager.h
    IPC.h
    AntiTamper.h
    RealTimeProtection.h
    ../common/Common.h
    ../common/Crypto.h
    ../common/NamedPipe.h
    ../common/Logger.h
    ../common/sqlite3.h
)

add_executable(VantorService ${SERVICE_SOURCES} ${SERVICE_HEADERS})

target_include_directories(VantorService PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

# MSVC Hardening flags
if(MSVC)
    target_compile_options(VantorService PRIVATE
        /W4
        /permissive-
        /guard:cf       # Control Flow Guard
        /GS             # Buffer Security Check
        /Gy             # Function-Level Linking
        /sdl            # Additional Security Checks
    )
    target_link_options(VantorService PRIVATE
        /DYNAMICBASE    # ASLR
        /HIGHENTROPYVA  # 64-bit ASLR
        /NXCOMPAT       # DEP
        /GUARD:CF       # Linker Control Flow Guard
    )
endif()

target_link_libraries(VantorService PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/sqlite3.lib
    bcrypt
    crypt32
    wintrust
    advapi32
    shell32
    psapi
)
