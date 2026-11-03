cmake_minimum_required(VERSION 3.20)
project(VantorBackend CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(BACKEND_SOURCES
    main.cpp
    SignatureStore.cpp
    ZipBombDetector.cpp
    GrpcServer.cpp
    ../service/AntiTamper.cpp
)

set(BACKEND_HEADERS
    SignatureStore.h
    ZipBombDetector.h
    GrpcServer.h
    ../service/AntiTamper.h
    ../common/Common.h
    ../common/Crypto.h
    ../common/NamedPipe.h
    ../common/Logger.h
    ../common/sqlite3.h
)

add_executable(VantorBackend ${BACKEND_SOURCES} ${BACKEND_HEADERS})

target_include_directories(VantorBackend PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
    ${CMAKE_CURRENT_SOURCE_DIR}/../service
)

if(MSVC)
    target_compile_options(VantorBackend PRIVATE
        /W4
        /permissive-
        /guard:cf
        /GS
        /Gy
        /sdl
    )
    target_link_options(VantorBackend PRIVATE
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
        /GUARD:CF
    )
endif()

target_link_libraries(VantorBackend PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/sqlite3.lib
    bcrypt
    crypt32
    wintrust
    advapi32
    ws2_32
)

add_subdirectory(tests)
