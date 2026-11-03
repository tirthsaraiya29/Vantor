cmake_minimum_required(VERSION 3.20)
project(VantorUI CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS Core Widgets Gui QUIET)
if(NOT Qt6_FOUND)
    find_package(Qt5 COMPONENTS Core Widgets Gui QUIET)
endif()

if(Qt6_FOUND OR Qt5_FOUND)
    message(STATUS "Qt found. Building hardened Vantor Qt UI.")

    set(UI_SOURCES
        main.cpp
        mainwindow.cpp
        QuarantineDialog.cpp
        SettingsDialog.cpp
        GrpcClient.cpp
        theme/resources.qrc
        ../service/AntiTamper.cpp
        ../backend/ZipBombDetector.cpp
    )

    set(UI_HEADERS
        mainwindow.h
        QuarantineDialog.h
        SettingsDialog.h
        GrpcClient.h
        ZipBombGuard.h
        performance/FrameRateLimiter.h
        ../service/AntiTamper.h
        ../backend/ZipBombDetector.h
        ../common/Common.h
        ../common/Crypto.h
        ../common/NamedPipe.h
        ../common/Logger.h
    )

    add_executable(VantorUI WIN32 ${UI_SOURCES} ${UI_HEADERS})

    target_include_directories(VantorUI PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
        ${CMAKE_CURRENT_SOURCE_DIR}/../service
        ${CMAKE_CURRENT_SOURCE_DIR}/../backend
    )

    if(MSVC)
        target_compile_options(VantorUI PRIVATE
            /W4
            /permissive-
            /guard:cf
            /GS
            /Gy
        )
        target_link_options(VantorUI PRIVATE
            /DYNAMICBASE
            /HIGHENTROPYVA
            /NXCOMPAT
            /GUARD:CF
        )
    endif()

    if(Qt6_FOUND)
        target_link_libraries(VantorUI PRIVATE
            Qt6::Core
            Qt6::Widgets
            Qt6::Gui
            ${CMAKE_CURRENT_SOURCE_DIR}/../common/sqlite3.lib
            bcrypt
            crypt32
            wintrust
            advapi32
            ws2_32
            shell32
        )
    else()
        target_link_libraries(VantorUI PRIVATE
            Qt5::Core
            Qt5::Widgets
            Qt5::Gui
            ${CMAKE_CURRENT_SOURCE_DIR}/../common/sqlite3.lib
            bcrypt
            crypt32
            wintrust
            advapi32
            ws2_32
            shell32
        )
    endif()
else()
    message(WARNING "Qt6/Qt5 not found on system. VantorUI target will be configured when Qt package is provided via vcpkg or system PATH.")
endif()
