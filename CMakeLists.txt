cmake_minimum_required(VERSION 3.20)
project(VantorSuite CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

message(STATUS "=======================================================")
message(STATUS "Configuring Vantor Enterprise Antivirus Solution (Win64)")
message(STATUS "=======================================================")

# Global MSVC Security Hardening & Optimizations
if(MSVC)
    add_compile_options(
        /W4
        /permissive-
        /guard:cf       # Control Flow Guard (CFG)
        /GS             # Buffer Security Check
        /Gy             # Separate Functions for Linker
        /sdl            # Additional Security Development Lifecycle checks
        /utf-8          # UTF-8 source and execution character set
    )
    add_link_options(
        /DYNAMICBASE    # Address Space Layout Randomization (ASLR)
        /HIGHENTROPYVA  # 64-bit ASLR
        /NXCOMPAT       # Data Execution Prevention (DEP)
        /GUARD:CF       # Link-time Control Flow Guard
    )
endif()

enable_testing()

# Core Subprojects
add_subdirectory(service)
add_subdirectory(backend)
add_subdirectory(ui)

message(STATUS "Vantor build configuration complete.")
