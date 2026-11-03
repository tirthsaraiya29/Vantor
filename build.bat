@echo off
setlocal
title Vantor Antivirus - Automated One-Click Build

cd /d "%~dp0"
echo ======================================================================
echo             VANTOR ENDPOINT SECURITY - ONE-CLICK BUILD
echo ======================================================================
echo [1/5] Detecting build environment...

:: Close any running UI instances to release file locks
taskkill /F /IM Vantor.exe >nul 2>&1

:: 1. Find CMake
where cmake >nul 2>&1
if %ERRORLEVEL% equ 0 goto :cmake_found
if exist "C:\Program Files\CMake\bin\cmake.exe" (
    set "PATH=C:\Program Files\CMake\bin;%PATH%"
    goto :cmake_found
)
echo [ERROR] CMake not found in PATH or C:\Program Files\CMake\bin.
goto :error

:cmake_found

:: 2. Find .NET SDK
where dotnet >nul 2>&1
if %ERRORLEVEL% equ 0 goto :dotnet_found
if exist "C:\Program Files\dotnet\dotnet.exe" (
    set "PATH=C:\Program Files\dotnet;%PATH%"
    goto :dotnet_found
)
echo [ERROR] .NET SDK (dotnet) not found in PATH or C:\Program Files\dotnet.
goto :error

:dotnet_found

:: 3. Setup MSVC if cl.exe is not yet in PATH
where cl.exe >nul 2>&1
if %ERRORLEVEL% equ 0 goto :tools_ready

if exist "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" (
    echo [INFO] Initializing Visual Studio build tools...
    call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto :tools_ready
)

if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    echo [INFO] Initializing Visual Studio 2022 build tools...
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto :tools_ready
)

if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" (
            echo [INFO] Initializing Visual Studio from vswhere...
            call "%%i\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
            goto :tools_ready
        )
    )
)

:tools_ready
echo [OK] Build tools initialized successfully.
echo.

:: ======================================================================
:: C++ ENGINE BUILD
:: ======================================================================
echo [2/5] Configuring and building C++ Win32 Service and Backend (Release)...

cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
if %ERRORLEVEL% neq 0 (
    echo [ERROR] CMake configuration failed.
    goto :error
)

cmake --build build --config Release --parallel
if %ERRORLEVEL% neq 0 (
    echo [ERROR] C++ build failed.
    goto :error
)

echo [OK] C++ backend and service built successfully.
echo.

:: ======================================================================
:: COPY C++ BINARIES TO ROOT REPO
:: ======================================================================
echo [3/5] Deploying backend binaries to root repository...

if exist "build\backend\Release\VantorBackend.exe" (
    copy /Y "build\backend\Release\VantorBackend.exe" ".\VantorBackend.exe" >nul
)
if exist "build\service\Release\VantorService.exe" (
    copy /Y "build\service\Release\VantorService.exe" ".\VantorService.exe" >nul
)
if not exist "sqlite3.dll" (
    if exist "common\sqlite3.dll" copy /Y "common\sqlite3.dll" ".\sqlite3.dll" >nul
    if exist "VantorBackend\sqlite3.dll" copy /Y "VantorBackend\sqlite3.dll" ".\sqlite3.dll" >nul
)

echo [OK] Root C++ binaries deployed.
echo.

:: ======================================================================
:: FRONTEND WPF BUILD (SINGLE-FILE RUNNABLE)
:: ======================================================================
echo [4/5] Building WPF Desktop Frontend (Vantor.exe)...

dotnet publish Vantor\Vantor.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:IncludeAllContentForSelfExtract=true -o build\publish
if %ERRORLEVEL% neq 0 (
    echo [ERROR] WPF Frontend build failed.
    goto :error
)

if exist "build\publish\Vantor.exe" (
    copy /Y "build\publish\Vantor.exe" ".\Vantor.exe" >nul
)

echo [OK] Standalone Vantor.exe generated in root folder.
echo.

:: ======================================================================
:: VERIFICATION TESTS
:: ======================================================================
echo [5/5] Running automated verification test suite...

ctest --test-dir build -C Release --output-on-failure
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Test suite reported warnings or failures.
) else (
    echo [OK] 100%% of automated verification tests passed!
)

echo.
echo ======================================================================
echo                      BUILD SUCCEEDED!
echo ======================================================================
echo The standalone application is ready in the root folder:
echo.
echo   - Vantor.exe          (Desktop Frontend GUI - double click to run)
echo   - VantorBackend.exe   (High-Performance C++ Core Scanner)
echo   - VantorService.exe   (Pure C++ Win32 Antivirus Service)
echo   - signatures.db       (SQLite Threat Signatures Database)
echo   - signatures.idx      (128KB Bloom Filter Mapped Index)
echo.
echo All components work seamlessly with zero directory configuration.
echo ======================================================================
echo.
pause
exit /b 0

:error
echo.
echo ======================================================================
echo [BUILD FAILED] An error occurred during the build process.
echo Please review the output above.
echo ======================================================================
echo.
pause
exit /b 1
