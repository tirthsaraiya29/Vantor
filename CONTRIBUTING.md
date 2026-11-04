# Contributing to Vantor Endpoint Security

Thank you for your interest in contributing to Vantor Antivirus! Vantor is an enterprise-grade Windows antivirus platform engineered with native C++20 Win32 system services, memory-mapped Bloom filter indices, multi-threaded work-stealing scanners, dynamic XGBoost heuristic modeling, and a modern WPF desktop frontend.

---

## 1. Codebase Architecture

The repository is modularized into distinct security domains:

| Subsystem | Location | Description |
| :--- | :--- | :--- |
| **Windows Service** | `service/` | Runs with `NT AUTHORITY\SYSTEM` privileges. Hosts the Named Pipe IPC daemon, Real-Time Protection (`ReadDirectoryChangesW`), memory auditor, and persistence scanners. |
| **Core Scanner Backend** | `backend/` | High-performance C++ engine containing the hybrid SQLite + memory-mapped Bloom filter (`signatures.idx`), Zip-bomb heuristics, Task Scheduler integration, and REST/gRPC daemon. |
| **Shared Common** | `common/` | Crypto primitives (`BCrypt` AES-256-GCM, SHA-256), Authenticode WinTrust signature verifiers, structured rolling logger, and serialization models. |
| **WPF Frontend** | `Vantor/` | Production .NET 10 WPF desktop application communicating with the backend and Windows service via Named Pipe IPC. |
| **Qt UI** | `ui/` | Native C++20 cross-platform frameless desktop interface with radar scanning animation, quarantine vault, and settings. |

---

## 2. Prerequisites & Development Environment

To build and debug Vantor locally, ensure you have:

1. **Operating System**: Windows 10 (version 2004+) or Windows 11 x64.
2. **Visual Studio**: Visual Studio 2022 or Visual Studio v18 with:
   - "Desktop development with C++"
   - MSVC v143 or newer x64/x86 build tools
   - Windows 10/11 SDK (10.0.22000.0 or higher)
3. **CMake**: Version 3.20 or newer.
4. **.NET SDK**: .NET 10.0 SDK for the WPF desktop client.
5. **Git**: Standard git CLI.

---

## 3. Quickstart One-Click Build

Clone the repository and execute `build.bat`:

```cmd
git clone https://github.com/tirthsaraiya29/Vantor.git
cd Vantor
build.bat
```

The script will automatically:
1. Detect MSVC developer tools (`vcvars64.bat`), CMake, and .NET.
2. Build `VantorService.exe`, `VantorBackend.exe`, and `VantorTests.exe` in `Release` configuration.
3. Publish and package the standalone `Vantor.exe` WPF frontend into the project root.
4. Run the automated CTest verification suite.

---

## 4. Coding & Security Standards

Security software must adhere to stringent quality standards:

- **Strict Warnings as Errors**: All C++ code is built with `/W4 /permissive- /sdl /guard:cf /GS /Gy`. Zero warnings are permitted.
- **Modern C++20**: Favor RAII, `std::unique_ptr`, `std::shared_mutex`, `std::span`, and smart pointers over raw memory management.
- **Unicode Win32 APIs**: Always call wide-character Win32 APIs (`CreateFileW`, `OpenProcessToken`, `RegOpenKeyExW`) instead of ANSI variants.
- **Cryptographic Security**:
  - Never implement ad-hoc encryption. Use `BCryptEncrypt` / `BCryptDecrypt` with AES-256-GCM.
  - Never store plain text passwords or secrets. Protect all credentials with Windows Data Protection API (DPAPI).
  - Use constant-time comparisons (`ConstantTimeAuthCheck` / XOR accumulator) for security tokens to eliminate timing side-channels.
- **Thread Safety**: Access to shared stores, event logs, and quarantine maps must be synchronized via `std::shared_mutex` or atomic operations.

---

## 5. Running Automated Verification Tests

Before submitting code, ensure all automated tests pass:

```cmd
# Run via CTest
ctest --test-dir build -C Release --output-on-failure

# Or execute test runner directly:
build\backend\tests\Release\VantorTests.exe
```

All 22+ security, cryptographic, heuristic, and regression unit tests must pass with a 100% success rate.

---

## 6. Submitting a Pull Request

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-new-feature
   ```
2. Commit your changes with descriptive messages:
   ```bash
   git commit -m "feat(scanner): add parallel directory worker pool"
   ```
3. Push to your fork and submit a Pull Request against `main`.
4. Ensure GitHub Actions CI passes (MSVC compilation, .NET build, Authenticode signing, CodeQL static analysis).
