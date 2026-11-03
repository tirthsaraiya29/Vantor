# Vantor Enterprise Security & Hardening Checklist

This document details the complete threat model, security posture, and defense-in-depth mechanisms implemented in Vantor.

---

## 1. Process & Memory Hardening

| Mitigation | Compiler / Linker Flag | Purpose |
|---|---|---|
| **Control Flow Guard (CFG)** | `/guard:cf` (CL & Linker) | Validates indirect call targets to thwart ROP/JOP exploits. |
| **Data Execution Prevention (DEP)** | `/NXCOMPAT` | Marks non-executable pages (stack, heap) with No-Execute bit. |
| **High-Entropy ASLR** | `/DYNAMICBASE`, `/HIGHENTROPYVA` | Randomizes 64-bit virtual memory addresses across a 1 TB entropy space. |
| **Stack Buffer Security Checks** | `/GS` | Injects stack canaries to detect and terminate on buffer overflows. |
| **Strict Conformance** | `/permissive-`, `/W4` | Enforces ISO C++ compliance and surfaces undefined behavior warnings. |
| **Structured Exception SDL** | `/sdl` | Enables Microsoft Security Development Lifecycle runtime checks. |

---

## 2. Access Control & Privilege Boundaries

- [x] **Service Isolation**: The Windows Service runs as `NT AUTHORITY\SYSTEM`. The Qt UI runs as the standard interactive logged-in user.
- [x] **Least Privilege Named Pipes**:
  - Named pipe is created with `PIPE_REJECT_REMOTE_CLIENTS` to prevent LAN/SMB hijacking.
  - SDDL DACL `D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)` explicitly restricts write commands to interactive users and administrators.
- [x] **Configuration Encryption**: `config.json` is protected on disk using Windows DPAPI with `CRYPTPROTECT_LOCAL_MACHINE` scope. Non-elevated accounts cannot decrypt or forge policy settings.
- [x] **Quarantine Encryption**: Quarantined files are encrypted with AES-256-GCM. The 256-bit symmetric key is stored in DPAPI-protected format in `quarantine/master.key`.

---

## 3. User-Mode Anti-Tamper & Integrity Verification

- [x] **Authenticode Signature Verification**: `WinVerifyTrust` validates the cryptographic signature of all core binaries on disk.
- [x] **In-Memory Code Integrity**:
  - The service locates its own `.text` PE section virtual address.
  - Compares the active memory hash against the startup baseline to detect runtime memory patching or inline function hooks.
- [x] **Inline Hook Detection**:
  - Scans function preambles of critical Win32 APIs (`NtQueryInformationProcess`, `NtSetInformationThread`, `CreateFileW`, `OpenProcess`, `VirtualAllocEx`, `TerminateProcess`).
  - Flags JMP/INT3 opcodes (`0xE9`, `0xEB`, `0xCC`, `0xFF 0x25`).
- [x] **Anti-Debugging Defenses**:
  - `IsDebuggerPresent()` & `CheckRemoteDebuggerPresent()`.
  - PEB `BeingDebugged` check via `__readgsqword(0x60)` on x64.
  - Native NT query checks: `ProcessDebugPort`, `ProcessDebugObjectHandle`, `ProcessDebugFlags`.
  - Hardware breakpoint check: queries thread context debug registers `Dr0`-`Dr3`.
  - Hides watchdog threads via `NtSetInformationThread(ThreadHideFromDebugger)`.
- [x] **Anti-VM Heuristics**:
  - RDTSC instruction cycle measurement detects hypervisor VM-Exit traps on `CPUID`.
  - Hypervisor signature inspection for sandbox evasion awareness.
- [x] **Self-Healing Watchdog**:
  - `ReadDirectoryChangesW` detects file replacement or deletion.
  - Restores altered files immediately from `C:\ProgramData\Vantor\ATBackup\`.

---

## 4. Archive & Zip-Bomb Defense

- [x] **Zero-Decompression Inspection**: Archive structure is inspected purely by reading header metadata without decompressing payload bytes.
- [x] **Compression Ratio Cap**: Archives exceeding a 10.0x compression ratio are rejected.
- [x] **Absolute Volume Cap**: Archives with > 1 GB uncompressed content or > 10,000 files are blocked.
- [x] **Path Traversal Mitigation**: Entries containing `../` or `..\` sequences are flagged.
- [x] **Overlapping Offset Detection**: Rejects archives where multiple directory entries point to identical compressed data blocks.

---

## 5. Communications & API Hardening

- [x] **Protected gRPC**: Exposes TLS-wrapped endpoints with bearer token authentication (`x-vantor-auth`).
- [x] **Input Validation**: All JSON and RPC messages are bound to strict length limits (10 MB maximum payload) to prevent memory exhaustion denial of service.
- [x] **Safe Database Queries**: All SQLite queries use parameterized prepared statements (`sqlite3_bind_text`, `sqlite3_bind_int64`) with zero string concatenation.
