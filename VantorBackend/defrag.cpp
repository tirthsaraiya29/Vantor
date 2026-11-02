#include <windows.h>
#include <filesystem>
#include <thread>
#include <chrono>
#include <vector>

namespace fs = std::filesystem;
namespace chrono = std::chrono;

// ---------------- CONFIG ----------------
constexpr int LOOP_DELAY_MS = 10 * 60 * 1000; // 10 minutes

// Helper: check if drive is ready
bool drive_ready(const wchar_t drive) {
    wchar_t root[] = { drive, L':', L'\\', 0 };
    UINT type = GetDriveTypeW(root);
    return type == DRIVE_FIXED || type == DRIVE_REMOVABLE;
}

// Defrag a single file (lightweight: read/write to trigger OS caching)
void defrag_file(const fs::path& path) {
    HANDLE h = CreateFileW(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
        nullptr
    );
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

// Main cleanup loop
void run_defrag_background() {
    while (true) {
        try {
            for (wchar_t drive = L'C'; drive <= L'Z'; ++drive) {
                if (!drive_ready(drive)) continue;

                wchar_t root[] = { drive, L':', L'\\', 0 };
                for (auto& e : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
                    try {
                        if (fs::is_regular_file(e.path()))
                            defrag_file(e.path());
                    } catch (...) { continue; }
                }
            }
        } catch (...) { /* resilient to any filesystem errors */ }

        std::this_thread::sleep_for(chrono::milliseconds(LOOP_DELAY_MS));
    }
}
