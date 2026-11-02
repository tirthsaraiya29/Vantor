#include <windows.h>
#include <psapi.h>
#include <thread>
#include <chrono>

namespace chrono = std::chrono;

// ---------------- CONFIG ----------------
constexpr int LOOP_DELAY_MS = 5 * 60 * 1000; // 5 minutes
constexpr SIZE_T MIN_FREE_RAM_MB = 200;      // target free RAM

void run_ram_boost_background() {
    while (true) {
        try {
            // Get system memory info
            MEMORYSTATUSEX memInfo{};
            memInfo.dwLength = sizeof(memInfo);
            if (GlobalMemoryStatusEx(&memInfo)) {
                SIZE_T availMB = memInfo.ullAvailPhys / (1024 * 1024);
                if (availMB < MIN_FREE_RAM_MB) {
                    // Enumerate processes and softly reduce memory pressure
                    DWORD processes[1024], needed;
                    if (EnumProcesses(processes, sizeof(processes), &needed)) {
                        int count = needed / sizeof(DWORD);
                        for (int i = 0; i < count; ++i) {
                            HANDLE h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, processes[i]);
                            if (h) {
                                // Ask OS to trim working set (soft RAM boost)
                                SetProcessWorkingSetSize(h, (SIZE_T)-1, (SIZE_T)-1);
                                CloseHandle(h);
                            }
                        }
                    }
                }
            }
        } catch (...) { /* resilient to all errors */ }

        std::this_thread::sleep_for(chrono::milliseconds(LOOP_DELAY_MS));
    }
}
