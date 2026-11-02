#include "process_monitor.h"
#include "telemetry.h"
#include <map>
#include <mutex>
#include <thread>
#include <windows.h>
#include <tlhelp32.h>

static std::mutex pm_mutex;
static std::map<DWORD, DWORD> pid_to_ppid;

void init_process_monitor() {
    std::lock_guard<std::mutex> lock(pm_mutex);
    pid_to_ppid.clear();
    init_telemetry();
}

static DWORD get_parent_pid(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD ppid = 0;
    do {
        if (pe.th32ProcessID == pid) { ppid = pe.th32ParentProcessID; break; }
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return ppid;
}

void monitor_processes() {
    std::thread([]() {
        while (true) {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) { std::this_thread::sleep_for(std::chrono::seconds(5)); continue; }

            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe)) {
                do {
                    std::lock_guard<std::mutex> lock(pm_mutex);
                    if (pid_to_ppid.find(pe.th32ProcessID) == pid_to_ppid.end()) {
                        pid_to_ppid[pe.th32ProcessID] = pe.th32ParentProcessID;
                        std::vector<std::string> args = {}; // Placeholder: could be improved by reading command line
                        register_process_creation(pe.szExeFile, args, pe.th32ParentProcessID);
                    }
                } while (Process32Next(hSnapshot, &pe));
            }

            CloseHandle(hSnapshot);
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
        }).detach();
}

void register_process_creation(const std::string& exe, const std::vector<std::string>& args, int ppid) {
    record_process_start(exe, args, ppid);
}
