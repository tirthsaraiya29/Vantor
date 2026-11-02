#include "VantorBackend.h"
#include "quarantine.h"
#include "mlinference.h"

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <psapi.h>
#include <shlobj.h>
#include <shlwapi.h>

#include <string>
#include <vector>
#include <thread>
#include <algorithm>
#include <iostream>
#include <regex>
#include <fstream>
#include <limits>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

// ======================================================
// GLOBALS & GUIDS
// ======================================================

static SafeDB* g_safe = nullptr;
static MLInference* g_ml = nullptr;
static ScanHistoryDB* g_history = nullptr;
static DWORD g_self_pid = 0;
static TRACEHANDLE g_traceSessionHandle = 0;

static const GUID KERNEL_PROCESS_PROVIDER =
{ 0x22FB2CD6, 0x0E7B, 0x422B,{0xA0,0xC7,0x2F,0xAD,0x1F,0xD0,0xE7,0x16} };

static const GUID TASK_SCHED_PROVIDER =
{ 0xde7b24dc, 0x1222, 0x47b0,{0xae,0x3d,0xbd,0x53,0x4f,0x0c,0x40,0x97} };

// ======================================================
// HELPERS
// ======================================================

bool IsRunAsAdmin() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            fRet = elevation.TokenIsElevated;
        }
    }
    if (hToken) CloseHandle(hToken);
    return fRet;
}

void ElevateNow() {
    if (IsRunAsAdmin()) return;
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath))) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.nShow = SW_NORMAL;
        if (!ShellExecuteExW(&sei)) {
            std::cerr << "[!] UAC Elevation failed.\n";
        }
        else {
            exit(0);
        }
    }
}

static std::string utf16_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string str(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], size, nullptr, nullptr);
    str.pop_back();
    return str;
}

static std::string resolve_target(std::string path) {
    if (path.empty()) return "";
    path.erase(std::remove(path.begin(), path.end(), '\"'), path.end());

    if (path.length() > 4 && _stricmp(path.c_str() + path.length() - 4, ".lnk") == 0) {
        std::wstring wpath(path.begin(), path.end());
        IShellLinkW* psl;
        CoInitialize(NULL);
        if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
            IID_IShellLinkW, (LPVOID*)&psl))) {

            IPersistFile* ppf;
            if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf))) {
                if (SUCCEEDED(ppf->Load(wpath.c_str(), STGM_READ))) {
                    wchar_t szTarget[MAX_PATH];
                    if (SUCCEEDED(psl->GetPath(szTarget, MAX_PATH, NULL, 0))) {
                        path = utf16_to_utf8(szTarget);
                    }
                }
                ppf->Release();
            }
            psl->Release();
        }
        CoUninitialize();
    }
    return path;
}

// ======================================================
// DISPATCHER
// ======================================================

static void dispatch_scan_and_action(std::string path, std::string source_tag, DWORD pid = 0) {
    std::string actual_path = resolve_target(path);
    if (actual_path.empty() || !PathFileExistsA(actual_path.c_str())) return;

    int sid = create_scan_session(*g_history, "rtp", source_tag);
    ScanResult r = scan_file(actual_path, *g_safe, *g_ml, *g_history, sid, source_tag);

    if (r.is_malicious) {
        if (pid != 0 && pid != GetCurrentProcessId()) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProcess) {
                TerminateProcess(hProcess, 1);
                CloseHandle(hProcess);
                std::cout << "[!] KILLED MALICIOUS PROCESS PID: " << pid << "\n";
            }
        }
        handle_malicious_file(actual_path, source_tag, r.sha256, r.sha512);
        std::cout << "[!] BLOCKED: " << actual_path << " (" << source_tag << ")\n";
    }
}

// ======================================================
// REGISTRY MONITOR
// ======================================================

static void monitor_registry_persistence() {
    auto watch_key = [](HKEY root, std::wstring subkey) {
        HKEY hKey;
        if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_NOTIFY | KEY_READ, &hKey) == ERROR_SUCCESS) {
            HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
            while (hEvent != NULL) {
                if (RegNotifyChangeKeyValue(hKey, TRUE,
                    REG_NOTIFY_CHANGE_LAST_SET, hEvent, TRUE) == ERROR_SUCCESS) {

                    WaitForSingleObject(hEvent, INFINITE);
                    DWORD index = 0;
                    wchar_t valName[16383];
                    BYTE data[MAX_PATH * 2];
                    DWORD valNameLen = 16383, dataLen = sizeof(data), type;

                    while (RegEnumValueW(hKey, index++, valName, &valNameLen,
                        NULL, &type, data, &dataLen) == ERROR_SUCCESS) {

                        if (type == REG_SZ || type == REG_EXPAND_SZ) {
                            std::string cmd = utf16_to_utf8((wchar_t*)data);
                            std::regex path_regex(R"(([a-zA-Z]:\\[^ "]+))");
                            std::smatch match;
                            if (std::regex_search(cmd, match, path_regex)) {
                                dispatch_scan_and_action(match[1].str(), "RTP-REG");
                            }
                        }
                        valNameLen = 16383;
                        dataLen = sizeof(data);
                    }
                }
            }
            RegCloseKey(hKey);
        }
        };

    std::thread(watch_key, HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run").detach();
    std::thread(watch_key, HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run").detach();
}

// ======================================================
// FILE SYSTEM MONITOR
// ======================================================

static void start_filesystem_rtp() {
    std::vector<std::wstring> targets;
    wchar_t path[MAX_PATH];

    if (SHGetSpecialFolderPathW(NULL, path, CSIDL_STARTUP, FALSE)) targets.push_back(path);
    if (SHGetSpecialFolderPathW(NULL, path, CSIDL_COMMON_STARTUP, FALSE)) targets.push_back(path);
    if (SHGetSpecialFolderPathW(NULL, path, CSIDL_DESKTOPDIRECTORY, FALSE)) targets.push_back(path);

    targets.push_back(L"C:\\Windows\\System32\\Tasks");

    for (const auto& dir : targets) {
        std::thread([dir]() {
            HANDLE hDir = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

            if (hDir == INVALID_HANDLE_VALUE) return;

            BYTE buffer[4096];
            DWORD bytes;

            while (ReadDirectoryChangesW(hDir, buffer, sizeof(buffer), TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytes, NULL, NULL)) {

                auto* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
                while (info) {
                    if (info->Action == FILE_ACTION_ADDED ||
                        info->Action == FILE_ACTION_RENAMED_NEW_NAME) {

                        std::wstring fname(info->FileName,
                            info->FileNameLength / sizeof(wchar_t));
                        std::string full_path =
                            utf16_to_utf8(dir + L"\\" + fname);

                        if (full_path.find("System32\\Tasks") != std::string::npos) {
                            std::ifstream file(full_path);
                            std::string line;
                            while (std::getline(file, line)) {
                                size_t s = line.find("<Command>");
                                size_t e = line.find("</Command>");
                                if (s != std::string::npos && e != std::string::npos) {
                                    std::string cmd =
                                        line.substr(s + 9, e - (s + 9));
                                    dispatch_scan_and_action(cmd, "RTP-TASK-PERSIST");
                                }
                            }
                        }
                        else {
                            dispatch_scan_and_action(full_path, "RTP-FS");
                        }
                    }

                    if (!info->NextEntryOffset) break;
                    info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                        (BYTE*)info + info->NextEntryOffset);
                }
            }
            CloseHandle(hDir);
            }).detach();
    }
}

// ======================================================
// ETW CALLBACK (FIXED)
// ======================================================

static void WINAPI on_etw_event(EVENT_RECORD* rec) {
    if (!rec) return;

    if (IsEqualGUID(rec->EventHeader.ProviderId, KERNEL_PROCESS_PROVIDER) &&
        rec->EventHeader.EventDescriptor.Id == 1) {

        ULONG infoSize = 0;
        if (TdhGetEventInformation(rec, 0, nullptr, nullptr, &infoSize)
            == ERROR_INSUFFICIENT_BUFFER) {

            std::vector<BYTE> infoBuf(infoSize);
            auto pInfo = (PTRACE_EVENT_INFO)infoBuf.data();

            if (TdhGetEventInformation(rec, 0, nullptr, pInfo, &infoSize)
                == ERROR_SUCCESS) {

                for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                    PWSTR propName = (PWSTR)((PBYTE)pInfo +
                        pInfo->EventPropertyInfoArray[i].NameOffset);

                    if (wcscmp(propName, L"ImageFileName") == 0) {

                        PROPERTY_DATA_DESCRIPTOR desc = {};
                        desc.PropertyName = (ULONGLONG)propName;
                        desc.ArrayIndex = ULONG_MAX;

                        ULONG dataSize = 0;
                        if (TdhGetPropertySize(rec, 0, nullptr, 1, &desc, &dataSize)
                            == ERROR_SUCCESS) {

                            std::vector<BYTE> data(dataSize);
                            if (TdhGetProperty(rec, 0, nullptr, 1,
                                &desc, dataSize, data.data()) == ERROR_SUCCESS) {

                                std::wstring wPath = (PWSTR)data.data();
                                dispatch_scan_and_action(
                                    utf16_to_utf8(wPath),
                                    "RTP-PROC",
                                    rec->EventHeader.ProcessId);
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
}

// ======================================================
// ENTRY POINT
// ======================================================

void run_rtp_engine(SafeDB& safe, const MLInference& ml, ScanHistoryDB& history) {
    ElevateNow();

    g_safe = &safe;
    g_ml = const_cast<MLInference*>(&ml);
    g_history = &history;
    g_self_pid = GetCurrentProcessId();

    std::cout << "[*] Real-Time Protection ACTIVE (Admin Mode)\n";

    start_filesystem_rtp();
    monitor_registry_persistence();

    const wchar_t* sessionName = L"VantorRTPSession";
    auto* props = (EVENT_TRACE_PROPERTIES*)
        malloc(sizeof(EVENT_TRACE_PROPERTIES) + 512);
    if (!props) return;

    memset(props, 0, sizeof(EVENT_TRACE_PROPERTIES) + 512);
    props->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 512;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ControlTraceW(0, sessionName, props, EVENT_TRACE_CONTROL_STOP);

    if (StartTraceW(&g_traceSessionHandle, sessionName, props) == ERROR_SUCCESS) {
        EnableTraceEx2(g_traceSessionHandle, &KERNEL_PROCESS_PROVIDER,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
            0, 0, 0, nullptr);

        std::thread([]() {
            EVENT_TRACE_LOGFILEW trace = {};
            trace.LoggerName = (LPWSTR)L"VantorRTPSession";
            trace.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            trace.EventRecordCallback = on_etw_event;

            TRACEHANDLE hTrace = OpenTraceW(&trace);
            if (hTrace != INVALID_PROCESSTRACE_HANDLE) {
                ProcessTrace(&hTrace, 1, NULL, NULL);
                CloseTrace(hTrace);
            }
            }).detach();
    }
    free(props);
}
