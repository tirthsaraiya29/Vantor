// ======================================================
// ZERO-TRUST RANSOMWARE BEHAVIOR DETECTOR (USER-MODE EDR)
// ETW + TDH | Continuous | High accuracy
// ======================================================

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <psapi.h>

#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <cmath>
#include <fstream>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Kernel32.lib")

// ======================================================
// GLOBALS
// ======================================================

std::atomic<bool> g_running(true);
CRITICAL_SECTION g_lock;
HANDLE g_block_event = nullptr;
DWORD g_self_pid = 0;

// ======================================================
// KERNEL FILE PROVIDER
// ======================================================

static const GUID KERNEL_FILE_PROVIDER =
{ 0xEDD08927, 0x9CC4, 0x4E65,{ 0x81,0x7D,0xA1,0x79,0x9E,0xAF,0x1B,0x07 } };

// ======================================================
// CONFIG
// ======================================================

constexpr double ENTROPY_THRESHOLD = 7.2;
constexpr int SCORE_KILL = 120;
constexpr int BURST_WRITE_THRESHOLD = 40;   // writes/sec
constexpr int GC_TTL_MS = 20000;

// ======================================================
// BEHAVIOR STATE
// ======================================================

struct TimedEvent {
    ULONGLONG t;
};

struct BehaviorState {
    int score = 0;
    int writes = 0;
    int renames = 0;
    int entropy_hits = 0;
    ULONGLONG first_seen = 0;
    ULONGLONG last_seen = 0;

    std::unordered_map<std::wstring, int> ext_entropy_hits;
    std::unordered_set<std::wstring> directories;
    std::deque<TimedEvent> events;
};

std::unordered_map<DWORD, BehaviorState> g_state;

// ======================================================
// UTILS
// ======================================================

std::wstring get_extension(const std::wstring& p) {
    auto pos = p.find_last_of(L'.');
    return pos == std::wstring::npos ? L"" : p.substr(pos);
}

std::wstring get_directory(const std::wstring& p) {
    auto pos = p.find_last_of(L"\\/");
    return pos == std::wstring::npos ? L"" : p.substr(0, pos);
}

std::wstring process_name(DWORD pid) {
    WCHAR buf[MAX_PATH] = L"<unknown>";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        GetModuleFileNameExW(h, nullptr, buf, MAX_PATH);
        CloseHandle(h);
    }
    return buf;
}

// ======================================================
// ENTROPY
// ======================================================

double entropy(const std::vector<BYTE>& d) {
    if (d.empty()) return 0.0;
    int freq[256] = { 0 };
    for (BYTE b : d) freq[b]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / d.size();
        e -= p * log2(p);
    }
    return e;
}

bool sample_entropy(const std::wstring& path, double& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    std::vector<BYTE> buf(32768);
    f.read((char*)buf.data(), buf.size());
    size_t n = f.gcount();
    if (n < 4096) return false;

    buf.resize(n);
    out = entropy(buf);
    return true;
}

// ======================================================
// BEHAVIOR ENGINE
// ======================================================

void decay(BehaviorState& b, ULONGLONG now) {
    while (!b.events.empty() && now - b.events.front().t > 3000) {
        b.score = max(0, b.score - 3);
        b.events.pop_front();
    }
}

void evaluate(DWORD pid) {
    if (pid == g_self_pid) return;

    EnterCriticalSection(&g_lock);
    auto it = g_state.find(pid);
    if (it == g_state.end()) {
        LeaveCriticalSection(&g_lock);
        return;
    }

    auto& b = it->second;
    ULONGLONG now = GetTickCount64();
    decay(b, now);

    double life = max(1.0, (now - b.first_seen) / 1000.0);
    double rate = b.writes / life;

    if (rate > BURST_WRITE_THRESHOLD) b.score += 35;
    if (b.directories.size() >= 3) b.score += 25;
    if (b.entropy_hits >= 3) b.score += 30;

    for (auto& kv : b.ext_entropy_hits) {
        if (kv.second >= 3) b.score += 20;
    }

    if (b.score >= SCORE_KILL) {
        std::wcout << L"\n[RBD] 🚨 RANSOMWARE BEHAVIOR CONFIRMED\n";
        std::wcout << L" PID   : " << pid << L"\n";
        std::wcout << L" BIN   : " << process_name(pid) << L"\n";
        std::wcout << L" SCORE : " << b.score << L"\n";

        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) {
            TerminateProcess(h, 1);
            CloseHandle(h);
            std::wcout << L" ACTION: PROCESS TERMINATED\n";
        }
        g_state.erase(pid);
    }

    LeaveCriticalSection(&g_lock);
}

void record(DWORD pid, const std::wstring& path, bool rename) {
    if (pid == g_self_pid) return;

    EnterCriticalSection(&g_lock);

    auto& b = g_state[pid];
    ULONGLONG now = GetTickCount64();
    if (!b.first_seen) b.first_seen = now;
    b.last_seen = now;

    b.writes++;
    if (rename) b.renames++;

    b.directories.insert(get_directory(path));
    b.events.push_back({ now });

    double e;
    if (sample_entropy(path, e) && e >= ENTROPY_THRESHOLD) {
        b.entropy_hits++;
        b.ext_entropy_hits[get_extension(path)]++;
    }

    LeaveCriticalSection(&g_lock);
    evaluate(pid);
}

// ======================================================
// TDH PATH EXTRACTION
// ======================================================

std::wstring extract_path(EVENT_RECORD* ev) {
    DWORD size = 0;
    TdhGetEventInformation(ev, 0, nullptr, nullptr, &size);
    if (!size) return L"";

    std::vector<BYTE> buf(size);
    auto info = (PTRACE_EVENT_INFO)buf.data();
    if (TdhGetEventInformation(ev, 0, nullptr, info, &size) != ERROR_SUCCESS)
        return L"";

    for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
        auto& prop = info->EventPropertyInfoArray[i];
        PWSTR name = (PWSTR)((PBYTE)info + prop.NameOffset);
        if (_wcsicmp(name, L"FileName") == 0) {
            PROPERTY_DATA_DESCRIPTOR desc{};
            desc.PropertyName = (ULONGLONG)name;
            desc.ArrayIndex = ULONG_MAX;

            DWORD sz = 0;
            TdhGetPropertySize(ev, 0, nullptr, 1, &desc, &sz);
            if (!sz) return L"";

            std::vector<BYTE> out(sz);
            if (TdhGetProperty(ev, 0, nullptr, 1, &desc, sz, out.data()) == ERROR_SUCCESS)
                return std::wstring((WCHAR*)out.data());
        }
    }
    return L"";
}

// ======================================================
// ETW CALLBACK
// ======================================================

VOID WINAPI etw_cb(EVENT_RECORD* ev) {
    if (!ev) return;

    DWORD pid = ev->EventHeader.ProcessId;
    if (!pid || pid == g_self_pid) return;

    if (ev->EventHeader.ProviderId == KERNEL_FILE_PROVIDER) {
        std::wstring path = extract_path(ev);
        if (!path.empty()) {
            std::wcout << L"[ETW] PID " << pid << L" -> " << path << L"\n";
            record(pid, path, false);
        }
    }
}

// ======================================================
// ETW THREAD
// ======================================================

void etw_thread() {
    std::wcout << L"[RBD] ETW thread starting...\n";

    EVENT_TRACE_PROPERTIES props{};
    props.Wnode.BufferSize = sizeof(props);
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    TRACEHANDLE session = 0;
    StartTrace(&session, L"RBD_SESSION", &props);

    ENABLE_TRACE_PARAMETERS p{};
    p.Version = ENABLE_TRACE_PARAMETERS_VERSION;

    EnableTraceEx2(
        session,
        &KERNEL_FILE_PROVIDER,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        &p
    );

    EVENT_TRACE_LOGFILE log{};
    log.LoggerName = (LPWSTR)L"RBD_SESSION";
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = etw_cb;

    TRACEHANDLE h = OpenTrace(&log);
    ProcessTrace(&h, 1, nullptr, nullptr);
}

// ======================================================
// MAIN
// ======================================================

int wmain() {
    g_self_pid = GetCurrentProcessId();
    InitializeCriticalSection(&g_lock);

    g_block_event = CreateEvent(nullptr, TRUE, FALSE, nullptr);

    std::wcout << L"[RBD] ZERO‑TRUST RBD ACTIVE\n";
    std::wcout << L"[RBD] PID: " << g_self_pid << L"\n";

    std::thread(etw_thread).detach();

    // HARD BLOCK — WILL NOT EXIT
    WaitForSingleObject(g_block_event, INFINITE);
    return 0;
}
