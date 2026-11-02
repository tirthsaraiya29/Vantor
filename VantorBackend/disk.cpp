// disk.cpp
#include <windows.h>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <atomic>
#include <thread>
#include <iostream>

namespace fs = std::filesystem;
namespace chrono = std::chrono;

// =======================================================
// ADMIN ELEVATION CHECK (UAC POPUP)
// =======================================================
#pragma comment(linker, "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")

// ------------------ PER-DIR CAPS ------------------
constexpr uint64_t CAP_D3DS_MB = 100;
constexpr uint64_t CAP_TEMP_MB = 200;
constexpr uint64_t CAP_DUMPS_MB = 100;
constexpr uint64_t CAP_WIN_TEMP_MB = 200;
constexpr uint64_t CAP_UPDATES_MB = 500;

// ------------------ AGE THRESHOLDS ------------------
constexpr uint64_t AGE_GENERAL_DAYS = 5;
constexpr uint64_t AGE_JUNK_HOURS = 24;

// ------------------ SIZE HEURISTICS ------------------
constexpr uint64_t BIG_SHADER_MB = 5;

// ------------------ SCAN LIMITS ------------------
constexpr int MAX_DEPTH = 2;
constexpr uint64_t OVER_SCAN_MB = 50;

// =======================================================
// THREAD-SAFE STATS
// =======================================================
struct Stats {
    std::atomic<uint64_t> scanned{ 0 };
    std::atomic<uint64_t> deleted{ 0 };
    std::atomic<uint64_t> freed_bytes{ 0 };
    std::atomic<uint64_t> skipped_locked{ 0 };
    std::atomic<uint64_t> skipped_perm{ 0 };
};

// =======================================================
// SAFETY HELPERS
// =======================================================
bool file_locked(const fs::path& p) {
    HANDLE h = CreateFileW(
        p.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (h == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_SHARING_VIOLATION;

    CloseHandle(h);
    return false;
}

bool multi_hardlink(const fs::path& p) {
    HANDLE h = CreateFileW(
        p.c_str(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );

    if (h == INVALID_HANDLE_VALUE)
        return true;

    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h, &info)) {
        CloseHandle(h);
        return true;
    }

    CloseHandle(h);
    return info.nNumberOfLinks > 1;
}

bool is_reparse_point(const fs::path& p) {
    DWORD attrs = GetFileAttributesW(p.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES &&
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT);
}

bool is_junk_ext(const fs::path& p) {
    auto ext = p.extension().wstring();
    return ext == L".tmp" || ext == L".log" ||
        ext == L".dmp" || ext == L".bak";
}

bool recently_modified(const fs::file_time_type& ft) {
    auto now = fs::file_time_type::clock::now();
    return (now - ft) < chrono::minutes(10);
}

uint64_t file_age_hours(const fs::file_time_type& ft) {
    auto now = fs::file_time_type::clock::now();
    return chrono::duration_cast<chrono::hours>(now - ft).count();
}

// =======================================================
// CORE CLEANER
// =======================================================
void cap_cache(const fs::path& dir, uint64_t cap_mb, Stats& st) {
    if (!fs::exists(dir)) return;

    struct Entry {
        fs::path p;
        uint64_t size;
        fs::file_time_type time;
    };

    uint64_t limit = cap_mb * 1024 * 1024;
    uint64_t hard_limit = limit + (OVER_SCAN_MB * 1024 * 1024);

    std::vector<Entry> files;
    uint64_t total = 0;

    try {
        fs::recursive_directory_iterator it(
            dir,
            fs::directory_options::skip_permission_denied
        );

        for (const auto& e : it) {
            if (it.depth() > MAX_DEPTH) {
                it.disable_recursion_pending();
                continue;
            }

            if (!e.is_regular_file())
                continue;

            const fs::path& p = e.path();
            st.scanned++;

            if (is_reparse_point(p))
                continue;

            if (file_locked(p)) {
                st.skipped_locked++;
                continue;
            }

            if (multi_hardlink(p))
                continue;

            uint64_t size = 0;
            try {
                size = fs::file_size(p);
            }
            catch (...) {
                st.skipped_perm++;
                continue;
            }

            auto ftime = e.last_write_time();
            if (recently_modified(ftime))
                continue;

            uint64_t age_h = file_age_hours(ftime);

            bool junk = is_junk_ext(p) && age_h >= AGE_JUNK_HOURS;
            bool old = age_h >= (AGE_GENERAL_DAYS * 24);
            bool big_shader =
                (size >= (BIG_SHADER_MB * 1024 * 1024)) &&
                p.extension() == L".bin";

            if (!(junk || old || big_shader))
                continue;

            total += size;
            files.push_back({ p, size, ftime });

            if (total >= hard_limit)
                break;
        }
    }
    catch (...) {
        return;
    }

    std::sort(files.begin(), files.end(),
        [](const Entry& a, const Entry& b) {
            return a.time < b.time;
        });

    for (const auto& f : files) {
        if (total <= limit)
            break;

        try {
            if (fs::remove(f.p)) {
                total -= f.size;
                st.deleted++;
                st.freed_bytes += f.size;
            }
        }
        catch (...) {}
    }
}

// =======================================================
// ENTRY POINT (FIXED SYMBOL)
// =======================================================
void run_disk_cleanup() {
    system("pip cache purge > nul 2>&1");
    system("ipconfig /flushdns > nul 2>&1");
    system("npm cache clean --force > nul 2>&1");
    system("dism /online /cleanup-image /startcomponentcleanup /resetbase > nul 2>&1");

    Stats st;
    wchar_t* local = nullptr;
    size_t len = 0;

    if (_wdupenv_s(&local, &len, L"LOCALAPPDATA") == 0 && local) {
        fs::path base(local);
        free(local);

        std::jthread t1([&] { cap_cache(base / L"D3DSCache", CAP_D3DS_MB, st); });
        std::jthread t2([&] { cap_cache(base / L"Temp", CAP_TEMP_MB, st); });
        std::jthread t3([&] { cap_cache(base / L"CrashDumps", CAP_DUMPS_MB, st); });
    }

    std::jthread t4([&] {
        cap_cache(L"C:\\Windows\\SoftwareDistribution\\Download", CAP_UPDATES_MB, st);
        });

    cap_cache(L"C:\\Windows\\Temp", CAP_WIN_TEMP_MB, st);
}
