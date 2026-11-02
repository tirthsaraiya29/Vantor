// AntiTamper.cpp
// User-mode file integrity enforcement for Vantor AV

#include <windows.h>
#include <wincrypt.h>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>

#pragma comment(lib, "advapi32.lib")

namespace fs = std::filesystem;

// ================= CONFIG =================

static const std::vector<std::wstring> PROTECTED_FILES = {
    L"VantorBackend.exe",
    L"RTP.exe",
    L"logs.zip",
    L"signatures.db",
    L"safe.db",
    L"scan_history.db"
};

static const std::wstring BACKUP_DIR =
L"C:\\ProgramData\\Vantor\\ATBackup\\";

// ================= GLOBALS =================

std::unordered_map<std::wstring, std::string> baselineHashes;
std::unordered_map<std::wstring, uintmax_t> baselineSizes;
std::atomic<bool> g_running{ true };

// ================= UTIL =================

std::wstring exeDir() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    return fs::path(path).parent_path().wstring() + L"\\";
}

bool fileExists(const fs::path& p) {
    return fs::exists(p) && fs::is_regular_file(p);
}

// ================= SHA-512 =================

std::string sha512(const fs::path& file) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    BYTE buf[4096];
    BYTE out[64];
    DWORD read = 0, len = 64;

    std::ifstream f(file, std::ios::binary);
    if (!f) return "";

    if (!CryptAcquireContextW(&prov, nullptr, nullptr,
        PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return "";

    if (!CryptCreateHash(prov, CALG_SHA_512, 0, 0, &hash)) {
        CryptReleaseContext(prov, 0);
        return "";
    }

    while (f.read((char*)buf, sizeof(buf)) || f.gcount())
        CryptHashData(hash, buf, (DWORD)f.gcount(), 0);

    CryptGetHashParam(hash, HP_HASHVAL, out, &len, 0);
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);

    static const char* hex = "0123456789abcdef";
    std::string s;
    for (BYTE b : out) {
        s += hex[b >> 4];
        s += hex[b & 0xF];
    }
    return s;
}

// ================= BACKUP =================

void initBackupDir() {
    fs::create_directories(BACKUP_DIR);
    SetFileAttributesW(BACKUP_DIR.c_str(),
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY);
}

void backupFile(const fs::path& src) {
    fs::path dst = fs::path(BACKUP_DIR) / src.filename();
    fs::copy_file(src, dst, fs::copy_options::overwrite_existing);
}

bool validateBackup(const fs::path& name) {
    fs::path b = fs::path(BACKUP_DIR) / name.filename();
    if (!fileExists(b)) return false;
    return sha512(b) == baselineHashes[name.filename().wstring()];
}

// ================= RESTORE =================

void atomicRestore(const fs::path& name) {
    fs::path backup = fs::path(BACKUP_DIR) / name.filename();
    fs::path target = exeDir() + name.filename().wstring();
    fs::path temp = target;
    temp += L".tmp";

    if (!validateBackup(name)) return;

    fs::copy_file(backup, temp,
        fs::copy_options::overwrite_existing);

    if (sha512(temp) != baselineHashes[name.filename().wstring()]) {
        fs::remove(temp);
        return;
    }

    fs::rename(temp, target);
}

// ================= BASELINE =================

void buildBaseline() {
    for (const auto& f : PROTECTED_FILES) {
        fs::path p = exeDir() + f;
        if (!fileExists(p)) continue;

        backupFile(p);
        baselineHashes[f] = sha512(p);
        baselineSizes[f] = fs::file_size(p);
    }
}

// ================= WATCHDOG =================

void integrityWatchdog() {
    while (g_running) {
        for (const auto& f : PROTECTED_FILES) {
            fs::path p = exeDir() + f;

            if (!fileExists(p)) {
                atomicRestore(f);
                continue;
            }

            uintmax_t sz = fs::file_size(p);
            if (sz != baselineSizes[f]) {
                atomicRestore(f);
                continue;
            }

            if (sha512(p) != baselineHashes[f]) {
                atomicRestore(f);
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}

// ================= DIRECTORY WATCH =================

void dirWatcher() {
    HANDLE dir = CreateFileW(
        exeDir().c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );

    BYTE buffer[8192];
    DWORD bytes;

    while (g_running) {
        if (ReadDirectoryChangesW(
            dir, buffer, sizeof(buffer), FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytes, nullptr, nullptr)) {

            for (const auto& f : PROTECTED_FILES) {
                fs::path p = exeDir() + f;
                if (!fileExists(p) ||
                    sha512(p) != baselineHashes[f]) {
                    atomicRestore(f);
                }
            }
        }
    }
    CloseHandle(dir);
}

// ================= ENTRY =================

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    initBackupDir();
    buildBaseline();

    std::thread watcher(dirWatcher);
    std::thread watchdog(integrityWatchdog);

    watcher.join();
    watchdog.join();
    return 0;
}
