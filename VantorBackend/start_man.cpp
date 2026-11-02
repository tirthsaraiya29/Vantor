// start_man.cpp
#include <windows.h>
#include <string>

struct Stats {
    int scanned = 0;
    int delayed = 0;
};

bool heavy_app(const std::wstring& cmd) {
    return cmd.find(L"update") != std::wstring::npos ||
        cmd.find(L"telemetry") != std::wstring::npos ||
        cmd.find(L"launcher") != std::wstring::npos ||
        cmd.find(L"helper") != std::wstring::npos;
}

void process_run_key(HKEY root, Stats& st) {
    HKEY h;
    if (RegOpenKeyExW(
        root,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_ALL_ACCESS,
        &h
    ) != ERROR_SUCCESS)
        return;

    wchar_t name[256];
    wchar_t data[1024];
    DWORD nameSize, dataSize, type;

    while (true) {
        nameSize = 256;
        dataSize = sizeof(data);

        LONG res = RegEnumValueW(
            h,
            0,
            name,
            &nameSize,
            nullptr,
            &type,
            (LPBYTE)data,
            &dataSize
        );

        if (res != ERROR_SUCCESS)
            break;

        st.scanned++;

        std::wstring cmd(data);

        if (heavy_app(cmd)) {
            std::wstring delayedName = std::wstring(name) + L"_Delayed";

            RegDeleteValueW(h, name);
            RegSetValueExW(
                h,
                delayedName.c_str(),
                0,
                REG_SZ,
                reinterpret_cast<const BYTE*>(cmd.c_str()),
                static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t))
            );

            st.delayed++;
        }
    }

    RegCloseKey(h);
}

// =======================================================
// PUBLIC ENTRY POINT
// =======================================================
void run_startup_optimization() {
    Stats st;

    process_run_key(HKEY_CURRENT_USER, st);
    process_run_key(HKEY_LOCAL_MACHINE, st);
}
