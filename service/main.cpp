#include "../common/Common.h"
#include "../common/Logger.h"
#include "AntiTamper.h"
#include "ConfigManager.h"
#include "Scanner.h"
#include "IPC.h"
#include "RealTimeProtection.h"

#include <iostream>
#include <string>

namespace vantor {
namespace service {

static SERVICE_STATUS g_serviceStatus{};
static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static HANDLE g_stopEvent = nullptr;

void UpdateStatus(DWORD currentState, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0) {
    static DWORD checkPoint = 1;
    g_serviceStatus.dwCurrentState = currentState;
    g_serviceStatus.dwWin32ExitCode = win32ExitCode;
    g_serviceStatus.dwWaitHint = waitHint;

    if (currentState == SERVICE_START_PENDING || currentState == SERVICE_STOP_PENDING) {
        g_serviceStatus.dwControlsAccepted = 0;
        g_serviceStatus.dwCheckPoint = checkPoint++;
    } else {
        g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT;
        g_serviceStatus.dwCheckPoint = 0;
    }

    if (g_statusHandle) {
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
    }
}

DWORD WINAPI HandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    (void)dwEventType;
    (void)lpEventData;
    (void)lpContext;
    switch (dwControl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            LOG_INFO("Service", "Service stop/shutdown signal received.");
            UpdateStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
            if (g_stopEvent) {
                SetEvent(g_stopEvent);
            }
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;

        default:
            break;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

void StartServiceEngines() {
    LOG_INFO("Service", "Starting Vantor Service Core Engines...");

    std::wstring exeDir = GetExecutableDirectory();
    std::string appDir = Utf16ToUtf8(exeDir);

    // 1. Load Encrypted Configuration from application directory
    config::ConfigManager::Instance().Load(appDir + "/config.json");

    // 2. Initialize and start Anti-Tamper with application directory
    antitamper::AntiTamper::Instance().Initialize(exeDir);
    if (config::ConfigManager::Instance().GetConfig().antiTamperEnabled) {
        antitamper::AntiTamper::Instance().Start();
    }

    // 3. Initialize Scanner & Quarantine with application directory
    scan::Scanner::Instance().Initialize(appDir);

    // 4. Start Named Pipe IPC Server
    ServiceIPC::Instance().Start();

    // 5. Start Real-Time Protection
    if (config::ConfigManager::Instance().GetConfig().rtpEnabled) {
        rtp::RealTimeProtection::Instance().Start();
    }

    LOG_INFO("Service", "All Vantor engines active and running.");
}

void StopServiceEngines() {
    LOG_INFO("Service", "Stopping Vantor Service Core Engines...");

    rtp::RealTimeProtection::Instance().Stop();
    ServiceIPC::Instance().Stop();
    scan::Scanner::Instance().CancelScan();
    antitamper::AntiTamper::Instance().Stop();

    LOG_INFO("Service", "All Vantor engines stopped.");
}

VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    (void)argc;
    (void)argv;
    g_statusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, HandlerEx, nullptr);
    if (!g_statusHandle) {
        return;
    }

    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    UpdateStatus(SERVICE_START_PENDING, NO_ERROR, 5000);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        UpdateStatus(SERVICE_STOPPED, GetLastError());
        return;
    }

    StartServiceEngines();
    UpdateStatus(SERVICE_RUNNING);

    // Wait until stop signal
    WaitForSingleObject(g_stopEvent, INFINITE);

    UpdateStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    StopServiceEngines();

    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;

    UpdateStatus(SERVICE_STOPPED);
}

bool InstallService() {
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) {
        std::cerr << "Failed to resolve executable path: " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        std::cerr << "Failed to open Service Control Manager (Run as Administrator): " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE hService = CreateServiceW(
        hSCM,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        path,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    if (!hService) {
        std::cerr << "Failed to create service: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCM);
        return false;
    }

    // Set Service Description
    SERVICE_DESCRIPTIONW desc;
    desc.lpDescription = const_cast<LPWSTR>(SERVICE_DESCRIPTION);
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &desc);

    // Auto-Restart on failure
    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART;
    actions[0].Delay = 5000; // 5 sec
    actions[1].Type = SC_ACTION_RESTART;
    actions[1].Delay = 10000;
    actions[2].Type = SC_ACTION_RESTART;
    actions[2].Delay = 30000;

    SERVICE_FAILURE_ACTIONSW sfa;
    sfa.dwResetPeriod = 86400; // 24 hours
    sfa.lpRebootMsg = nullptr;
    sfa.lpCommand = nullptr;
    sfa.cActions = 3;
    sfa.lpsaActions = actions;
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    std::cout << "[+] Vantor Windows Service successfully installed and configured." << std::endl;
    return true;
}

bool UninstallService() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        std::cerr << "Failed to open SCM (Run as Administrator): " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (!hService) {
        std::cerr << "Failed to open service: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS status;
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    if (!DeleteService(hService)) {
        std::cerr << "Failed to delete service: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    std::cout << "[+] Vantor Windows Service successfully removed." << std::endl;
    return true;
}

static BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_CLOSE_EVENT) {
        std::cout << "\n[!] Shutting down console service..." << std::endl;
        StopServiceEngines();
        exit(0);
    }
    return TRUE;
}

void RunConsole() {
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    std::cout << "====================================================\n";
    std::cout << "      Vantor Antivirus Service (Console Mode)        \n";
    std::cout << "====================================================\n";
    StartServiceEngines();

    std::cout << "[+] Vantor Service active in console mode. Press Ctrl+C to exit.\n";
    while (true) {
        Sleep(1000);
    }
}

} // namespace service
} // namespace vantor

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        std::wstring arg = argv[1];
        if (arg == L"--install" || arg == L"-i") {
            return vantor::service::InstallService() ? 0 : 1;
        }
        if (arg == L"--uninstall" || arg == L"-u") {
            return vantor::service::UninstallService() ? 0 : 1;
        }
        if (arg == L"--console" || arg == L"--run" || arg == L"-c") {
            vantor::service::RunConsole();
            return 0;
        }
    }

    // Windows SCM Service Dispatch Table
    SERVICE_TABLE_ENTRYW dispatchTable[] = {
        { const_cast<LPWSTR>(vantor::SERVICE_NAME), vantor::service::ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(dispatchTable)) {
        // If not launched by SCM, fallback to console mode
        vantor::service::RunConsole();
    }

    return 0;
}
