#include "ScheduledScanService.h"
#include "../common/Logger.h"
#include "../common/Common.h"

#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

namespace vantor {
namespace backend {

static std::wstring GetCurrentBackendPath() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    return std::wstring(buffer);
}

bool ScheduledScanService::RegisterTask(const ScheduledScanConfig& config, std::string& outError) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool needCoUninit = SUCCEEDED(hr);

    ITaskService* pService = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        outError = "Failed to create TaskScheduler COM instance: 0x" + std::to_string(hr);
        if (needCoUninit) CoUninitialize();
        return false;
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        outError = "Failed to connect to Task Scheduler: 0x" + std::to_string(hr);
        if (needCoUninit) CoUninitialize();
        return false;
    }

    ITaskFolder* pRootFolder = nullptr;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pService->Release();
        outError = "Failed to get root task folder: 0x" + std::to_string(hr);
        if (needCoUninit) CoUninitialize();
        return false;
    }

    ITaskDefinition* pTask = nullptr;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) {
        pRootFolder->Release();
        pService->Release();
        outError = "Failed to initialize new task definition: 0x" + std::to_string(hr);
        if (needCoUninit) CoUninitialize();
        return false;
    }

    // Task metadata
    IRegistrationInfo* pRegInfo = nullptr;
    if (SUCCEEDED(pTask->get_RegistrationInfo(&pRegInfo))) {
        pRegInfo->put_Author(_bstr_t(L"Vantor Antivirus"));
        pRegInfo->put_Description(_bstr_t(L"Automated scheduled antivirus scan background trigger."));
        pRegInfo->Release();
    }

    // Task settings
    ITaskSettings* pSettings = nullptr;
    if (SUCCEEDED(pTask->get_Settings(&pSettings))) {
        pSettings->put_StartWhenAvailable(VARIANT_TRUE);
        pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
        pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
        pSettings->Release();
    }

    // Trigger collection
    ITriggerCollection* pTriggerCollection = nullptr;
    hr = pTask->get_Triggers(&pTriggerCollection);
    if (SUCCEEDED(hr)) {
        ITrigger* pTrigger = nullptr;
        hr = pTriggerCollection->Create(TASK_TRIGGER_DAILY, &pTrigger);
        if (SUCCEEDED(hr)) {
            IDailyTrigger* pDailyTrigger = nullptr;
            if (SUCCEEDED(pTrigger->QueryInterface(IID_IDailyTrigger, (void**)&pDailyTrigger))) {
                pDailyTrigger->put_DaysInterval(1);

                // Format boundary: YYYY-MM-DDTHH:MM:SS
                SYSTEMTIME st;
                GetLocalTime(&st);
                wchar_t startBoundary[64];
                swprintf_s(startBoundary, L"%04d-%02d-%02dT%02d:%02d:00",
                          st.wYear, st.wMonth, st.wDay, config.hour, config.minute);
                pDailyTrigger->put_StartBoundary(_bstr_t(startBoundary));
                pDailyTrigger->Release();
            }
            pTrigger->put_Enabled(config.enabled ? VARIANT_TRUE : VARIANT_FALSE);
            pTrigger->Release();
        }
        pTriggerCollection->Release();
    }

    // Action collection
    IActionCollection* pActionCollection = nullptr;
    hr = pTask->get_Actions(&pActionCollection);
    if (SUCCEEDED(hr)) {
        IAction* pAction = nullptr;
        hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
        if (SUCCEEDED(hr)) {
            IExecAction* pExecAction = nullptr;
            if (SUCCEEDED(pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction))) {
                std::wstring exePath = GetCurrentBackendPath();
                pExecAction->put_Path(_bstr_t(exePath.c_str()));
                std::wstring args = L"scan " + Utf8ToUtf16(config.scanType);
                pExecAction->put_Arguments(_bstr_t(args.c_str()));
                pExecAction->Release();
            }
            pAction->Release();
        }
        pActionCollection->Release();
    }

    // Register task
    IRegisteredTask* pRegisteredTask = nullptr;
    std::wstring wTaskName = Utf8ToUtf16(config.taskName);
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(wTaskName.c_str()),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(),
        _variant_t(),
        TASK_LOGON_INTERACTIVE_TOKEN,
        _variant_t(L""),
        &pRegisteredTask
    );

    if (SUCCEEDED(hr) && pRegisteredTask) {
        pRegisteredTask->Release();
    }

    pTask->Release();
    pRootFolder->Release();
    pService->Release();

    if (needCoUninit) CoUninitialize();

    if (FAILED(hr)) {
        outError = "RegisterTaskDefinition failed: 0x" + std::to_string(hr);
        return false;
    }

    LOG_INFO("ScheduledScanService", "Scheduled scan task '" + config.taskName + "' registered successfully for " +
             std::to_string(config.hour) + ":" + std::to_string(config.minute) + " (" + config.scanType + ").");
    return true;
}

bool ScheduledScanService::DeleteTask(const std::string& taskName, std::string& outError) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool needCoUninit = SUCCEEDED(hr);

    ITaskService* pService = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        outError = "Failed to create TaskScheduler COM instance";
        if (needCoUninit) CoUninitialize();
        return false;
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        outError = "Failed to connect to Task Scheduler";
        if (needCoUninit) CoUninitialize();
        return false;
    }

    ITaskFolder* pRootFolder = nullptr;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pService->Release();
        outError = "Failed to get root task folder";
        if (needCoUninit) CoUninitialize();
        return false;
    }

    std::wstring wTaskName = Utf8ToUtf16(taskName);
    hr = pRootFolder->DeleteTask(_bstr_t(wTaskName.c_str()), 0);

    pRootFolder->Release();
    pService->Release();
    if (needCoUninit) CoUninitialize();

    if (FAILED(hr)) {
        outError = "DeleteTask failed: 0x" + std::to_string(hr);
        return false;
    }

    LOG_INFO("ScheduledScanService", "Scheduled scan task '" + taskName + "' deleted.");
    return true;
}

bool ScheduledScanService::GetNextRunTime(const std::string& taskName, std::string& outNextRunIso, std::string& outError) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool needCoUninit = SUCCEEDED(hr);

    ITaskService* pService = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        outError = "Failed to create TaskScheduler COM instance";
        if (needCoUninit) CoUninitialize();
        return false;
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        outError = "Failed to connect to Task Scheduler";
        if (needCoUninit) CoUninitialize();
        return false;
    }

    ITaskFolder* pRootFolder = nullptr;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pService->Release();
        outError = "Failed to get root task folder";
        if (needCoUninit) CoUninitialize();
        return false;
    }

    std::wstring wTaskName = Utf8ToUtf16(taskName);
    IRegisteredTask* pTask = nullptr;
    hr = pRootFolder->GetTask(_bstr_t(wTaskName.c_str()), &pTask);

    if (SUCCEEDED(hr) && pTask) {
        DATE nextRun = 0.0;
        hr = pTask->get_NextRunTime(&nextRun);
        if (SUCCEEDED(hr) && nextRun != 0.0) {
            SYSTEMTIME st;
            VariantTimeToSystemTime(nextRun, &st);
            char buf[64];
            snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            outNextRunIso = buf;
        } else {
            outNextRunIso = "None scheduled";
        }
        pTask->Release();
    } else {
        outError = "Task not found";
    }

    pRootFolder->Release();
    pService->Release();
    if (needCoUninit) CoUninitialize();

    return SUCCEEDED(hr);
}

bool ScheduledScanService::IsTaskRegistered(const std::string& taskName) {
    std::string nextRun, err;
    return GetNextRunTime(taskName, nextRun, err);
}

} // namespace backend
} // namespace vantor
