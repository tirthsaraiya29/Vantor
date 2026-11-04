#include "DetonationChamber.h"
#include "../common/Logger.h"
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;

namespace vantor {
namespace scan {

DetonationReport DetonationChamber::DetonateSample(const std::string& filePath, uint32_t timeoutMs) {
    DetonationReport report;
    std::error_code ec;
    if (!fs::exists(filePath, ec) || !fs::is_regular_file(filePath, ec)) {
        report.summary = "Sample file not found on disk.";
        return report;
    }

    // Only detonate executable binaries
    std::string ext = ToLower(fs::path(filePath).extension().string());
    if (ext != ".exe" && ext != ".com" && ext != ".scr") {
        report.summary = "Non-executable extension; skipping dynamic detonation.";
        return report;
    }

    // 1. Create isolated Windows Job Object
    HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
    if (!hJob) {
        LOG_WARN("DetonationChamber", "Failed to create Windows Job Object for sandboxing.");
        report.summary = "Job Object creation failed.";
        return report;
    }

    // Configure limits: 5s execution ceiling, kill on close, max 4 child processes
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimits{};
    jobLimits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
        JOB_OBJECT_LIMIT_JOB_MEMORY;
    jobLimits.BasicLimitInformation.ActiveProcessLimit = 4;
    jobLimits.JobMemoryLimit = 256ULL * 1024ULL * 1024ULL; // 256 MB RAM limit

    SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jobLimits, sizeof(jobLimits));

    // Configure UI restrictions: block clipboard, desktop, handles, system parameters
    JOBOBJECT_BASIC_UI_RESTRICTIONS uiLimits{};
    uiLimits.UIRestrictionsClass =
        JOB_OBJECT_UILIMIT_HANDLES |
        JOB_OBJECT_UILIMIT_READCLIPBOARD |
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
        JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
        JOB_OBJECT_UILIMIT_DESKTOP;

    SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &uiLimits, sizeof(uiLimits));

    // 2. Launch process suspended with isolated environment
    std::wstring widePath = Utf8ToUtf16(filePath);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    DWORD creationFlags = CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_CONSOLE;

    auto startTime = std::chrono::steady_clock::now();

    BOOL created = CreateProcessW(
        widePath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        FALSE,
        creationFlags,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if (!created) {
        CloseHandle(hJob);
        report.summary = "Failed to launch sample in suspended sandbox.";
        return report;
    }

    // Assign process to Job Object
    if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(hJob);
        report.summary = "Failed to assign process to Job Object sandbox.";
        return report;
    }

    // Resume execution in isolated sandbox
    ResumeThread(pi.hThread);
    report.executed = true;

    // Monitor process execution up to timeoutMs
    DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    report.executionTimeMs = static_cast<uint32_t>(elapsed);

    // Inspect job accounting information to check child processes
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acctInfo{};
    if (QueryInformationJobObject(hJob, JobObjectBasicAccountingInformation, &acctInfo, sizeof(acctInfo), nullptr)) {
        report.childProcessesSpawned = static_cast<int>(acctInfo.TotalProcesses) - 1;
    }

    if (waitResult == WAIT_TIMEOUT) {
        // Sample ran longer than timeout or hung: terminate
        report.anomalousBehavior = true;
        report.behaviorRiskScore += 0.35;
        report.summary = "Process executed longer than sandbox timeout (" + std::to_string(timeoutMs) + "ms) and was terminated.";
    } else {
        GetExitCodeProcess(pi.hProcess, &report.exitCode);
        if (report.exitCode != 0) {
            report.behaviorRiskScore += 0.15;
        }
        report.summary = "Process completed in " + std::to_string(report.executionTimeMs) +
                         "ms with exit code " + std::to_string(report.exitCode);
    }

    // If spawned multiple child processes, mark anomalous
    if (report.childProcessesSpawned > 0) {
        report.anomalousBehavior = true;
        report.behaviorRiskScore += 0.40;
        report.summary += " Spawned " + std::to_string(report.childProcessesSpawned) + " child process(es).";
    }

    report.behaviorRiskScore = std::clamp(report.behaviorRiskScore, 0.0, 1.0);

    // Clean up all resources and kill all remaining processes in job
    TerminateJobObject(hJob, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hJob);

    return report;
}

} // namespace scan
} // namespace vantor
