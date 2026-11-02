#include "heuristic.h"
#include "VantorBackend.h"
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <filesystem>
#include <string>
#include <algorithm>

#pragma comment(lib, "wintrust.lib")

/**
 * Checks if a file has a valid digital signature.
 * Trusted signatures are the strongest defense against False Positives.
 */
static bool is_signed_and_valid(const std::wstring& path) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policy, &trustData);

    // Cleanup
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &trustData);

    return status == ERROR_SUCCESS;
}

/**
 * UPGRADED: Weighted Heuristic Engine
 * Instead of simple addition, we use a point system normalized to 0.0 - 1.0.
 */
double run_heuristic_scan(const std::string& path) {
    int total_points = 0;
    std::error_code ec;
    auto file_size = std::filesystem::file_size(path, ec);

    // 1. Digital Signature Logic (The primary FP filter)
    std::wstring wpath(path.begin(), path.end());
    if (is_signed_and_valid(wpath)) {
        // Massive point reduction for signed files. 
        // This makes it nearly impossible for a signed Microsoft app to be flagged.
        total_points -= 60;
    }
    else {
        // Penalty for unsigned binaries.
        total_points += 30;
    }

    // 2. Structural/Size Heuristics
    if (!ec) {
        if (file_size < 10 * 1024) total_points += 20;       // Tiny stubs/droppers
        if (file_size > 150 * 1024 * 1024) total_points += 5; // Unusually bloated
    }

    // 3. Contextual Heuristics (Where is the file?)
    // Malware often executes from Temp or AppData to bypass permissions.
    std::string path_lower = path;
    std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(), ::tolower);

    if (path_lower.find("\\appdata\\") != std::string::npos ||
        path_lower.find("\\temp\\") != std::string::npos) {
        total_points += 25;
    }

    // 4. Double Extension Check (Classic trick: invoice.pdf.exe)
    if (path_lower.find(".pdf.exe") != std::string::npos ||
        path_lower.find(".txt.exe") != std::string::npos ||
        path_lower.find(".jpg.exe") != std::string::npos) {
        total_points += 50;
    }

    // 5. Extension weighting
    if (path_lower.ends_with(".exe") || path_lower.ends_with(".dll") || path_lower.ends_with(".sys")) {
        total_points += 10;
    }

    // Normalize: Convert points to a 0.0 - 1.0 scale
    // 0 points = 0.0, 100+ points = 1.0
    double final_score = static_cast<double>(total_points) / 100.0;

    // Clamp values
    if (final_score < 0.0) final_score = 0.0;
    if (final_score > 1.0) final_score = 1.0;

    return final_score;
}