#pragma once

#include "Common.h"
#include <wintrust.h>
#include <softpub.h>
#include <filesystem>

#pragma comment(lib, "wintrust.lib")

namespace vantor {
namespace authenticode {

/**
 * @brief Verifies the Authenticode signature of a PE executable file.
 * Returns true if the file has a valid digital signature trusted by Windows trust provider.
 */
inline bool VerifyAuthenticodeSignature(const std::wstring& filePath) {
    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec)) {
        return false;
    }

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policyGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &trustData);

    return status == ERROR_SUCCESS;
}

} // namespace authenticode
} // namespace vantor
