#pragma once

#include "Common.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <fstream>
#include <memory>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace vantor {
namespace crypto {

inline std::string ToHex(const uint8_t* data, size_t length) {
    static const char hexChars[] = "0123456789abcdef";
    std::string s;
    s.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        s.push_back(hexChars[(data[i] >> 4) & 0x0F]);
        s.push_back(hexChars[data[i] & 0x0F]);
    }
    return s;
}

inline bool HexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.length() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        char high = hex[i];
        char low = hex[i + 1];
        auto charVal = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = charVal(high);
        int l = charVal(low);
        if (h == -1 || l == -1) return false;
        out.push_back(static_cast<uint8_t>((h << 4) | l));
    }
    return true;
}

// Memory hash via BCrypt
inline std::string HashMemory(const LPCWSTR algorithm, const void* data, size_t size) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string hexResult;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, algorithm, nullptr, 0))) {
        return "";
    }

    DWORD hashLength = 0;
    DWORD resultSize = 0;
    if (NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLength, sizeof(DWORD), &resultSize, 0))) {
        if (NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0))) {
            if (NT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, static_cast<ULONG>(size), 0))) {
                std::vector<uint8_t> hashVal(hashLength);
                if (NT_SUCCESS(BCryptFinishHash(hHash, hashVal.data(), hashLength, 0))) {
                    hexResult = ToHex(hashVal.data(), hashVal.size());
                }
            }
            BCryptDestroyHash(hHash);
        }
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hexResult;
}

inline std::string ComputeSHA256Memory(const void* data, size_t size) {
    return HashMemory(BCRYPT_SHA256_ALGORITHM, data, size);
}

inline std::string ComputeSHA512Memory(const void* data, size_t size) {
    return HashMemory(BCRYPT_SHA512_ALGORITHM, data, size);
}

// Streaming File Hashes using 64KB chunks
inline bool ComputeFileHashes(const std::wstring& filePath, std::string& sha256Out, std::string& sha512Out) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER sizeBefore{}, sizeAfter{};
    if (!GetFileSizeEx(hFile, &sizeBefore)) {
        CloseHandle(hFile);
        return false;
    }

    BCRYPT_ALG_HANDLE hAlg256 = nullptr;
    BCRYPT_ALG_HANDLE hAlg512 = nullptr;
    BCRYPT_HASH_HANDLE hHash256 = nullptr;
    BCRYPT_HASH_HANDLE hHash512 = nullptr;

    bool success = false;
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg256, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) &&
        NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg512, BCRYPT_SHA512_ALGORITHM, nullptr, 0))) {

        if (NT_SUCCESS(BCryptCreateHash(hAlg256, &hHash256, nullptr, 0, nullptr, 0, 0)) &&
            NT_SUCCESS(BCryptCreateHash(hAlg512, &hHash512, nullptr, 0, nullptr, 0, 0))) {

            constexpr DWORD BUFFER_SIZE = 64 * 1024; // 64 KB buffer
            std::vector<uint8_t> buffer(BUFFER_SIZE);
            DWORD bytesRead = 0;
            bool readOk = true;

            while (ReadFile(hFile, buffer.data(), BUFFER_SIZE, &bytesRead, nullptr) && bytesRead > 0) {
                if (!NT_SUCCESS(BCryptHashData(hHash256, buffer.data(), bytesRead, 0)) ||
                    !NT_SUCCESS(BCryptHashData(hHash512, buffer.data(), bytesRead, 0))) {
                    readOk = false;
                    break;
                }
            }

            // Verify file size remained stable throughout the hash read
            if (readOk && GetFileSizeEx(hFile, &sizeAfter) && sizeBefore.QuadPart == sizeAfter.QuadPart) {
                std::vector<uint8_t> hash256(32);
                std::vector<uint8_t> hash512(64);
                if (NT_SUCCESS(BCryptFinishHash(hHash256, hash256.data(), 32, 0)) &&
                    NT_SUCCESS(BCryptFinishHash(hHash512, hash512.data(), 64, 0))) {
                    sha256Out = ToHex(hash256.data(), hash256.size());
                    sha512Out = ToHex(hash512.data(), hash512.size());
                    success = true;
                }
            }

            BCryptDestroyHash(hHash256);
            BCryptDestroyHash(hHash512);
        }
    }

    if (hAlg256) BCryptCloseAlgorithmProvider(hAlg256, 0);
    if (hAlg512) BCryptCloseAlgorithmProvider(hAlg512, 0);
    CloseHandle(hFile);
    return success;
}

inline bool ComputeFileHashes(const std::string& filePathUtf8, std::string& sha256Out, std::string& sha512Out) {
    return ComputeFileHashes(Utf8ToUtf16(filePathUtf8), sha256Out, sha512Out);
}

// Cryptographically Secure Random Bytes
inline bool GenerateRandomBytes(void* buffer, size_t size) {
    return NT_SUCCESS(BCryptGenRandom(nullptr, (PUCHAR)buffer, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// Windows DPAPI Data Protection
inline bool DPAPIProtect(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext, bool machineScope = false) {
    if (plaintext.empty()) return false;
    DATA_BLOB inBlob;
    inBlob.cbData = static_cast<DWORD>(plaintext.size());
    inBlob.pbData = const_cast<BYTE*>(plaintext.data());

    DATA_BLOB outBlob = { 0, nullptr };
    DWORD flags = CRYPTPROTECT_UI_FORBIDDEN;
    if (machineScope) {
        flags |= CRYPTPROTECT_LOCAL_MACHINE;
    }

    if (!CryptProtectData(&inBlob, L"VantorProtectedData", nullptr, nullptr, nullptr, flags, &outBlob)) {
        return false;
    }

    ciphertext.assign(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return true;
}

inline bool DPAPIUnprotect(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext) {
    if (ciphertext.empty()) return false;
    DATA_BLOB inBlob;
    inBlob.cbData = static_cast<DWORD>(ciphertext.size());
    inBlob.pbData = const_cast<BYTE*>(ciphertext.data());

    DATA_BLOB outBlob = { 0, nullptr };
    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &outBlob)) {
        return false;
    }

    plaintext.assign(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return true;
}

// AES-256-GCM Authenticated Encryption
inline bool AES256GCMEncrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key32,
    std::vector<uint8_t>& ciphertext,
    std::vector<uint8_t>& iv12,
    std::vector<uint8_t>& tag16)
{
    if (key32.size() != 32) return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        return false;
    }

    bool ok = false;
    if (NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                     sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {

        BCRYPT_KEY_HANDLE hKey = nullptr;
        if (NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                                 const_cast<PUCHAR>(key32.data()),
                                                 static_cast<ULONG>(key32.size()), 0))) {

            iv12.resize(12);
            GenerateRandomBytes(iv12.data(), iv12.size());
            tag16.resize(16);

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = iv12.data();
            authInfo.cbNonce = static_cast<ULONG>(iv12.size());
            authInfo.pbTag = tag16.data();
            authInfo.cbTag = static_cast<ULONG>(tag16.size());

            ciphertext.resize(plaintext.size());
            ULONG bytesCopied = 0;

            // When buffer is 0 bytes, BCrypt expects a non-null pointer with 0 length to avoid size query mode
            uint8_t dummyByte = 0;
            PUCHAR pbIn = plaintext.empty() ? &dummyByte : const_cast<PUCHAR>(plaintext.data());
            PUCHAR pbOut = ciphertext.empty() ? &dummyByte : ciphertext.data();

            NTSTATUS status = BCryptEncrypt(hKey,
                                            pbIn,
                                            static_cast<ULONG>(plaintext.size()),
                                            &authInfo,
                                            nullptr, 0,
                                            pbOut,
                                            static_cast<ULONG>(ciphertext.size()),
                                            &bytesCopied, 0);
            if (NT_SUCCESS(status)) {
                ciphertext.resize(bytesCopied);
                ok = true;
            }
            BCryptDestroyKey(hKey);
        }
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

inline bool AES256GCMDecrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key32,
    const std::vector<uint8_t>& iv12,
    const std::vector<uint8_t>& tag16,
    std::vector<uint8_t>& plaintext)
{
    if (key32.size() != 32 || iv12.size() != 12 || tag16.size() != 16) return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        return false;
    }

    bool ok = false;
    if (NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                     sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {

        BCRYPT_KEY_HANDLE hKey = nullptr;
        if (NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                                 const_cast<PUCHAR>(key32.data()),
                                                 static_cast<ULONG>(key32.size()), 0))) {

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = const_cast<PUCHAR>(iv12.data());
            authInfo.cbNonce = static_cast<ULONG>(iv12.size());
            authInfo.pbTag = const_cast<PUCHAR>(tag16.data());
            authInfo.cbTag = static_cast<ULONG>(tag16.size());

            plaintext.resize(ciphertext.size());
            ULONG bytesCopied = 0;

            uint8_t dummyByte = 0;
            PUCHAR pbIn = ciphertext.empty() ? &dummyByte : const_cast<PUCHAR>(ciphertext.data());
            PUCHAR pbOut = plaintext.empty() ? &dummyByte : plaintext.data();

            NTSTATUS status = BCryptDecrypt(hKey,
                                            pbIn,
                                            static_cast<ULONG>(ciphertext.size()),
                                            &authInfo,
                                            nullptr, 0,
                                            pbOut,
                                            static_cast<ULONG>(plaintext.size()),
                                            &bytesCopied, 0);
            if (NT_SUCCESS(status)) {
                plaintext.resize(bytesCopied);
                ok = true;
            }
            BCryptDestroyKey(hKey);
        }
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

} // namespace crypto
} // namespace vantor
