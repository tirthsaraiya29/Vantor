#pragma once

#include "Common.h"
#include <sddl.h>
#include <vector>
#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>

namespace vantor {
namespace ipc {

constexpr DWORD DEFAULT_PIPE_BUFFER_SIZE = 64 * 1024; // 64 KB

// Helper to create SECURITY_ATTRIBUTES from SDDL
inline bool CreateSecurityAttributesFromSDDL(const wchar_t* sddl, SECURITY_ATTRIBUTES& sa) {
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = nullptr;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            SDDL_REVISION_1,
            &sa.lpSecurityDescriptor,
            nullptr)) {
        return false;
    }
    return true;
}

inline void FreeSecurityAttributes(SECURITY_ATTRIBUTES& sa) {
    if (sa.lpSecurityDescriptor) {
        LocalFree(sa.lpSecurityDescriptor);
        sa.lpSecurityDescriptor = nullptr;
    }
}

// Low-level Framing read/write helpers
inline bool WriteFramedMessage(HANDLE hPipe, const std::string& message) {
    uint32_t length = static_cast<uint32_t>(message.size());
    DWORD bytesWritten = 0;

    // Write length header
    if (!WriteFile(hPipe, &length, sizeof(length), &bytesWritten, nullptr) || bytesWritten != sizeof(length)) {
        return false;
    }

    // Write payload
    if (length > 0) {
        if (!WriteFile(hPipe, message.data(), length, &bytesWritten, nullptr) || bytesWritten != length) {
            return false;
        }
    }
    FlushFileBuffers(hPipe);
    return true;
}

inline bool ReadFramedMessage(HANDLE hPipe, std::string& message, DWORD timeoutMs = INFINITE) {
    (void)timeoutMs;
    uint32_t length = 0;
    DWORD bytesRead = 0;

    if (!ReadFile(hPipe, &length, sizeof(length), &bytesRead, nullptr) || bytesRead != sizeof(length)) {
        return false;
    }

    if (length > 10 * 1024 * 1024) { // 10MB safety sanity cap
        return false;
    }

    message.resize(length);
    if (length > 0) {
        DWORD totalRead = 0;
        while (totalRead < length) {
            if (!ReadFile(hPipe, &message[totalRead], length - totalRead, &bytesRead, nullptr) || bytesRead == 0) {
                return false;
            }
            totalRead += bytesRead;
        }
    }
    return true;
}

// Client Named Pipe Wrapper
class NamedPipeClient {
public:
    NamedPipeClient(std::wstring pipeName = IPC_PIPE_NAME) : pipeName_(std::move(pipeName)), hPipe_(INVALID_HANDLE_VALUE) {}

    ~NamedPipeClient() {
        Disconnect();
    }

    bool Connect(DWORD timeoutMs = 5000) {
        Disconnect();
        auto start = std::chrono::steady_clock::now();

        while (true) {
            hPipe_ = CreateFileW(
                pipeName_.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr
            );

            if (hPipe_ != INVALID_HANDLE_VALUE) {
                DWORD mode = PIPE_READMODE_BYTE;
                SetNamedPipeHandleState(hPipe_, &mode, nullptr, nullptr);
                return true;
            }

            if (GetLastError() != ERROR_PIPE_BUSY) {
                return false;
            }

            if (!WaitNamedPipeW(pipeName_.c_str(), 1000)) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed >= timeoutMs) {
                    return false;
                }
            }
        }
    }

    void Disconnect() {
        if (hPipe_ != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe_);
            hPipe_ = INVALID_HANDLE_VALUE;
        }
    }

    bool IsConnected() const {
        return hPipe_ != INVALID_HANDLE_VALUE;
    }

    bool SendRequest(const std::string& request, std::string& response) {
        if (!IsConnected()) {
            if (!Connect()) return false;
        }
        if (!WriteFramedMessage(hPipe_, request)) {
            Disconnect();
            return false;
        }
        if (!ReadFramedMessage(hPipe_, response)) {
            Disconnect();
            return false;
        }
        return true;
    }

private:
    std::wstring pipeName_;
    HANDLE hPipe_;
};

// Server Named Pipe Wrapper
class NamedPipeServer {
public:
    using MessageHandler = std::function<std::string(const std::string& request)>;

    NamedPipeServer(std::wstring pipeName = IPC_PIPE_NAME)
        : pipeName_(std::move(pipeName)), running_(false), hStopEvent_(nullptr) {}

    ~NamedPipeServer() {
        Stop();
    }

    bool Start(MessageHandler handler) {
        handler_ = std::move(handler);
        running_ = true;
        hStopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        serverThread_ = std::thread(&NamedPipeServer::ServerWorker, this);
        return true;
    }

    void Stop() {
        running_ = false;
        if (hStopEvent_) {
            SetEvent(hStopEvent_);
        }
        // Connect a dummy client to wake up any blocking ConnectNamedPipe
        HANDLE hWake = CreateFileW(pipeName_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hWake != INVALID_HANDLE_VALUE) {
            CloseHandle(hWake);
        }

        if (serverThread_.joinable()) {
            serverThread_.join();
        }
        if (hStopEvent_) {
            CloseHandle(hStopEvent_);
            hStopEvent_ = nullptr;
        }
    }

private:
    void ServerWorker() {
        SECURITY_ATTRIBUTES sa;
        if (!CreateSecurityAttributesFromSDDL(IPC_PIPE_SDDL, sa)) {
            return;
        }

        while (running_) {
            HANDLE hPipe = CreateNamedPipeW(
                pipeName_.c_str(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                DEFAULT_PIPE_BUFFER_SIZE,
                DEFAULT_PIPE_BUFFER_SIZE,
                0,
                &sa
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                continue;
            }

            BOOL connected = ConnectNamedPipe(hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

            if (connected && running_) {
                std::string request;
                while (running_ && ReadFramedMessage(hPipe, request)) {
                    std::string response = handler_ ? handler_(request) : "{\"status\":\"ok\"}";
                    if (!WriteFramedMessage(hPipe, response)) {
                        break;
                    }
                }
            }

            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }

        FreeSecurityAttributes(sa);
    }

    std::wstring pipeName_;
    std::atomic<bool> running_;
    HANDLE hStopEvent_;
    std::thread serverThread_;
    MessageHandler handler_;
};

} // namespace ipc
} // namespace vantor
