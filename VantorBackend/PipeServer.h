#pragma once
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <functional>

class PipeServer {
public:
    using MessageHandler = std::function<void(const std::string&)>;

    PipeServer(const std::string& pipeName, MessageHandler handler);
    ~PipeServer();

    void start();
    void stop();

private:
    void serverLoop();
    void handleClient(HANDLE pipe);

    std::string pipeName_;
    MessageHandler handler_;
    std::atomic<bool> running_;
    std::thread serverThread_;
};