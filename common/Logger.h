#pragma once

#include "Common.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <mutex>
#include <filesystem>
#include <deque>
#include <thread>
#include <condition_variable>
#include <atomic>

namespace vantor {
namespace logger {

enum class LogLevel {
    Debug = 0,
    Info,
    Warn,
    SecurityAlert,
    Error,
    Fatal
};

inline const char* LogLevelToString(LogLevel l) {
    switch (l) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warn: return "WARN";
        case LogLevel::SecurityAlert: return "SECURITY_ALERT";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Fatal: return "FATAL";
        default: return "UNKNOWN";
    }
}

struct LogEntry {
    std::string timestamp;
    LogLevel level;
    std::string component;
    std::string message;
    std::string extraJson;
};

class Logger {
public:
    static Logger& Instance() {
        static Logger instance;
        return instance;
    }

    void Init(const std::string& logDirectory = "logs") {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            logDir_ = logDirectory;
            std::error_code ec;
            std::filesystem::create_directories(logDir_, ec);
            logFile_ = logDir_ + "/vantor_service.jsonl";
        }
        StartFlushWorker();
    }

    void Log(LogLevel level, const std::string& component, const std::string& message, const std::string& extraJson = "{}") {
        std::string ts = NowUtcIso8601();

        // 1. Console Output immediately
        std::cout << "[" << ts << "] [" << LogLevelToString(level) << "] [" << component << "] " << message << std::endl;

        // 2. Windows Event Log Integration (SecurityAlert, Error, Fatal)
        if (level >= LogLevel::SecurityAlert && hEventSource_) {
            WORD wType = EVENTLOG_INFORMATION_TYPE;
            if (level == LogLevel::SecurityAlert) wType = EVENTLOG_WARNING_TYPE;
            else if (level == LogLevel::Error || level == LogLevel::Fatal) wType = EVENTLOG_ERROR_TYPE;

            std::wstring wideMsg = Utf8ToUtf16("[" + std::string(LogLevelToString(level)) + "] [" + component + "] " + message);
            LPCWSTR strings[1] = { wideMsg.c_str() };
            ReportEventW(hEventSource_, wType, 0, static_cast<DWORD>(level), nullptr, 1, 0, strings, nullptr);
        }

        // 3. Queue into in-memory ring buffer (up to 1000 entries)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.size() >= MAX_BUFFER_ENTRIES) {
                queue_.pop_front(); // drop oldest entry if buffer is saturated
            }
            queue_.push_back({ts, level, component, message, extraJson});
        }

        // If high severity or fatal, trigger immediate flush
        if (level >= LogLevel::SecurityAlert) {
            cv_.notify_one();
        }
    }

    void Flush() {
        std::vector<LogEntry> batch;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            batch.assign(queue_.begin(), queue_.end());
            queue_.clear();
        }
        if (!batch.empty()) {
            WriteBatch(batch);
        }
    }

    ~Logger() {
        running_ = false;
        cv_.notify_all();
        if (flushThread_.joinable()) {
            flushThread_.join();
        }
        Flush();

        if (hEventSource_) {
            DeregisterEventSource(hEventSource_);
            hEventSource_ = nullptr;
        }
    }

private:
    static constexpr size_t MAX_BUFFER_ENTRIES = 1000;
    static constexpr uint64_t MAX_LOG_FILE_SIZE = 10ULL * 1024ULL * 1024ULL; // 10 MB
    static constexpr int MAX_ROLLING_FILES = 5;

    Logger() {
        hEventSource_ = RegisterEventSourceW(nullptr, L"VantorAntivirus");
        Init();
    }

    void StartFlushWorker() {
        if (!flushThread_.joinable()) {
            running_ = true;
            flushThread_ = std::thread(&Logger::FlushWorker, this);
        }
    }

    void FlushWorker() {
        while (running_) {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(500), [this] {
                return !running_ || queue_.size() >= 50;
            });

            std::vector<LogEntry> batch;
            if (!queue_.empty()) {
                batch.assign(queue_.begin(), queue_.end());
                queue_.clear();
            }
            lock.unlock();

            if (!batch.empty()) {
                WriteBatch(batch);
            }
        }
    }

    void RotateLogsIfNeeded() {
        namespace fs = std::filesystem;
        std::error_code ec;
        if (!fs::exists(logFile_, ec)) return;

        uint64_t sz = fs::file_size(logFile_, ec);
        if (ec || sz < MAX_LOG_FILE_SIZE) return;

        // Perform rolling rotation: 5 rolling files
        fs::path oldest = fs::path(logDir_) / ("vantor_service." + std::to_string(MAX_ROLLING_FILES) + ".jsonl");
        fs::remove(oldest, ec);

        for (int i = MAX_ROLLING_FILES - 1; i >= 1; --i) {
            fs::path src = fs::path(logDir_) / ("vantor_service." + std::to_string(i) + ".jsonl");
            fs::path dst = fs::path(logDir_) / ("vantor_service." + std::to_string(i + 1) + ".jsonl");
            if (fs::exists(src, ec)) {
                fs::rename(src, dst, ec);
            }
        }

        fs::path target1 = fs::path(logDir_) / "vantor_service.1.jsonl";
        fs::rename(logFile_, target1, ec);
    }

    void WriteBatch(const std::vector<LogEntry>& batch) {
        if (logFile_.empty()) return;

        RotateLogsIfNeeded();

        std::ofstream ofs(logFile_, std::ios::app);
        if (!ofs) return;

        for (const auto& entry : batch) {
            ofs << "{"
                << "\"timestamp\":\"" << entry.timestamp << "\","
                << "\"level\":\"" << LogLevelToString(entry.level) << "\","
                << "\"component\":\"" << entry.component << "\","
                << "\"message\":\"" << EscapeJson(entry.message) << "\","
                << "\"details\":" << (entry.extraJson.empty() ? "{}" : entry.extraJson)
                << "}\n";
        }
        ofs.flush();
    }

    std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\b') o << "\\b";
            else if (c == '\f') o << "\\f";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else if ((unsigned char)c <= 0x1f) {
                o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            } else {
                o << c;
            }
        }
        return o.str();
    }

    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<LogEntry> queue_;
    std::atomic<bool> running_{false};
    std::thread flushThread_;

    std::string logDir_;
    std::string logFile_;
    HANDLE hEventSource_{nullptr};
};

#define LOG_DEBUG(comp, msg) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::Debug, comp, msg)
#define LOG_INFO(comp, msg) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::Info, comp, msg)
#define LOG_WARN(comp, msg) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::Warn, comp, msg)
#define LOG_ALERT(comp, msg, extra) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::SecurityAlert, comp, msg, extra)
#define LOG_ERROR(comp, msg) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::Error, comp, msg)
#define LOG_FATAL(comp, msg) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::Fatal, comp, msg)

} // namespace logger
} // namespace vantor
