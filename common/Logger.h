#pragma once

#include "Common.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <mutex>
#include <filesystem>

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

class Logger {
public:
    static Logger& Instance() {
        static Logger instance;
        return instance;
    }

    void Init(const std::string& logDirectory = "logs") {
        std::lock_guard<std::mutex> lock(mutex_);
        logDir_ = logDirectory;
        std::error_code ec;
        std::filesystem::create_directories(logDir_, ec);
        logFile_ = logDir_ + "/vantor_service.jsonl";
    }

    void Log(LogLevel level, const std::string& component, const std::string& message, const std::string& extraJson = "{}") {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string ts = NowUtcIso8601();

        // 1. Console Output
        std::cout << "[" << ts << "] [" << LogLevelToString(level) << "] [" << component << "] " << message << std::endl;

        // 2. Structured JSONL output
        if (!logFile_.empty()) {
            std::ofstream ofs(logFile_, std::ios::app);
            if (ofs) {
                ofs << "{"
                    << "\"timestamp\":\"" << ts << "\","
                    << "\"level\":\"" << LogLevelToString(level) << "\","
                    << "\"component\":\"" << component << "\","
                    << "\"message\":\"" << EscapeJson(message) << "\","
                    << "\"details\":" << (extraJson.empty() ? "{}" : extraJson)
                    << "}\n";
            }
        }
    }

private:
    Logger() {
        Init();
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
    std::string logDir_;
    std::string logFile_;
};

#define LOG_DEBUG(comp, msg) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::Debug, comp, msg)
#define LOG_INFO(comp, msg) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::Info, comp, msg)
#define LOG_WARN(comp, msg) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::Warn, comp, msg)
#define LOG_ALERT(comp, msg, extra) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::SecurityAlert, comp, msg, extra)
#define LOG_ERROR(comp, msg) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::Error, comp, msg)
#define LOG_FATAL(comp, msg) vantor::logger::Logger::Instance().Log(vantor::logger::LogLevel::Fatal, comp, msg)

} // namespace logger
} // namespace vantor
