#include "telemetry.h"
#include "logging.h"
#include <vector>
#include <string>
#include <mutex>

static std::mutex telemetry_mutex;
static std::vector<std::string> telemetry_buffer;

void init_telemetry() {
    std::lock_guard<std::mutex> lock(telemetry_mutex);
    telemetry_buffer.clear();
}

void record_process_start(const std::string& exe, const std::vector<std::string>& args, int ppid) {
    std::lock_guard<std::mutex> lock(telemetry_mutex);
    std::string entry = exe + " [PPID:" + std::to_string(ppid) + "] Args:";
    for (auto& a : args) entry += " " + a;
    telemetry_buffer.push_back(entry);
}

void send_telemetry_batch() {
    std::lock_guard<std::mutex> lock(telemetry_mutex);
    for (auto& t : telemetry_buffer) {
        log_event_json({ {"type","telemetry"}, {"data",t} });
    }
    telemetry_buffer.clear();
}
