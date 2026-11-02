#include "VantorBackend.h"
#include <string>

void log_memory_event(
    const std::string& type,
    const std::string& message
) {
    log_event_json({
        {"type", type},
        {"message", message}
        });
}
