#pragma once
#include "VantorBackend.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include <mutex>

using json = nlohmann::json;

static const std::string LOG_FILE = "logs.json";
static std::mutex log_mutex;

// Thread-safe append to logs.#pragma once

#include "VantorBackend.h"

/*
  Thin compatibility wrapper.
  No mutex.
  No file IO.
  No parsing.
*/

inline void log_scan_result(const ScanResult& r) {
    log_event_json({
        {"type", "file_scan_compat"},
        {"path", r.file_path},
        {"sha256", r.sha256},
        {"sha512", r.sha512},
        {"ml", r.ml_score},
        {"heur", r.heuristic_score},
        {"verdict", r.verdict}
        });
}