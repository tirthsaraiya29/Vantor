#pragma once
#include "VantorBackend.h"
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

void scan_recursive(
	const std::string& root,
	SafeDB& safe_db,
	const MLInference& ml,
	ScanHistoryDB& history_db,
	int session_id,
	const std::string& sid_string,
	int& files,
	int& threats
);

bool is_container_file(const std::string& path);