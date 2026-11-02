#pragma once
#include <string>
#include <vector>

void init_telemetry();
void record_process_start(const std::string& exe, const std::vector<std::string>& args, int ppid);
void send_telemetry_batch();
