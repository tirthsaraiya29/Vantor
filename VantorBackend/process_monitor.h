#pragma once
#include <string>
#include <vector>

void init_process_monitor();
void monitor_processes();
void register_process_creation(const std::string& exe, const std::vector<std::string>& args, int ppid);
