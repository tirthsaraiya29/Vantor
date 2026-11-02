#pragma once
#include <string>
#include <vector>

bool is_whitelisted(const std::string& path);
void add_whitelist_entry(const std::string& path);
void load_whitelist(const std::string& path);
