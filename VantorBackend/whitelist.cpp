#include "whitelist.h"
#include <set>
#include <mutex>
#include <fstream>
#include <algorithm>

static std::set<std::string> whitelist;
static std::mutex wl_mutex;

void load_whitelist(const std::string& path) {
    std::lock_guard<std::mutex> lock(wl_mutex);
    whitelist.clear();
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        whitelist.insert(line);
    }
}

bool is_whitelisted(const std::string& path) {
    std::lock_guard<std::mutex> lock(wl_mutex);
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return whitelist.count(lower) > 0;
}

void add_whitelist_entry(const std::string& path) {
    std::lock_guard<std::mutex> lock(wl_mutex);
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    whitelist.insert(lower);
}
