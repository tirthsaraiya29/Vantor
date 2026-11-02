#include "recursive.h"
#include <thread>
#include <chrono>
#include <iostream>

bool is_container_file(const std::string& path) {
	std::string ext = fs::path(path).extension().string();
	for (auto& c : ext) c = std::tolower(c);
	return (ext == ".zip" || ext == ".7z" || ext == ".iso" || ext == ".rar" || ext == ".tar");
}

void scan_recursive(const std::string& root, SafeDB& safe_db, const MLInference& ml, ScanHistoryDB& history_db, int session_id, const std::string& sid_string, int& files, int& threats) {
    if (!fs::exists(root)) return;

    for (const auto& entry : fs::directory_iterator(root, fs::directory_options::skip_permission_denied)) {
        try {
            std::string path = entry.path().string();

            if (entry.is_directory()) {
                // Normal folder recursion
                scan_recursive(path, safe_db, ml, history_db, session_id, sid_string, files, threats);
            }
            else if (entry.is_regular_file()) {

                if (is_container_file(path)) {
                    // --- CONTAINER HANDLING LOGIC ---
                    // 1. Create a unique temp directory for this archive
                    std::string temp_work_dir = "temp_scan_" + std::to_string(std::hash<std::string>{}(path));
                    fs::create_directories(temp_work_dir);

                    // 2. Extract the archive (Using system call to PowerShell/7z for example)
                    // In a production environment, use libarchive here.
                    std::string cmd = "powershell -Command \"Expand-Archive -Path '" + path + "' -DestinationPath '" + temp_work_dir + "' -Force\"";

                    // We hide the output to keep the console clean
                    if (system((cmd + " > nul 2>&1").c_str()) == 0) {
                        // 3. Recurse into the extracted folder (allows zips inside zips)
                        scan_recursive(temp_work_dir, safe_db, ml, history_db, session_id, sid_string, files, threats);
                    }

                    // 4. Cleanup temp files after scanning
                    fs::remove_all(temp_work_dir);
                }
                else {
                    // Normal file scan
                    files++;
                    ScanResult r = scan_file(path, safe_db, ml, history_db, session_id, sid_string);
                    if (r.is_malicious) threats++;
                }
            }

            // CPU Yield to prevent system lag
            std::this_thread::sleep_for(std::chrono::milliseconds(5));

        }
        catch (const std::exception& e) {
            // Log error but continue scanning other files
            continue;
        }
    }
}