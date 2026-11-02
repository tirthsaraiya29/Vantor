#pragma once
#include <string>

bool handle_malicious_file(
    const std::string& path,
    const std::string& sid,
    const std::string& sha256,
    const std::string& sha512
);

bool decrypt_quarantined_file(
    const std::string& enc_path,
    const std::string& output_path
);

std::string get_quarantine_dir();