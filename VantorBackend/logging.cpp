#include "logging.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <iostream>
#include <vector>
#include <mutex>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <zip.h>

namespace fs = std::filesystem;

namespace {
    std::mutex log_mutex;
    fs::path log_dir = "logs";
    fs::path temp_log_file = log_dir / "scan_log.jsonl";

    std::string current_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::tm tm{};
        localtime_s(&tm, &t);  // <-- safer version

        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        oss << '.' << std::setw(3) << std::setfill('0') << ms.count();
        return oss.str();
    }


    std::ofstream& log_file() {
        static std::ofstream ofs;
        if (!ofs.is_open()) {
            fs::create_directories(log_dir);
            ofs.open(temp_log_file, std::ios::app);
            if (!ofs.is_open()) throw std::runtime_error("Cannot open log file");
        }
        return ofs;
    }

    // AES-256-CBC encryption helper
    std::vector<unsigned char> encrypt_aes(const std::vector<unsigned char>& plaintext, const std::string& password) {
        std::vector<unsigned char> ciphertext(plaintext.size() + 32);
        unsigned char key[32], iv[16];
        if (!RAND_bytes(iv, sizeof(iv))) throw std::runtime_error("Failed to generate IV");

        // Simple key derivation from password (PBKDF2 could be used here)
        std::fill(key, key + 32, 0);
        for (size_t i = 0; i < password.size() && i < 32; ++i) key[i] = password[i];

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int len, ciphertext_len;
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);

        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }
}

// =========================
// Logging Implementations
// =========================

void log_event_json(const std::string& sid, const std::string& timestamp, const std::string& path, const std::string& verdict) {
    std::lock_guard<std::mutex> lock(log_mutex);
    json obj = { {"sid", sid}, {"timestamp", timestamp}, {"path", path}, {"verdict", verdict} };
    log_file() << obj.dump() << std::endl;
}

void log_event_json(const json& obj) {
    std::lock_guard<std::mutex> lock(log_mutex);
    log_file() << obj.dump() << std::endl;
}

// =========================
// Finalize logs: zip + encrypt
// =========================

bool finalize_logs(const std::string& zip_path, const std::string& password) {
    std::lock_guard<std::mutex> lock(log_mutex);

    if (!fs::exists(temp_log_file)) return false;

    int err = 0;
    zip_t* zip = zip_open(zip_path.c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!zip) return false;

    std::ifstream ifs(temp_log_file, std::ios::binary);
    std::vector<unsigned char> log_data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    std::vector<unsigned char> encrypted = encrypt_aes(log_data, password);

    zip_source_t* src = zip_source_buffer(zip, encrypted.data(), encrypted.size(), 0);
    if (!src) { zip_close(zip); return false; }

    zip_file_add(zip, "scan_log.enc", src, ZIP_FL_OVERWRITE);
    zip_close(zip);

    fs::remove(temp_log_file); // remove temporary plaintext log
    return true;
}
