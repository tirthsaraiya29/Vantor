#include "quarantine.h"
#include "VantorBackend.h"
#include <windows.h>
#include <wincrypt.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#pragma comment(lib, "crypt32.lib")
namespace fs = std::filesystem;

static const size_t KEY_SIZE = 32;
static const size_t IV_SIZE = 12;
static const size_t TAG_SIZE = 16;

/* =========================   Helpers   ========================= */

static std::string get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    gmtime_s(&tm, &t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string get_quarantine_dir() {
    fs::path dir = fs::current_path() / "quarantine";
    fs::create_directories(dir);
    return dir.string();
}

/* =========================   Database Logic   ========================= */

static void init_quarantine_db() {
    sqlite3* db;
    std::string db_path = (fs::path(get_quarantine_dir()) / "quarantine.db").string();
    if (sqlite3_open(db_path.c_str(), &db) == SQLITE_OK) {
        const char* sql = "CREATE TABLE IF NOT EXISTS quarantined_files ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT, "
            "scan_id TEXT, "
            "original_path TEXT, "
            "sha256 TEXT, "
            "sha512 TEXT);";
        sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
    }
    sqlite3_close(db);
}

static void log_to_quarantine_db(const std::string& sid, const std::string& path, const std::string& s256, const std::string& s512) {
    sqlite3* db;
    std::string db_path = (fs::path(get_quarantine_dir()) / "quarantine.db").string();
    if (sqlite3_open(db_path.c_str(), &db) == SQLITE_OK) {
        const char* sql = "INSERT INTO quarantined_files (timestamp, scan_id, original_path, sha256, sha512) VALUES (?, ?, ?, ?, ?);";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            std::string ts = get_current_timestamp();
            sqlite3_bind_text(stmt, 1, ts.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, sid.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, path.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 4, s256.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 5, s512.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
}

static void add_to_signatures_db(const std::string& sha256) {
    sqlite3* db;
    // Open signatures.db in the current working directory
    if (sqlite3_open("signatures.db", &db) == SQLITE_OK) {
        sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS signatures (hash TEXT UNIQUE);", nullptr, nullptr, nullptr);
        const char* sql = "INSERT OR IGNORE INTO signatures (hash) VALUES (?);";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, sha256.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
}

/* =========================   Encryption Logic   ========================= */

static bool load_or_create_key(std::vector<uint8_t>& key) {
    fs::path key_path = fs::path(get_quarantine_dir()) / "master.key";

    if (fs::exists(key_path)) {
        std::ifstream in(key_path, std::ios::binary);
        std::vector<uint8_t> enc((std::istreambuf_iterator<char>(in)), {});
        DATA_BLOB in_blob{ static_cast<DWORD>(enc.size()), enc.data() };
        DATA_BLOB out_blob{};

        if (!CryptUnprotectData(&in_blob, nullptr, nullptr, nullptr, nullptr, 0, &out_blob))
            return false;

        key.assign(out_blob.pbData, out_blob.pbData + out_blob.cbData);
        LocalFree(out_blob.pbData);
        return true;
    }

    key.resize(KEY_SIZE);
    RAND_bytes(key.data(), (int)KEY_SIZE);
    DATA_BLOB in_blob{ (DWORD)KEY_SIZE, key.data() };
    DATA_BLOB out_blob{};

    if (!CryptProtectData(&in_blob, L"VantorKey", nullptr, nullptr, nullptr, 0, &out_blob))
        return false;

    std::ofstream out(key_path, std::ios::binary);
    out.write((char*)out_blob.pbData, out_blob.cbData);
    LocalFree(out_blob.pbData);
    return true;
}

static bool encrypt_file(const std::string& src, const std::string& dst, const std::vector<uint8_t>& key) {
    std::ifstream in(src, std::ios::binary);
    if (!in) return false;

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), {});
    std::vector<uint8_t> iv(IV_SIZE);
    RAND_bytes(iv.data(), (int)IV_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> out_buf(data.size() + 32);
    int len = 0, outlen = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)IV_SIZE, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    EVP_EncryptUpdate(ctx, out_buf.data(), &len, data.data(), (int)data.size());
    outlen = len;

    EVP_EncryptFinal_ex(ctx, out_buf.data() + outlen, &len);
    outlen += len;

    std::vector<uint8_t> tag(TAG_SIZE);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)TAG_SIZE, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    std::ofstream ofs(dst, std::ios::binary);
    ofs.write((char*)iv.data(), iv.size());
    ofs.write((char*)out_buf.data(), outlen);
    ofs.write((char*)tag.data(), tag.size());
    return true;
}

/* =========================   Public API   ========================= */

bool handle_malicious_file(const std::string& path, const std::string& sid, const std::string& sha256, const std::string& sha512) {
    init_quarantine_db();

    std::vector<uint8_t> key;
    if (!load_or_create_key(key)) return false;

    fs::path src(path);
    fs::path dst = fs::path(get_quarantine_dir()) / (src.filename().string() + ".enc");

    if (!encrypt_file(src.string(), dst.string(), key)) return false;

    // Record metadata and blacklist hash
    log_to_quarantine_db(sid, path, sha256, sha512);
    add_to_signatures_db(sha256);

    fs::remove(src);
    log_event_json(sid, get_current_timestamp(), path, "quarantined");

    return true;
}

bool decrypt_quarantined_file(const std::string& enc_path, const std::string& output_path) {
    std::vector<uint8_t> key;
    if (!load_or_create_key(key)) return false;

    std::ifstream in(enc_path, std::ios::binary);
    if (!in) return false;

    std::vector<uint8_t> iv(IV_SIZE);
    in.read((char*)iv.data(), IV_SIZE);

    std::vector<uint8_t> enc_data((std::istreambuf_iterator<char>(in)), {});
    if (enc_data.size() < TAG_SIZE) return false;

    std::vector<uint8_t> tag(enc_data.end() - TAG_SIZE, enc_data.end());
    enc_data.resize(enc_data.size() - TAG_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> out_buf(enc_data.size());
    int len = 0, outlen = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)IV_SIZE, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    EVP_DecryptUpdate(ctx, out_buf.data(), &len, enc_data.data(), (int)enc_data.size());
    outlen = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)TAG_SIZE, tag.data());
    if (EVP_DecryptFinal_ex(ctx, out_buf.data() + outlen, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    std::ofstream ofs(output_path, std::ios::binary);
    ofs.write((char*)out_buf.data(), outlen + len);
    return true;
}