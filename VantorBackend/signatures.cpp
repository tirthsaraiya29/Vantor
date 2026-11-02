#include "signatures.h"
#include <sqlite3.h>
#include <iostream>

// Implementation to check the SHA256 against a database of known malware
bool signature_hit(const std::string& sha256) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    bool found = false;

    // Open the signatures database
    // "signatures.db" should contain a table (e.g., 'malware_hashes') with a 'hash' column
    if (sqlite3_open("signatures.db", &db) != SQLITE_OK) {
        return false;
    }

    // Prepare a SQL statement to find the hash
    const char* sql = "SELECT 1 FROM malware_hashes WHERE hash = ? LIMIT 1;";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        // Bind the sha256 string to the '?' placeholder
        sqlite3_bind_text(stmt, 1, sha256.c_str(), -1, SQLITE_TRANSIENT);

        // If a row is returned, the hash is in the database
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            found = true;
        }
    }

    // Clean up resources
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return found;
}