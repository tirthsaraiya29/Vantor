#define NOMINMAX
#include "feature_extractor.h"
#include <windows.h>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>

/**
 * Calculates normalized entropy (0.0 to 1.0) to identify potentially
 * packed or encrypted data segments [cite: 590-594].
 */
static double calculate_entropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    double freq[256] = {};
    for (size_t i = 0; i < size; i++)
        freq[data[i]]++;
    double ent = 0.0;
    for (double f : freq) {
        if (f == 0) continue;
        double p = f / size;
        ent -= p * std::log2(p);
    }
    return ent / 8.0;
}

/**
 * Helper to read raw binary data into a buffer [cite: 594-595].
 */
static bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign(std::istreambuf_iterator<char>(f), {});
    return true;
}

/**
 * Deep PE parsing to extract structural and behavioral traits [cite: 596-597].
 * Upgraded to identify 'Suspicious Sections' (e.g., Writable + Executable).
 */
template<typename NT_HEADERS>
static void parse_pe_internal(const std::vector<uint8_t>& buf, std::vector<float>& feats, const NT_HEADERS* nt) {
    const auto& fh = nt->FileHeader;
    const auto& oh = nt->OptionalHeader;

    // Structural features: Section count, Characteristics, and Memory layout
    feats.push_back((float)fh.NumberOfSections / 10.0f);
    feats.push_back((float)fh.Characteristics / 65535.0f);
    feats.push_back((float)oh.SizeOfImage / (1024.0f * 1024.0f));
    feats.push_back((float)oh.AddressOfEntryPoint / (1024.0f * 1024.0f));

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    double max_ent = 0.0;
    double mean_ent = 0.0;
    int suspicious_sections = 0;

    for (int i = 0; i < fh.NumberOfSections; i++) {
        if (sec[i].PointerToRawData + sec[i].SizeOfRawData > buf.size())
            continue;

        // UPGRADE: Identify sections that are both Writable and Executable (W^X violation)
        // This is a hallmark of unpacked malware or shellcode stubs .
        if ((sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            suspicious_sections++;
        }

        double e = calculate_entropy(&buf[sec[i].PointerToRawData], sec[i].SizeOfRawData);
        max_ent = (std::max)(max_ent, e);
        mean_ent += e;
    }

    if (fh.NumberOfSections > 0)
        mean_ent /= fh.NumberOfSections;

    feats.push_back((float)mean_ent);
    feats.push_back((float)max_ent);

    // UPGRADE: New features for the Weighted Point System
    feats.push_back((float)suspicious_sections / 5.0f);
    feats.push_back((float)oh.CheckSum == 0 ? 1.0f : 0.0f); // Missing checksums are common in custom malware
}

std::vector<float> extract_features(const std::string& path) {
    std::vector<float> features;
    features.reserve(8);
    std::vector<uint8_t> buf;

    if (!read_file(path, buf) || buf.size() < sizeof(IMAGE_DOS_HEADER)) {
        return std::vector<float>(8, 0.0f); 
    }

    auto* dos = (IMAGE_DOS_HEADER*)buf.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        dos->e_lfanew + sizeof(DWORD) > buf.size()) {
        return std::vector<float>(8, 0.0f); 
    }

    DWORD nt_sig = *(DWORD*)&buf[dos->e_lfanew];
    if (nt_sig != IMAGE_NT_SIGNATURE) {
        return std::vector<float>(8, 0.0f);
    }

    WORD magic = *(WORD*)(&buf[dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)]);

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        parse_pe_internal(buf, features, (IMAGE_NT_HEADERS32*)&buf[dos->e_lfanew]);
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        parse_pe_internal(buf, features, (IMAGE_NT_HEADERS64*)&buf[dos->e_lfanew]);
    }
    else {
        features.assign(8, 0.0f);
    }

    // Ensure we always return at least the minimum expected vector size
    if (features.size() < 8)
        features.resize(8, 0.0f);

    return features;
}