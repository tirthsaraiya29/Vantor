# Vantor Signature Distribution & Update Guide

This guide describes how threat signatures are structured, imported, indexed in memory, and distributed across Vantor endpoints.

---

## 1. Hybrid Storage & Index Architecture

Vantor utilizes a **two-tier hybrid storage engine**:

1. **Persistent SQLite Store (`signatures.db`)**:
   - Stores all known SHA-256 malware digests in table `malware_hashes`.
   - Indexed via B-Tree index `idx_hash`.
   - Handles transactional bulk imports with rollbacks.
2. **Memory-Mapped Binary Index (`signatures.idx`)**:
   - High-performance binary file mapped directly into process memory (`CreateFileMappingW` / `MapViewOfFile`).
   - Contains:
     - **Header**: Magic `VSIG` (0x56534947), version, signature count.
     - **Bloom Filter (128 KB)**: Fast bitset keyed on MurmurMix64. Evaluated in $O(1)$ time (< 50 CPU cycles) to immediately eliminate non-malware files without disk I/O.
     - **Sorted 32-byte Binary Array**: All SHA-256 digests sorted in ascending order. Binary search executes in $O(\log N)$ microsecond time directly over virtual memory pages.

---

## 2. Bulk Importing Signatures

### Via Command-Line Interface (CLI)
You can import SHA-256 hashes from a standard text file (one 64-character hex hash per line):

```cmd
VantorBackend.exe db --import "path\to\hashes.txt"
```

The import pipeline:
1. Opens a high-speed SQLite transaction: `PRAGMA synchronous = OFF; BEGIN TRANSACTION;`.
2. Inserts batches of 50,000 hashes.
3. Automatically triggers `RebuildMemoryMappedIndex()` to update `signatures.idx` and re-map the Bloom filter.

### Via gRPC API
Invoke the `UpdateSignatures` RPC defined in `proto/vantor.proto`:

```protobuf
message SignatureUpdateRequest {
    string client_version = 1;
    repeated string sha256_hashes = 2;
    string update_source_url = 3;
    bool force_rebuild_index = 4;
}
```

Example request via curl / JSON-RPC:
```bash
curl -X POST http://127.0.0.1:50051/vantor.VantorBackendService/UpdateSignatures \
  -H "Content-Type: application/json" \
  -H "x-vantor-auth: vantor-secure-token-v2" \
  -d '{
    "sha256_hashes": [
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    ]
  }'
```

---

## 3. Zip-Bomb Ratio & Threshold Configuration

Protection against decompression bombs is managed via `config.json` or the Settings UI:

```json
{
    "zipBombRatioLimit": 10.0,
    "maxArchiveUncompressedBytes": 1073741824
}
```

- **`zipBombRatioLimit`**: Any archive with $\frac{\text{UncompressedSize}}{\text{CompressedSize}} > 10.0$ is immediately flagged as `ExcessiveCompressionRatio` and rejected.
- **`maxArchiveUncompressedBytes`**: Default 1 GB limit prevents disk filling attacks.

---

## 4. Self-Hosted Signature Server Setup

To distribute signature updates to remote endpoints:

1. Host a standard HTTPS endpoint that returns a JSON list of SHA-256 hashes:
   ```json
   {
       "version": "2026.11.03",
       "signatures": [
           "...",
           "..."
       ]
   }
   ```
2. Configure the URL in `config.json` under `"updateServerUrl"`.
3. The background service polls the update endpoint periodically according to `"updateIntervalMinutes"`.
