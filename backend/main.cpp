#include "../common/Common.h"
#include "../common/Logger.h"
#include "SignatureStore.h"
#include "ZipBombDetector.h"
#include "GrpcServer.h"
#include "../service/AntiTamper.h"
#include "../common/NamedPipe.h"

#include <iostream>
#include <string>

using namespace vantor;

void PrintBanner() {
    std::cout << "========================================================\n";
    std::cout << "       Vantor Antivirus High-Performance C++ Backend    \n";
    std::cout << "       Platform: Windows 10/11 x64                      \n";
    std::cout << "========================================================\n\n";
}

void PrintHelp() {
    PrintBanner();
    std::cout << "Usage:\n";
    std::cout << "  VantorBackend.exe server [--port 50051]       Start gRPC daemon\n";
    std::cout << "  VantorBackend.exe scan <quick|full|custom>    Trigger scan via Service\n";
    std::cout << "  VantorBackend.exe db --stats                  Display signature store metrics\n";
    std::cout << "  VantorBackend.exe db --import <hashes.txt>    Bulk import signatures\n";
    std::cout << "  VantorBackend.exe inspect-zip <archive.zip>   Analyze archive for zip-bombs\n";
    std::cout << "  VantorBackend.exe verify                      Execute anti-tamper verification\n\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintBanner();
        std::cout << "[*] Starting Vantor gRPC Server on 127.0.0.1:50051 (Default)...\n";

        backend::SignatureStore::Instance().Initialize();
        backend::VantorGrpcServer server;
        if (!server.Start()) {
            std::cerr << "[-] Failed to start gRPC server.\n";
            return 1;
        }

        std::cout << "[+] Server running. Press Ctrl+C or send SIGINT to stop.\n";
        server.WaitForShutdown();
        return 0;
    }

    std::string command = argv[1];

    if (command == "server") {
        int port = 50051;
        if (argc >= 4 && std::string(argv[2]) == "--port") {
            port = std::stoi(argv[3]);
        }

        PrintBanner();
        std::cout << "[*] Initializing SignatureStore & Index...\n";
        backend::SignatureStore::Instance().Initialize();

        backend::GrpcServerOptions opts;
        opts.port = port;
        backend::VantorGrpcServer server(opts);
        if (!server.Start()) {
            std::cerr << "[-] Failed to bind gRPC server to port " << port << "\n";
            return 1;
        }

        std::cout << "[+] Vantor gRPC Backend Server active on port " << port << ".\n";
        server.WaitForShutdown();
        return 0;
    }
    else if (command == "scan") {
        std::string mode = argc >= 3 ? argv[2] : "quick";
        std::string path = argc >= 4 ? argv[3] : "";

        ipc::NamedPipeClient client;
        if (!client.Connect()) {
            std::cerr << "[-] Cannot connect to Vantor Windows Service. Ensure service is running.\n";
            return 1;
        }

        std::string req = "{\"cmd\":\"start_scan\",\"type\":\"" + mode + "\",\"path\":\"" + path + "\"}";
        std::string resp;
        if (client.SendRequest(req, resp)) {
            std::cout << "[+] Scan Response: " << resp << "\n";
        } else {
            std::cerr << "[-] Failed to send scan request to service.\n";
            return 1;
        }
        return 0;
    }
    else if (command == "db") {
        backend::SignatureStore::Instance().Initialize();

        if (argc >= 3 && std::string(argv[2]) == "--stats") {
            std::cout << "[+] Total Indexed Signatures: " << backend::SignatureStore::Instance().GetTotalSignatures() << "\n";
            return 0;
        }
        else if (argc >= 4 && std::string(argv[2]) == "--import") {
            std::string file = argv[3];
            std::cout << "[*] Importing signatures from: " << file << "...\n";
            auto start = std::chrono::steady_clock::now();
            size_t count = backend::SignatureStore::Instance().ImportFromTextFile(file);
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();

            std::cout << "[+] Successfully imported " << count << " signatures in " << elapsed << " ms.\n";
            std::cout << "[+] Current total signatures: " << backend::SignatureStore::Instance().GetTotalSignatures() << "\n";
            return 0;
        }
    }
    else if (command == "inspect-zip") {
        if (argc < 3) {
            std::cerr << "Usage: VantorBackend.exe inspect-zip <path-to-archive.zip>\n";
            return 1;
        }
        std::string archivePath = argv[2];
        backend::ZipBombDetector detector;
        auto res = detector.InspectArchive(archivePath);

        std::cout << "========================================================\n";
        std::cout << "               ZIP ARCHIVE SECURITY AUDIT                \n";
        std::cout << "========================================================\n";
        std::cout << "File:                 " << res.archivePath << "\n";
        std::cout << "Verdict:              " << backend::ZipVerdictToString(res.verdict) << "\n";
        std::cout << "Archive File Size:    " << res.archiveFileSizeBytes << " bytes\n";
        std::cout << "Total Uncompressed:   " << res.totalUncompressedBytes << " bytes\n";
        std::cout << "Total Compressed:     " << res.totalCompressedBytes << " bytes\n";
        std::cout << "Compression Ratio:    " << res.overallCompressionRatio << "x\n";
        std::cout << "Total Entries:        " << res.totalEntries << "\n";
        std::cout << "Nested Archives:      " << res.nestedArchiveCount << "\n";
        std::cout << "Evaluation Reason:    " << res.reason << "\n";
        std::cout << "========================================================\n";

        return (res.verdict == backend::ZipVerdict::Safe) ? 0 : 2;
    }
    else if (command == "verify") {
        std::cout << "[*] Running Anti-Tamper self-check...\n";
        antitamper::AntiTamper::Instance().Initialize();
        auto alert = antitamper::AntiTamper::Instance().RunComprehensiveIntegrityCheck();

        if (alert.tampered) {
            std::cerr << "[!] SECURITY ALERT: Tampering detected!\n";
            std::cerr << "    Reason:    " << alert.reason << "\n";
            std::cerr << "    Target:    " << alert.affectedTarget << "\n";
            std::cerr << "    Mechanism: " << alert.detectionMechanism << "\n";
            return 3;
        } else {
            std::cout << "[+] All user-mode integrity, code-signing, self-hash, and anti-debug checks passed.\n";
            return 0;
        }
    }

    PrintHelp();
    return 0;
}
