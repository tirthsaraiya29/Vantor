#include "service.h"
#include "ram.h"
#include <thread>
#include <windows.h>

void run_rtp_service() {
    // Run RAM booster in background
    std::thread ram_thread(run_ram_boost_background);
    ram_thread.detach();

    // Placeholder: additional realtime monitoring can be added here

    // Keep service alive
    while (true) {
        Sleep(60 * 1000);
    }
}
