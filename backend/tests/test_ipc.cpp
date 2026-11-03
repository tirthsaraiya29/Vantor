#include "TestHarness.h"
#include "../../common/NamedPipe.h"
#include <chrono>

using namespace vantor::ipc;

TEST(IpcTests, NamedPipeServerClientCommunication) {
    std::wstring testPipe = L"\\\\.\\pipe\\VantorTestPipe_" + std::to_wstring(GetCurrentProcessId());

    NamedPipeServer server(testPipe);
    bool started = server.Start([](const std::string& req) {
        return "{\"echo\":\"" + req + "\"}";
    });
    EXPECT_TRUE(started);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    NamedPipeClient client(testPipe);
    EXPECT_TRUE(client.Connect(3000));

    std::string response;
    EXPECT_TRUE(client.SendRequest("hello_vantor", response));
    EXPECT_TRUE(response.find("hello_vantor") != std::string::npos);

    client.Disconnect();
    server.Stop();
}
