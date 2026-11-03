#pragma once

#include "../common/NamedPipe.h"
#include <memory>
#include <string>

namespace vantor {
namespace service {

class ServiceIPC {
public:
    static ServiceIPC& Instance() {
        static ServiceIPC instance;
        return instance;
    }

    bool Start();
    void Stop();

    std::string HandleRequest(const std::string& requestJson);

private:
    ServiceIPC();
    ~ServiceIPC();

    std::unique_ptr<ipc::NamedPipeServer> server_;
};

} // namespace service
} // namespace vantor
